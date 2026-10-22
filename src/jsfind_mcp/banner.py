"""Server / middleware banner fingerprinting.

Static analysis finds what the *code* says; this finds what the *server* says
about itself. Two sources are used:

* **response headers** — ``Server``, ``X-Powered-By``, ``Via`` and friends;
* **error-page bodies** — a 404 often prints the full banner
  (``Apache/2.4.41 (Ubuntu) Server at example.com Port 80``), which headers
  truncate.

One rule governs the whole module: **a match without a version is not a
finding**. ``Server: nginx`` says almost nothing — it is the default value of
the header and gives a tester nothing actionable. ``Server: nginx/1.18.0`` says
exactly which CVE set applies. Reporting only versioned banners keeps the
signal-to-noise ratio high.

That rule is enforced twice: every pattern is written so its version group is
mandatory, and :meth:`BannerEngine._from_match` independently rejects any
capture with no digit in it, so a loosely written custom rule cannot produce a
versionless "fingerprint" either.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from .model import Banner, Severity
from .resources import safe_data_path as _safe_data_path

BUILTIN_BANNERS_PATH = _safe_data_path("banners.yml")

#: how much of a response body to scan for an error-page banner. Error banners
#: live in the first few KB; scanning a 5 MB bundle would be wasted work.
_BODY_SCAN_BYTES = 64 * 1024

#: header values are short by construction; a pathological one is not a banner
_MAX_HEADER_VALUE = 1024

#: rule categories, mirrored from banners.yml for validation
_CATEGORIES = frozenset({
    "web_server", "app_server", "language", "gateway", "framework", "cdn", "db",
})

#: scope markers, so a reader knows where a version came from
SCOPE_HEADER = "header"
SCOPE_BODY = "body"

_HAS_DIGIT = re.compile(r"\d")

_LOCK = threading.Lock()
_ENGINE: "BannerEngine | None" = None


@dataclass
class BannerRule:
    """One compiled version-detection rule."""

    id: str = ""
    product: str = ""
    category: str = "web_server"
    severity: Severity = Severity.INFO
    source_pattern: str = ""
    #: header names to search, lowercase; empty means every header
    headers: tuple[str, ...] = ()
    #: whether the version group is mandatory; the engine enforces it either way
    require_version: bool = True
    pattern: Any = None


class BannerEngine:
    """Applies banner rules to headers and error-page bodies."""

    def __init__(self, rules: Iterable[BannerRule],
                 diagnostics: list[str] | None = None):
        self.rules = list(rules)
        self.diagnostics = list(diagnostics or [])

    # -- loading --------------------------------------------------------

    @staticmethod
    def default(rules_file: str = "", disabled: Iterable[str] = ()) -> "BannerEngine":
        """Build the engine from the built-in set plus any user file.

        Precedence: explicit ``rules_file`` > built-in set. A rule id defined in
        both places is taken from the explicit file.
        """
        disabled_ids = {item.strip().lower() for item in disabled if item.strip()}
        diagnostics: list[str] = []

        sources: list[Path] = []
        if rules_file:
            path = Path(rules_file).expanduser()
            if path.exists():
                sources.append(path)
            else:
                diagnostics.append(f"banners file not found: {path}")
        if BUILTIN_BANNERS_PATH.exists():
            sources.append(BUILTIN_BANNERS_PATH)
        else:
            diagnostics.append(
                f"built-in banners file missing: {BUILTIN_BANNERS_PATH}"
            )

        raw_rules: list[dict] = []
        seen: set[str] = set()
        for path in sources:
            for entry in _load(path, diagnostics):
                rule_id = str(entry.get("id", "")).strip().lower()
                if not rule_id or rule_id in seen:
                    continue
                seen.add(rule_id)
                raw_rules.append(entry)

        compiled: list[BannerRule] = []
        for entry in raw_rules:
            rule = _compile(entry, diagnostics)
            if rule is not None and rule.id.lower() not in disabled_ids:
                compiled.append(rule)
        return BannerEngine(compiled, diagnostics)

    # -- matching -------------------------------------------------------

    def match_headers(self, headers: Mapping[str, str], host: str = "",
                      source_url: str = "", status_code: int = 0) -> list[Banner]:
        """Match versioned products against one response's headers."""
        if not headers:
            return []
        lowered = {str(name).lower(): str(value) for name, value in headers.items()}
        out: list[Banner] = []
        for rule in self.rules:
            for name in (rule.headers or tuple(lowered)):
                value = lowered.get(name)
                if not value:
                    continue
                banner = self._apply(rule, value, SCOPE_HEADER, name)
                if banner is not None:
                    banner.host = host
                    banner.source_url = source_url
                    banner.status_code = status_code
                    out.append(banner)
                break
        return out

    def match_body(self, body: str, host: str = "", source_url: str = "",
                   status_code: int = 0) -> list[Banner]:
        """Match an error page that prints the full server banner.

        Header scoping does not apply here: an error page names whatever
        software produced it, not just the ones that advertise a header.
        """
        if not body:
            return []
        head = body[:_BODY_SCAN_BYTES]
        out: list[Banner] = []
        for rule in self.rules:
            for match in rule.pattern.finditer(head):
                banner = self._from_match(rule, match, head, SCOPE_BODY, "")
                if banner is None:
                    continue
                banner.host = host
                banner.source_url = source_url
                banner.status_code = status_code
                out.append(banner)
                break
        return out

    def _apply(self, rule: BannerRule, value: str, scope: str,
               header: str) -> Banner | None:
        head = value[:_MAX_HEADER_VALUE]
        for match in rule.pattern.finditer(head):
            return self._from_match(rule, match, head, scope, header)
        return None

    def _from_match(self, rule: BannerRule, match: re.Match, text: str,
                    scope: str, header: str) -> Banner | None:
        """Turn one match into a banner, or nothing when it lacks a version.

        This is the guard that makes the module's central promise true
        regardless of how a custom rule was written.
        """
        version = match.group(1) if match.lastindex else ""
        version = (version or "").strip().strip(")").strip()
        if not _HAS_DIGIT.search(version):
            return None
        return Banner(
            product=rule.product or rule.id,
            version=version,
            raw=match.group(0).strip()[:200],
            header=header,
            rule_id=rule.id,
            category=rule.category,
            severity=rule.severity,
            scope=scope,
        )

    # -- inventory ------------------------------------------------------

    def describe(self) -> list[dict]:
        return [{
            "id": rule.id,
            "product": rule.product,
            "category": rule.category,
            "severity": rule.severity.value,
            "headers": list(rule.headers),
            "pattern": rule.source_pattern,
        } for rule in self.rules]

    def __len__(self) -> int:
        return len(self.rules)


def _load(path: Path, diagnostics: list[str]) -> list[dict]:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        diagnostics.append(f"cannot read banners file {path}: {exc}")
        return []
    if not isinstance(document, dict):
        diagnostics.append(f"banners file {path}: expected a mapping")
        return []
    entries = document.get("banners") or []
    if not isinstance(entries, list):
        diagnostics.append(f"banners file {path}: 'banners' must be a list")
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def _compile(entry: dict, diagnostics: list[str]) -> BannerRule | None:
    rule_id = str(entry.get("id", "")).strip()
    pattern = str(entry.get("pattern", ""))
    if not rule_id or not pattern:
        diagnostics.append(f"banner rule {rule_id or '<no id>'}: missing id or pattern")
        return None

    category = str(entry.get("category", "web_server")).strip().lower()
    if category not in _CATEGORIES:
        diagnostics.append(
            f"banner rule {rule_id}: unknown category {category!r}, using web_server"
        )
        category = "web_server"

    headers = entry.get("headers") or ()
    if isinstance(headers, str):
        headers = (headers,)
    header_names = tuple(
        str(name).strip().lower() for name in headers if str(name).strip()
    )

    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        diagnostics.append(
            f"banner rule {rule_id}: pattern failed to compile ({exc})"
        )
        return None

    if compiled.groups < 1:
        # Without a capture group there is no version to keep, and this engine
        # reports nothing without one.
        diagnostics.append(
            f"banner rule {rule_id}: pattern has no version capture group, skipped"
        )
        return None

    return BannerRule(
        id=rule_id,
        product=str(entry.get("product", rule_id)),
        category=category,
        severity=_severity(entry.get("severity")),
        source_pattern=pattern,
        headers=header_names,
        require_version=bool(entry.get("require_version", True)),
        pattern=compiled,
    )


def _severity(raw: Any) -> Severity:
    if isinstance(raw, Severity):
        return raw
    try:
        return Severity(str(raw).strip().lower())
    except ValueError:
        return Severity.INFO


def shared_engine(rules_file: str = "") -> BannerEngine:
    """Process-wide engine for callers that need no custom rule set."""
    global _ENGINE
    if _ENGINE is None:
        with _LOCK:
            if _ENGINE is None:
                _ENGINE = BannerEngine.default(rules_file=rules_file)
    return _ENGINE


def dedupe(banners: Iterable[Banner]) -> list[Banner]:
    """Collapse duplicates, keeping the first occurrence and its ordering."""
    seen: set[tuple] = set()
    out: list[Banner] = []
    for banner in banners:
        key = banner.key()
        if key in seen:
            continue
        seen.add(key)
        out.append(banner)
    return out


def summarize(banners: Iterable[Banner]) -> dict:
    """Counts by category and by product, for the scan summary."""
    by_category: dict[str, int] = {}
    by_product: dict[str, int] = {}
    for banner in banners:
        by_category[banner.category] = by_category.get(banner.category, 0) + 1
        by_product[banner.product] = by_product.get(banner.product, 0) + 1
    return {
        "total": sum(by_category.values()),
        "by_category": dict(sorted(by_category.items())),
        "by_product": dict(sorted(by_product.items())),
    }