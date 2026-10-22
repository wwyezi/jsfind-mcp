"""HaE-compatible rule loading and compilation.

Two rule formats are accepted:

* **HaE native** — ``rules: [{group, rule: [{name, f_regex, s_regex, format,
  color, sensitive, loaded}]}]``. The rule id is generated as
  ``hae.<group>.<name>``, so ``loaded: false`` disables a single entry and the
  ``disabled:`` list addresses rules by that generated id.
* **jsfind-mcp native** — a flat list of mappings with ``id``, ``name``,
  ``category``, ``severity``, ``pattern``, ``group``, ``method_group``, ...

Patterns compile with the ``regex`` module when available (variable-width
lookbehind, possessive quantifiers) and fall back to the standard library
``re`` otherwise, so a HaE rule stdlib ``re`` cannot parse is skipped with a
diagnostic instead of aborting the whole rule set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

try:  # pragma: no cover - exercised implicitly by the import
    import regex as _re
    _REGEX_MODULE = "regex"
except ImportError:  # pragma: no cover
    import re as _re
    _REGEX_MODULE = "re"

from .model import RuleCategory, Severity
from .resources import safe_data_path as _safe_data_path

#: Resolved through :mod:`jsfind_mcp.resources` so a frozen binary finds its rules
#: just as a source checkout does.
BUILTIN_RULES_PATH = _safe_data_path("rules.yml")

COLOR_SEVERITY = {
    "red": Severity.CRITICAL,
    "orange": Severity.HIGH,
    "yellow": Severity.MEDIUM,
    "green": Severity.LOW,
    "blue": Severity.INFO,
    "gray": Severity.LOW,
    "grey": Severity.LOW,
}

NATIVE_RULE_FIELDS = frozenset({
    "id", "name", "category", "severity", "pattern", "group", "method_group",
    "description", "enabled", "engine", "s_regex", "s_group", "format",
    "ignore_case",
})


@dataclass
class CompiledRule:
    """One URL or sensitive-information extraction pattern."""

    id: str = ""
    name: str = ""
    category: RuleCategory = RuleCategory.SENSITIVE
    severity: Severity = Severity.INFO
    #: capture group holding the extracted value; 0 means the whole match
    group: int = 0
    #: optional capture group holding the HTTP verb for the same match
    method_group: int = 0
    description: str = ""
    enabled: bool = True
    source_pattern: str = ""
    #: raw second-stage pattern, kept for diagnostics after compilation
    s_pattern_raw: str = ""
    s_group: int = 0
    format: str = ""
    ignore_case: bool = False
    pattern: Any = None
    s_pattern: Any = None

    def extract(self, text: str) -> tuple[str, int, int] | None:
        """Run the rule.

        Returns ``(value, start_offset, end_offset)`` or None. ``start``/``end``
        describe the whole match, so context extraction always points at the
        real code region even when the value came from a capture group.
        """
        flags = _re.IGNORECASE if self.ignore_case else 0
        try:
            match = self.pattern.search(text, flags)
        except Exception:  # noqa: BLE001 - never let one rule abort a scan
            return None
        if not match:
            return None
        value = self._render(match)
        if not value:
            return None
        start, end = match.span()
        if self.s_pattern is not None:
            try:
                second = self.s_pattern.search(value)
            except Exception:  # noqa: BLE001
                return None
            if not second:
                return None
            if self.s_group:
                try:
                    value = second.group(self.s_group) or ""
                except Exception:  # noqa: BLE001
                    return None
        if not value:
            return None
        return value, start, end

    def method_of(self, text: str, match) -> str:
        """HTTP verb bound to the same match, when the rule declares one."""
        if not self.method_group:
            return ""
        try:
            return (match.group(self.method_group) or "").upper()
        except Exception:  # noqa: BLE001
            return ""

    def iter_matches(self, text: str):
        """Yield ``(value, start, end, match)`` for every match in ``text``."""
        flags = _re.IGNORECASE if self.ignore_case else 0
        try:
            for match in self.pattern.finditer(text, flags):
                value = self._render(match)
                if not value:
                    continue
                if self.s_pattern is not None:
                    try:
                        second = self.s_pattern.search(value)
                    except Exception:  # noqa: BLE001
                        continue
                    if not second:
                        continue
                    if self.s_group:
                        try:
                            value = second.group(self.s_group) or ""
                        except Exception:  # noqa: BLE001
                            continue
                    if not value:
                        continue
                start, end = match.span()
                yield value, start, end, match
        except Exception:  # noqa: BLE001
            return

    def _render(self, match) -> str:
        """Apply the HaE-style ``format`` template to one match."""
        if not self.format:
            try:
                return match.group(self.group) or ""
            except Exception:  # noqa: BLE001
                return ""
        out: list[str] = []
        index = 0
        length = len(self.format)
        while index < length:
            char = self.format[index]
            if char == "{":
                close = self.format.find("}", index)
                if close > 0:
                    token = self.format[index + 1:close]
                    if token.isdigit():
                        try:
                            out.append(match.group(int(token)) or "")
                        except Exception:  # noqa: BLE001
                            return ""
                        index = close + 1
                        continue
            out.append(char)
            index += 1
        return "".join(out)


@dataclass
class RuleSet:
    url: list[CompiledRule] = field(default_factory=list)
    sensitive: list[CompiledRule] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    def all(self) -> list[CompiledRule]:
        return self.url + self.sensitive

    def by_id(self, rule_id: str) -> CompiledRule | None:
        for rule in self.all():
            if rule.id == rule_id:
                return rule
        return None


def regex_backend() -> str:
    """Name of the regex backend in use (``regex`` or ``re``)."""
    return _REGEX_MODULE


def _compile(rule: CompiledRule, diagnostics: list[str]) -> CompiledRule | None:
    if not rule.source_pattern:
        diagnostics.append(f"rule {rule.id}: empty pattern, skipped")
        return None
    flags = _re.IGNORECASE if rule.ignore_case else 0
    try:
        rule.pattern = _re.compile(rule.source_pattern, flags)
    except Exception as exc:  # noqa: BLE001 - surface any backend error
        diagnostics.append(f"rule {rule.id}: pattern failed to compile ({exc}), skipped")
        return None
    if rule.s_pattern_raw:
        try:
            rule.s_pattern = _re.compile(rule.s_pattern_raw, _re.IGNORECASE)
        except Exception as exc:  # noqa: BLE001
            diagnostics.append(f"rule {rule.id}: s_regex failed to compile ({exc}), ignored")
            rule.s_pattern = None
    return rule


def _compile_all(rules: Iterable[CompiledRule], diagnostics: list[str]) -> list[CompiledRule]:
    out: list[CompiledRule] = []
    for rule in rules:
        compiled = _compile(rule, diagnostics)
        if compiled is not None:
            out.append(compiled)
    return out


def _normalize_severity(raw: Any, color: str) -> Severity:
    if raw:
        try:
            return Severity(str(raw).lower())
        except ValueError:
            pass
    return COLOR_SEVERITY.get((color or "").lower(), Severity.MEDIUM)


def _normalize_category(raw: Any) -> RuleCategory:
    if raw:
        try:
            return RuleCategory(str(raw).lower())
        except ValueError:
            pass
    return RuleCategory.SENSITIVE


def _parse_native(entry: dict, diagnostics: list[str]) -> CompiledRule | None:
    unknown = set(entry) - NATIVE_RULE_FIELDS
    if unknown:
        diagnostics.append(
            f"rule {entry.get('id', '<no id>')}: unknown field(s) {sorted(unknown)}, ignored"
        )
    rule = CompiledRule(
        id=str(entry.get("id") or entry.get("name") or ""),
        name=str(entry.get("name") or entry.get("id") or ""),
        category=_normalize_category(entry.get("category")),
        severity=_normalize_severity(entry.get("severity"), str(entry.get("color") or "")),
        group=int(entry.get("group") or 0),
        method_group=int(entry.get("method_group") or 0),
        description=str(entry.get("description") or ""),
        enabled=bool(entry.get("enabled", True)),
        source_pattern=str(entry.get("pattern") or ""),
        s_pattern_raw=str(entry.get("s_regex") or ""),
        s_group=int(entry.get("s_group") or 0),
        format=str(entry.get("format") or ""),
        ignore_case=bool(entry.get("ignore_case", False)),
    )
    if not rule.id:
        diagnostics.append("native rule without id, skipped")
        return None
    return rule


def _parse_hae(entry: dict, diagnostics: list[str]) -> list[CompiledRule]:
    """Parse one HaE ``{group, rule: [...]}`` block.

    HaE semantics carried over: ``loaded: false`` disables a single entry, an
    absent or false ``sensitive`` means case-insensitive, and ``format``
    (``{0}``/``{N}``) defines the extracted value because HaE's parser otherwise
    always yields the whole match.
    """
    group = str(entry.get("group") or "custom")
    rules: list[CompiledRule] = []
    for item in entry.get("rule") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if not name:
            diagnostics.append(f"hae group {group}: rule without name, skipped")
            continue
        rules.append(CompiledRule(
            id=f"hae.{group}.{name}",
            name=name,
            category=_normalize_category(item.get("category")),
            severity=_normalize_severity(item.get("severity"), str(item.get("color") or "")),
            group=int(item.get("group") or 0),
            method_group=int(item.get("method_group") or 0),
            description=str(item.get("description") or ""),
            enabled=bool(item.get("loaded", True)),
            source_pattern=str(item.get("f_regex") or ""),
            s_pattern_raw=str(item.get("s_regex") or ""),
            s_group=int(item.get("s_group") or 0),
            format=str(item.get("format") or ""),
            ignore_case=not bool(item.get("sensitive", False)),
        ))
    return rules


def parse_rules_document(document: Any, diagnostics: list[str] | None = None) -> list[CompiledRule]:
    """Parse either rule format into an uncompiled rule list."""
    diagnostics = diagnostics if diagnostics is not None else []
    out: list[CompiledRule] = []
    if not document:
        return out
    if isinstance(document, list):
        for entry in document:
            if isinstance(entry, dict):
                rule = _parse_native(entry, diagnostics)
                if rule is not None:
                    out.append(rule)
        return out
    if not isinstance(document, dict):
        diagnostics.append("rules document must be a mapping or a list")
        return out
    for key in ("rules", "custom"):
        value = document.get(key)
        if not isinstance(value, list):
            continue
        for entry in value:
            if not isinstance(entry, dict):
                continue
            if "rule" in entry or "group" in entry:
                out.extend(_parse_hae(entry, diagnostics))
            else:
                rule = _parse_native(entry, diagnostics)
                if rule is not None:
                    out.append(rule)
    return out


def load_rules_file(path: str | Path) -> list[CompiledRule]:
    with open(path, "r", encoding="utf-8") as handle:
        return parse_rules_document(yaml.safe_load(handle) or [])


def build_ruleset(
    builtin_api_rules: list[CompiledRule],
    rules_file: str = "",
    extra_files: Iterable[str] = (),
    custom: Iterable[dict] = (),
    disabled: Iterable[str] = (),
    use_builtin_sensitive: bool = True,
) -> RuleSet:
    """Assemble the final rule set.

    Load order: api rules (always compiled) > built-in sensitive set >
    ``rules_file`` > extra files > custom. A later definition with the same id
    overrides the earlier one, so a user rule can retune a built-in without
    editing the shipped file; ``disabled`` addresses rules by that id.
    """
    diagnostics: list[str] = []
    merged: dict[str, CompiledRule] = {rule.id: rule for rule in builtin_api_rules}

    sources: list[list[CompiledRule]] = []
    if use_builtin_sensitive:
        if BUILTIN_RULES_PATH.exists():
            sources.append(load_rules_file(BUILTIN_RULES_PATH))
        else:  # pragma: no cover - only when the package data is missing
            diagnostics.append(f"built-in rules file missing: {BUILTIN_RULES_PATH}")
    if rules_file:
        path = Path(rules_file)
        if path.exists():
            sources.append(load_rules_file(path))
        else:
            diagnostics.append(f"rules_file not found: {path}")
    for extra in extra_files or ():
        path = Path(extra)
        if path.exists():
            sources.append(load_rules_file(path))
        else:
            diagnostics.append(f"included rules file not found: {path}")
    for entry in custom or ():
        rule = _parse_native(entry, diagnostics)
        if rule is not None:
            sources.append([rule])

    for rules in sources:
        for rule in rules:
            merged[rule.id] = rule

    for rule_id in disabled or ():
        rule = merged.get(rule_id)
        if rule is None:
            diagnostics.append(f"disabled rule id not found: {rule_id}")
        else:
            rule.enabled = False

    url_rules: list[CompiledRule] = []
    sensitive_rules: list[CompiledRule] = []
    for rule in merged.values():
        if not rule.enabled:
            continue
        target = url_rules if rule.category is RuleCategory.URL else sensitive_rules
        target.append(rule)

    return RuleSet(
        url=_compile_all(url_rules, diagnostics),
        sensitive=_compile_all(sensitive_rules, diagnostics),
        diagnostics=diagnostics,
    )