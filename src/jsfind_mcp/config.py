"""Layered configuration loading (defaults -> user -> project -> explicit)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .model import Mode
from .resources import safe_data_path, user_config_dir

PACKAGE_ROOT = Path(__file__).resolve().parent
#: Bundled data files are resolved through :mod:`jsfind_mcp.resources`, so a frozen
#: binary loads exactly the defaults a source checkout does.
BUILTIN_CONFIG = safe_data_path("config.yml")
BUILTIN_RULES = safe_data_path("rules.yml")
BUILTIN_BANNERS = safe_data_path("banners.yml")


def _merge(base: dict, override: dict) -> dict:
    """Deep-merge ``override`` into a copy of ``base``."""
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def _duration(value: Any, fallback: float) -> float:
    """Parse ``15s`` / ``1m30s`` / ``500ms`` / plain seconds into seconds."""
    if value is None:
        return fallback
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().lower()
    if not text:
        return fallback
    units = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}
    total = 0.0
    number = ""
    matched = False
    for char in text:
        if char.isdigit() or char == ".":
            number += char
        elif char in units:
            total += float(number or 0) * units[char]
            number = ""
            matched = True
        else:
            return fallback
    if number:
        total += float(number)
        matched = True
    return total if matched else fallback


@dataclass
class RequestConfig:
    timeout: float = 15.0
    #: Wall-clock budget for one whole scan, every phase included, not just the
    #: first queue drain. It is deliberately short for an interactive caller: an
    #: MCP client gives up on a tool that blocks for minutes and closes the
    #: stdio pipe, which takes the server process -- and every in-memory result
    #: -- with it. Raise it per call with jsfind_scan's ``timeout_seconds``, or
    #: in config, when a target genuinely needs longer. 0 means unlimited.
    target_timeout: float = 90.0
    #: Ceiling on one response body, counted after decompression. The body is
    #: fetched streaming and cut at the cap, so a 20 MB bundle costs one capped
    #: read instead of filling memory before any check ever sees it. The first
    #: 10 MB of a bundle holds essentially every endpoint and secret the rest
    #: would repeat; the cap is raised per call via jsfind_scan. 0 means
    #: unlimited -- and hands the target a way to exhaust the scan's memory.
    max_response_bytes: int = 10 * 1024 * 1024
    #: Wall-clock ceiling on one request including its whole body transfer.
    #: httpx's own ``read`` timeout only bounds the gap between two reads, so a
    #: server that dribbles bytes just under the gap streams forever and pins
    #: one fetch slot for the remainder of the scan. 0 means unlimited.
    download_timeout: float = 30.0
    retry: int = 1
    #: Outbound proxy for every request. Accepts a bare host:port (assumed
    #: http) or a full URL, optionally with credentials. Never echoed back
    #: to a caller with the password intact -- see :mod:`jsfind_mcp.proxy`.
    proxy: str = ""
    #: Comma-separated hosts that bypass the proxy,
    #: e.g. "localhost,.corp.internal".
    no_proxy: str = ""
    #: Honour HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY from the
    #: environment. On by default because that is httpx's own behaviour and
    #: an operator who exported a proxy expects it to be used; set false to
    #: make a scan provably direct.
    trust_env: bool = True
    user_agent: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    verify_tls: bool = False
    max_redirects: int = 10
    #: Business-code semantics: category -> body patterns that mean it.
    #: e.g. {"biz_auth_fail": ["\"code\":477"]}. A probe whose body
    #: matches a pattern takes that category as its signal, so an endpoint
    #: answering 200 with {"code":477} reads as an auth failure rather
    #: than as a success. Empty means the feature is off.
    business_codes: dict = field(default_factory=dict)


@dataclass
class ConcurrencyConfig:
    targets: int = 4
    resources_per_target: int = 16


@dataclass
class LimitsConfig:
    max_depth: int = 5
    max_resources: int = 0        # 0 = unlimited
    max_body_size: int = 0        # 0 = unlimited
    max_ast_bytes: int = 8 * 1024 * 1024


@dataclass
class ScopeConfig:
    allow_domains: list[str] = field(default_factory=list)
    restrict_domains: list[str] = field(default_factory=list)
    suffix_blacklist: list[str] = field(default_factory=list)
    fetch_external_scripts: bool = True
    probe_external_endpoints: bool = False
    probe_routes: bool = False
    #: whether to confirm discovered API endpoints with a read-only GET probe;
    #: turning both this and probe_routes off is what --no-probe does
    probe_endpoints: bool = True
    #: Fetch asset manifests / service-worker precache lists and queue every
    #: file they name. Deterministic where the rest is heuristic, so on by default.
    probe_asset_manifests: bool = True
    #: Render each front-end route to reach the scripts it loads on demand.
    #: Sends GET only; nothing is submitted. Off by default because it
    #: multiplies the request count against the target.
    crawl_routes: bool = True
    #: How many routes one scan renders.
    route_budget: int = 40
    #: Probe well-known locations for a published OpenAPI/Swagger document.
    #: A spec is authoritative where static analysis is inferential.
    probe_api_specs: bool = True
    explore_base_paths: bool = True
    probe_source_maps: bool = True
    source_map_blacklist: list[str] = field(default_factory=list)
    skip_library_bundles: bool = True


@dataclass
class HostsConfig:
    internal_suffixes: list[str] = field(default_factory=list)


@dataclass
class Config:
    mode: Mode = Mode.AUTO
    request: RequestConfig = field(default_factory=RequestConfig)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    hosts: HostsConfig = field(default_factory=HostsConfig)
    #: Collected JavaScript is written here so jsfind_js_search can read
    #: it back. Not a human-facing report directory.
    js_dir: str = "./jsfind-js"
    #: Set false to analyze without writing anything to disk.
    save_js: bool = True
    #: Reconstruct a copy-pasteable request packet per endpoint.
    request_template: bool = True
    rules_file: str = ""
    #: server / middleware version rules; empty means the built-in set
    banners_file: str = ""

    @property
    def concurrency_limit(self) -> int:
        return max(1, self.concurrency.resources_per_target)


#: Top-level Config attributes a YAML file may set. Anything not listed here is
#: ignored on load, so adding a documented key means adding it here too.
_TOP_LEVEL_KEYS = ("js_dir", "save_js", "request_template", "rules_file",
                   "banners_file")

_SECTIONS = {
    "request": RequestConfig,
    "concurrency": ConcurrencyConfig,
    "limits": LimitsConfig,
    "scope": ScopeConfig,
    "hosts": HostsConfig,
}

# Fields carrying a duration literal rather than a plain number.
_DURATION_FIELDS = {
    ("request", "timeout"),
    ("request", "target_timeout"),
    ("request", "download_timeout"),
}


def _apply_section(section_name: str, section: Any, data: dict) -> None:
    known = set(section.__dataclass_fields__)
    for key, value in (data or {}).items():
        if key not in known:
            continue
        if (section_name, key) in _DURATION_FIELDS:
            setattr(section, key, _duration(value, getattr(section, key)))
            continue
        if isinstance(value, dict) and isinstance(getattr(section, key), dict):
            merged = dict(getattr(section, key))
            merged.update(value)
            setattr(section, key, merged)
            continue
        setattr(section, key, value)


def load_config_file(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def user_config_path() -> Path:
    return user_config_dir() / "config.yml"


def load_config(explicit: str | Path | None = None) -> Config:
    """Load the layered configuration.

    Precedence: explicit file > project ./jsfind-mcp.yml > ~/.jsfind-mcp/config.yml >
    built-in defaults. Later layers override earlier ones key by key.
    """
    layered: dict = {}
    if BUILTIN_CONFIG.exists():
        layered = _merge(layered, load_config_file(BUILTIN_CONFIG))

    candidates: list[Path] = []
    local = Path.cwd() / "jsfind-mcp.yml"
    if local.exists():
        candidates.append(local)
    home = user_config_path()
    if home.exists():
        candidates.append(home)
    for candidate in candidates:
        layered = _merge(layered, load_config_file(candidate))

    if explicit:
        path = Path(explicit)
        if not path.exists():
            raise FileNotFoundError(f"config file not found: {path}")
        layered = _merge(layered, load_config_file(path))

    config = Config()
    mode = layered.get("mode")
    if mode:
        try:
            config.mode = Mode(str(mode).lower())
        except ValueError:
            pass
    for name, klass in _SECTIONS.items():
        section = klass()
        _apply_section(name, section, layered.get(name) or {})
        setattr(config, name, section)
    config.rules_file = layered.get("rules_file") or ""
    # Top-level scalars, not sections. Each must be read explicitly or the
    # documented YAML key silently does nothing -- save_js especially, since it
    # is the switch a user reaches for to keep collected code off disk.
    for key in _TOP_LEVEL_KEYS:
        if key in layered and layered[key] is not None:
            setattr(config, key, layered[key])
    return config


def seed_user_rules(target: Path | None = None) -> Path:
    """Create ``~/.jsfind-mcp/rules.yml`` from the built-in set on first run."""
    target = target or (user_config_path().parent / "rules.yml")
    if target.exists():
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(BUILTIN_RULES.read_text(encoding="utf-8"), encoding="utf-8")
    return target