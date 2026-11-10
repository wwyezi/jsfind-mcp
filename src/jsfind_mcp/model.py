"""Scannable data model for jsfind-mcp.

Mirrors the reference Go implementation: every finding keeps the evidence that
produced it (source URL, line, surrounding source lines) so a report reader can
verify a claim without re-downloading the bundle.
"""

from __future__ import annotations

import dataclasses
import enum
import re
from dataclasses import dataclass, field
from typing import Any


class Mode(str, enum.Enum):
    """Collection strategy: ``direct`` fetches HTML and JavaScript over
    HTTP; ``auto`` is the default and currently behaves identically.
    """

    AUTO = "auto"
    DIRECT = "direct"
    #: Local file analysis. No network is touched, and saying so is more
    #: useful than reporting "auto" or "direct" for a run that did neither.
    LOCAL = "local"


class RuleCategory(str, enum.Enum):
    URL = "url"
    SENSITIVE = "sensitive"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK.get(self.value, 0)


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_rank(value: str | None) -> int:
    """Numeric rank for a severity label; unknown labels rank lowest."""
    return _SEVERITY_RANK.get((value or "").lower(), 0)


# Endpoint evidence ranks how strongly an API path is confirmed.
EVIDENCE_RUNTIME = "runtime"    # observed as a live browser request
EVIDENCE_FULL_URL = "full-url"  # absolute URL recovered by AST analysis
EVIDENCE_STATIC = "static"      # relative path from AST or regex matching
#: declared by an API specification. It outranks inference because
#: the author wrote it down rather than the scanner guessing.
EVIDENCE_SPEC = "spec"

# Request-parameter evidence ranks how strongly a value was recovered.
EVIDENCE_LITERAL = "literal"          # written as a constant in the source
EVIDENCE_CONSTANT = "constant"        # resolved through an identifier binding
EVIDENCE_PLACEHOLDER = "placeholder"  # dynamic expression, name kept as {name}
EVIDENCE_INFERRED = "inferred"        # deduced from the payload shape


# Parameter extraction scenarios — the code shape a name came from.
SCENARIO_OBJECT_PROPERTY = "object_property"
SCENARIO_DESTRUCTURING = "destructuring"
SCENARIO_NESTED_DESTRUCTURING = "nested_destructuring"
SCENARIO_FUNCTION_PARAM = "function_param"
SCENARIO_VARIABLE = "variable"
SCENARIO_API_REQUEST = "api_request"
SCENARIO_URL_QUERY = "url_query"
SCENARIO_CONFIG_OBJECT = "config_object"
SCENARIO_ROUTE_PARAM = "route_param"

SCENARIO_LABELS = {
    SCENARIO_OBJECT_PROPERTY: "对象属性",
    SCENARIO_DESTRUCTURING: "解构赋值",
    SCENARIO_NESTED_DESTRUCTURING: "嵌套解构",
    SCENARIO_FUNCTION_PARAM: "函数参数",
    SCENARIO_VARIABLE: "变量赋值",
    SCENARIO_API_REQUEST: "API请求",
    SCENARIO_URL_QUERY: "URL参数",
    SCENARIO_CONFIG_OBJECT: "配置对象",
    SCENARIO_ROUTE_PARAM: "路由参数",
}

# Taint kinds for placeholder parameters: where a runtime-only value comes from.
TAINT_UPSTREAM = "upstream"
TAINT_STORAGE = "storage"
TAINT_ROUTE = "route"
TAINT_UNKNOWN = "unknown"

_ROUTE_PARAM_RE = re.compile(r"(?::|\{)([A-Za-z_][A-Za-z0-9_]*)\}?")


def route_param_names(raw: str) -> list[str]:
    """Route placeholders in ``/user/:id/x`` or ``/user/{id}/x`` -> ["id"].

    Hash fragments are scanned too, so ``/#/user/:id`` works. The colon form
    requires a letter to start so ports and hash fragments never match.
    """
    names: list[str] = []
    seen: set[str] = set()
    for match in _ROUTE_PARAM_RE.finditer(raw or ""):
        name = match.group(1)
        if name not in seen:
            seen.add(name)
            names.append(name)
    return names


class ResourceType(str, enum.Enum):
    DOCUMENT = "document"
    SCRIPT = "script"
    CHUNK = "chunk"
    API = "api"
    ROUTE = "route"
    SOURCEMAP = "sourcemap"
    ASSET = "asset"
    EXTERNAL = "external"


@dataclass
class ContextLine:
    """One line of surrounding source code for a finding."""

    line_number: int = 0
    content: str = ""
    match_start: int = 0
    match_end: int = 0


@dataclass
class Taint:
    """Local backward-taint annotation for a placeholder parameter."""

    kind: str = TAINT_UNKNOWN
    symbol: str = ""
    upstream: str = ""
    upstream_field: str = ""
    hops: int = 0


@dataclass
class Param:
    key: str = ""
    value: str = ""
    evidence: str = ""
    taint: Taint | None = None


@dataclass
class RequestSpec:
    """Normalized shape of one request call site."""

    base_url: str = ""
    base_url_kind: str = ""
    content_type: str = ""
    content_type_evidence: str = ""
    query: list[Param] = field(default_factory=list)
    body: list[Param] = field(default_factory=list)

    def param_keys(self) -> list[str]:
        seen: set[str] = set()
        keys: list[str] = []
        for param in self.query + self.body:
            if not param.key or param.key in seen:
                continue
            seen.add(param.key)
            keys.append(param.key)
        return keys


@dataclass
class HeaderTpl:
    key: str = ""
    value: str = ""
    evidence: str = ""


@dataclass
class RequestTemplate:
    """Reconstructed HTTP request packet for one endpoint.

    Placeholders embedded in URL/headers/body:

    * ``{{fuzz:name}}``       — value must be invented for testing
    * ``{{fuzz:body:{sym}}}`` — the whole body is a runtime object
    * ``{{cookie:NAME}}``     — session cookie the client is expected to send
    """

    method: str = "GET"
    url: str = ""
    headers: list[HeaderTpl] = field(default_factory=list)
    body: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class Resource:
    url: str = ""
    type: ResourceType = ResourceType.SCRIPT
    source_url: str = ""
    final_url: str = ""
    local_path: str = ""
    status_code: int = 0
    content_type: str = ""
    size: int = 0
    depth: int = 0


@dataclass
class Endpoint:
    raw: str = ""
    url: str = ""
    source_url: str = ""
    authorized: bool = False
    status_code: int = 0
    #: classify_status(status_code) — what the probe result means for testing
    signal: str = "unprobed"
    method: str = ""
    evidence: str = ""
    source: str = ""          # ast | regex | cdp | sourcemap
    type: str = ""            # api | route
    probe: str = ""           # server | static | error
    line: int = 0
    column: int = 0
    context_lines: list[ContextLine] = field(default_factory=list)
    body_params: list[str] = field(default_factory=list)
    spec: RequestSpec | None = None
    vendor: bool = False
    response_params: list[str] = field(default_factory=list)
    template: RequestTemplate | None = None
    #: full URL resolved from a joined prefix expression,  when the
    #: reference was not joined or the prefix value was unknown
    resolved: str = ""
    #: True when the path is a joined half whose prefix value is unknown
    unresolved_prefix: bool = False

    @property
    def dedup_key(self) -> str:
        return f"{self.method}\x00{self.url}"


@dataclass
class Finding:
    rule_id: str = ""
    rule_name: str = ""
    category: RuleCategory = RuleCategory.SENSITIVE
    severity: Severity = Severity.INFO
    value: str = ""
    source_url: str = ""
    line: int = 0
    column: int = 0
    context_lines: list[ContextLine] = field(default_factory=list)
    vendor: bool = False


@dataclass
class ParamHit:
    """One parameter name recovered from a code shape in the source."""

    name: str = ""
    scenario: str = ""
    value: str = ""
    evidence: str = ""
    source_url: str = ""
    line: int = 0
    column: int = 0
    context_lines: list[ContextLine] = field(default_factory=list)
    vendor: bool = False


@dataclass
class Banner:
    """One versioned server / middleware product the target disclosed.

    Only products whose version was actually recovered are recorded: a bare
    ``Server: nginx`` is the header's default and carries no actionable
    information, so the engine discards it rather than reporting a guess.
    """

    product: str = ""
    version: str = ""
    #: the matched text as it appeared, e.g. "Apache/2.4.41 (Ubuntu)"
    raw: str = ""
    #: response header the value came from, empty when it came from a body
    header: str = ""
    rule_id: str = ""
    #: web_server | app_server | language | gateway | framework | cdn | db
    category: str = ""
    severity: Severity = Severity.INFO
    #: "header" or "body"
    scope: str = "header"
    #: host that served the response, so per-node middleware stays separated
    host: str = ""
    source_url: str = ""
    status_code: int = 0

    def key(self) -> tuple:
        """Deduplication key: the same product/version/host is one banner."""
        return (self.product, self.version, self.host, self.scope)

    def to_dict(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "version": self.version,
            "raw": self.raw,
            "header": self.header,
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.value,
            "scope": self.scope,
            "host": self.host,
            "source_url": self.source_url,
            "status_code": self.status_code,
        }


@dataclass
class Issue:
    code: str = ""
    stage: str = ""
    url: str = ""
    message: str = ""
    retryable: bool = False


@dataclass
class HostAsset:
    """One deduplicated host with every place it was observed."""

    value: str = ""
    kind: str = ""          # domain | ipv4 | ipv6 | internal_host
    origin: str = "js"      # js (found in content) | scan (touched by scan)
    attributes: list[str] = field(default_factory=list)
    occurrences: int = 0
    vendor: bool = False
    sources: list["HostEvidence"] = field(default_factory=list)


@dataclass
class HostEvidence:
    source_url: str = ""
    raw: str = ""
    line: int = 0
    column: int = 0
    method: str = ""        # url | ast_literal | static_expression | regex
    associated_url: str = ""
    note: str = ""
    vendor: bool = False
    context_lines: list[ContextLine] = field(default_factory=list)


# How a probe status code should be read. An agent that sees "403" and "404"
# without this has to guess whether the interface exists, and it usually guesses
# wrong in the optimistic direction.
SIGNAL_EXISTS = "exists"          # 2xx: the interface answered
SIGNAL_PROTECTED = "protected"    # 401/403: real, but gated — an auth target
SIGNAL_METHOD = "method"          # 405: real, wrong verb for a GET probe
SIGNAL_GONE = "gone"              # 410
SIGNAL_SERVER_ERROR = "error"     # 5xx: real, misconfigured or erroring
SIGNAL_CLIENT_ERROR = "client_error"   # 4xx: ambiguous, often a generic handler
SIGNAL_NOT_FOUND = "not_found"    # 404/403-with-no-body: probably absent
SIGNAL_UNPROBED = "unprobed"      # no probe was sent
#: Signals derived from the response body rather than the status line.
#: Many APIs answer 200 with a business code, and "exists" says nothing
#: about whether the call succeeded.
SIGNAL_BIZ_SUCCESS = "biz_success"          # body says the call succeeded
SIGNAL_BIZ_AUTH_FAIL = "biz_auth_fail"      # body says auth failed
SIGNAL_BIZ_PARAM_MISSING = "biz_param_missing"  # body says a param is missing
SIGNAL_BIZ_ERROR = "biz_error"              # body says the call failed


def classify_status(status: int) -> str:
    """Map an HTTP status code to what it means for an attack surface.

    ``404`` is deliberately conservative: many frameworks route unknown paths
    to a catch-all that also answers 404, so "not_found" means "no evidence it
    exists", never "it does not exist".
    """
    if not status:
        return SIGNAL_UNPROBED
    if 200 <= status < 300:
        return SIGNAL_EXISTS
    if status in (401, 403):
        return SIGNAL_PROTECTED
    if status == 405:
        return SIGNAL_METHOD
    if status == 410:
        return SIGNAL_GONE
    if status >= 500:
        return SIGNAL_SERVER_ERROR
    if status in (404, 400, 422):
        return SIGNAL_NOT_FOUND if status == 404 else SIGNAL_CLIENT_ERROR
    return SIGNAL_CLIENT_ERROR


@dataclass
class Statistics:
    resources: int = 0
    scripts: int = 0
    chunks: int = 0
    endpoints: int = 0
    findings: int = 0
    routes: int = 0
    hosts: int = 0
    parameters: int = 0
    #: server / middleware products whose version was recovered
    banners: int = 0


@dataclass
class SPAEvidence:
    """Signals that the page loads code dynamically.

    Recorded so a reader knows *why* runtime evidence is absent: a dynamic
    import family cannot be enumerated by static analysis.
    """

    root_node: bool = False
    dynamic_import: bool = False
    history_routing: bool = False
    hash_routing: bool = False
    dynamic_script: bool = False
    webpack: bool = False
    requirejs: bool = False
    vite: bool = False
    large_bundle: bool = False

    def merge(self, other: "SPAEvidence") -> "SPAEvidence":
        for name in self.__dataclass_fields__:
            if not getattr(self, name) and getattr(other, name):
                setattr(self, name, True)
        return self

    @property
    def any(self) -> bool:
        return any(getattr(self, name) for name in self.__dataclass_fields__)


@dataclass
class Result:
    """Deterministic, serializable output of one target scan."""

    target: str = ""
    started_at: str = ""
    finished_at: str = ""
    mode: Mode = Mode.AUTO
    user_agent: str = ""
    resources: list[Resource] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    params: list[ParamHit] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    hosts: list[HostAsset] = field(default_factory=list)
    scan_hosts: list[HostAsset] = field(default_factory=list)
    spa: SPAEvidence = field(default_factory=SPAEvidence)
    #: server / middleware products whose version the target disclosed
    banners: list["Banner"] = field(default_factory=list)
    #: dynamic code that exists but has no single resolvable file — a glob
    #: family, or an import whose middle is a runtime map. Present so a reader
    #: knows the scan is not seeing everything, rather than assuming it is.
    hints: list[str] = field(default_factory=list)
    #: front-end routes with the result of rendering each one
    routes: list[dict] = field(default_factory=list)
    #: asset manifests recovered, with how many files each listed
    assets: list[dict] = field(default_factory=list)
    #: API specification documents recovered
    specs: list[dict] = field(default_factory=list)
    #: GraphQL operation documents embedded in the bundles, with their field
    #: sets — the target's own statement of what the server will hand over
    graphql: list[dict] = field(default_factory=list)
    #: Absolute path this run wrote its scripts to, or "" when saving was off
    #: or the directory could not be created. Resolved rather than as-configured
    #: so a caller never has to guess where a relative js_dir landed.
    js_dir: str = ""
    statistics: Statistics = field(default_factory=Statistics)
    issues: list[Issue] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(self)


_KEEP_EMPTY = frozenset(
    {"method", "url", "target", "kind", "scenario", "name", "value",
     "base_url", "evidence", "type", "mode", "category", "severity", "raw"}
)


def _serialize(obj: Any) -> Any:
    """Recursively convert dataclasses/enums to JSON-friendly primitives.

    Empty optionals are dropped so the payload stays readable; fields whose
    emptiness is meaningful (method, url, severity, ...) are always kept.
    """
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out: dict[str, Any] = {}
        for f in dataclasses.fields(obj):
            value = getattr(obj, f.name)
            if f.name not in _KEEP_EMPTY and _is_blank(value):
                continue
            out[f.name] = _serialize(value)
        return out
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, (list, tuple, set)):
        return [_serialize(item) for item in obj]
    if isinstance(obj, dict):
        return {key: _serialize(value) for key, value in obj.items()}
    return obj


def _is_blank(value: Any) -> bool:
    if value is None or value is False:
        return True
    if isinstance(value, (str, list, tuple, dict, set)) and len(value) == 0:
        return True
    return False


def count_by(items: list, predicate) -> int:
    return sum(1 for item in items if predicate(item))