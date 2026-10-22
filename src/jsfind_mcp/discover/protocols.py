"""Non-HTTP transports and the documents that describe them.

Everything else in this package looks at ``fetch``/``axios``/XHR. Three real
attack surfaces sit outside that vocabulary and were previously invisible:

* **WebSocket** — ``new WebSocket("wss://...")``. A push or notification
  channel is frequently authenticated differently from the REST API, and an
  unauthenticated socket is a common finding.
* **Server-Sent Events** — ``new EventSource("/api/stream")``. Same argument:
  a read-only stream that quietly leaks live records.
* **GraphQL** — the operation *document*. A query embedded in the bundle
  names every field the server will hand over, including the ones the UI never
  renders. Finding ``user { id email isAdmin }`` is stronger than finding the
  endpoint that fetches it.
"""

from __future__ import annotations

import re

from .types import Candidate, Kind

# -- WebSocket ------------------------------------------------------------

_WS_CALL = re.compile(
    r"""(?is)\b(?:new\s+WebSocket|socket\s*\(\s*|io\s*\(\s*|WebSocket\.connect"""
    r"""\s*\(\s*)"""
    r"""(?P<q>["'`])(?P<url>(?:wss?|https?)://[^"'`\s]+)"""
)
_WS_BARE = re.compile(
    r"""(?i)(?<![\w./-])(wss?://[A-Za-z0-9._-]+(?::\d+)?(?:/[^\s"'`<>]*)?)"""
)
# Socket.IO / SockJS style path-only references.
_WS_PATH = re.compile(
    r"""(?i)["'](/(?:socket\.io|sockjs|ws|websocket|mqtt)[^"'\s]*)["']"""
)

# -- Server-Sent Events ---------------------------------------------------

_SSE_CALL = re.compile(
    r"""(?is)\b(?:new\s+EventSource|EventSource\.connect)\s*\(\s*"""
    r"""(?P<q>["'`])(?P<url>[^"'`\s]+)"""
)

# -- GraphQL --------------------------------------------------------------

#: A GraphQL endpoint: a path whose last segment names the protocol.
_GRAPHQL_PATH = re.compile(
    r"""(?i)(?<![\w./-])(/[\w./-]{0,60}/(?:graphql|gql|query|graphiql)"""
    r"""(?:/[\w./-]{0,20})?)(?![\w./-])"""
)
_GRAPHQL_FULL = re.compile(
    r"""(?i)(?<![\w./-])((?:https?|wss?)://[A-Za-z0-9._-]+(?::\d+)?"""
    r"""/(?:[\w./-]{0,60})?/(?:graphql|gql|query)(?![\w./-]))"""
)
#: An operation document: gql`...`, gql("..."), GraphQL`...`.
_GRAPHQL_DOC = re.compile(
    r"""(?is)\b(?:gql|graphql)\s*(?:\(\s*)?(?P<q>["'`])"""
    r"""(?P<doc>\s*(?:query|mutation|subscription|fragment)\b.*?)"""
    r"""(?P=q)"""
)
#: Apollo/urql client against a relative path.
_GRAPHQL_CLIENT = re.compile(
    r"""(?i)\b(?:ApolloClient|createClient|gql`|graphql)\s*\(?"""
    r"""[^)]{0,80}?uri\s*:\s*(?P<q>["'`])(?P<url>/[^"'`]+)(?P=q)"""
)

_OPERATION_NAME = re.compile(
    r"""(?x)\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)"""
)
_FIELD_NAMES = re.compile(
    r"""(?x)
    \{\s*
    (?:[A-Za-z_][A-Za-z0-9_]*(?:\s*\([^)]*\))?\s+)+
    """
)

#: Fields that reveal a schema far more than the names do.
_INTERESTING_GRAPHQL_FIELDS = frozenset({
    "password", "passwd", "pwd", "token", "secret", "apikey", "api_key",
    "isadmin", "is_admin", "superuser", "is_superuser", "role", "roles",
    "permission", "permissions", "authority", "authorities", "email",
    "phone", "mobile", "idcard", "id_card", "identity", "ssn", "balance",
    "amount", "credit", "internal", "debug", "rawpassword", "oldpassword",
    "salt", "privatekey", "private_key", "credential",
})

#: GraphQL field names are camelCase, so an exact-match set alone misses
#: ``rawPassword``, ``accessToken`` and ``isAdminOverride`` — the most
#: interesting names there are. These fragments are matched anywhere in the
#: name. The list is deliberately short and high-signal: a lead with a stated
#: reason is worth more than a silent miss, but a loose match would bury the
#: real ones in noise.
_SENSITIVE_FIELD_FRAGMENTS = (
    "password", "passwd", "secret", "token", "apikey", "credential",
    "privatekey", "isadmin", "superuser", "idcard", "ssn",
)

_MAX_DOC_LENGTH = 4000


class GraphQLOperation:
    """One operation document recovered from the bundle."""

    def __init__(self, kind: str = "query", name: str = "", document: str = "",
                 url: str = "", fields: list[str] | None = None,
                 sensitive_fields: list[str] | None = None):
        self.kind = kind
        self.name = name
        self.document = document
        self.url = url
        self.fields = list(fields or [])
        self.sensitive_fields = list(sensitive_fields or [])

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "name": self.name,
            "url": self.url,
            "fields": self.fields[:60],
            "sensitive_fields": self.sensitive_fields,
            "document": self.document[:_MAX_DOC_LENGTH],
        }


def from_protocols(source_url: str, body: str,
                   limit: int = 200) -> tuple[list[Candidate], list[GraphQLOperation], list[str]]:
    """Extract WebSocket, SSE and GraphQL references from one script body.

    Returns ``(candidates, operations, hints)``. Anything that cannot be
    resolved to a single URL is reported as a hint rather than dropped.
    """
    candidates: list[Candidate] = []
    operations: list[GraphQLOperation] = []
    hints: list[str] = []
    seen: set[str] = set()

    def add(raw: str, kind: str, rule: str) -> None:
        raw = (raw or "").strip()
        if not raw or raw in seen:
            return
        seen.add(raw)
        candidates.append(Candidate(
            raw=raw, kind=kind, source_url=source_url,
            source="protocol", rule_id=rule,
        ))

    # -- WebSocket
    for match in _WS_CALL.finditer(body):
        add(match.group("url"), Kind.ENDPOINT, "ws.call")
    for match in _WS_BARE.finditer(body):
        add(match.group(1), Kind.ENDPOINT, "ws.url")
    for match in _WS_PATH.finditer(body):
        add(match.group(1), Kind.ENDPOINT, "ws.path")

    # -- SSE
    for match in _SSE_CALL.finditer(body):
        add(match.group("url"), Kind.ENDPOINT, "sse.call")

    # -- GraphQL endpoints
    for match in _GRAPHQL_FULL.finditer(body):
        add(match.group(1), Kind.ENDPOINT, "graphql.url")
    for match in _GRAPHQL_PATH.finditer(body):
        add(match.group(1), Kind.ENDPOINT, "graphql.path")
    for match in _GRAPHQL_CLIENT.finditer(body):
        add(match.group("url"), Kind.ENDPOINT, "graphql.client-uri")

    # -- GraphQL documents
    for match in _GRAPHQL_DOC.finditer(body):
        document = match.group("doc").strip()
        if not document or len(document) > _MAX_DOC_LENGTH:
            continue
        operation = _read_operation(document)
        operations.append(operation)
        if operation.url:
            add(operation.url, Kind.ENDPOINT, "graphql.operation")

    if len(candidates) > limit:
        hints.append(f"协议类引用超过 {limit} 条，已截断。")
        del candidates[limit:]

    return candidates, operations, hints


def _read_operation(document: str) -> GraphQLOperation:
    """Pull the kind, name and field set out of one operation document."""
    head = document.lstrip()
    kind = "query"
    for candidate in ("mutation", "subscription", "fragment", "query"):
        if head.startswith(candidate):
            kind = "query" if candidate == "fragment" else candidate
            break
    name_match = _OPERATION_NAME.search(head)
    name = name_match.group(1) if name_match else ""

    fields = _field_names(document)
    sensitive = [f for f in fields if _is_sensitive_field(f)]
    return GraphQLOperation(kind=kind, name=name, document=document,
                           fields=fields, sensitive_fields=sensitive)


def _is_sensitive_field(name: str) -> bool:
    """Whether a selected field is worth a tester's attention.

    Exact match first so the precise names stay authoritative, then a fragment
    match because GraphQL's camelCase naming defeats an exact set on its own.
    """
    lowered = (name or "").lower()
    if lowered in _INTERESTING_GRAPHQL_FIELDS:
        return True
    stripped = lowered.replace("_", "")
    return any(fragment in lowered or fragment in stripped
               for fragment in _SENSITIVE_FIELD_FRAGMENTS)


def _field_names(document: str) -> list[str]:
    """Every identifier that appears as a field selection.

    Deliberately forgiving: a query's field set is written many ways, and a
    partial list still tells a tester what the server will hand over.
    """
    body = document
    start = body.find("{")
    if start < 0:
        return []
    body = body[start:]
    names: list[str] = []
    seen: set[str] = set()
    # Field selections sit between braces; skip string values and arguments.
    for token in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)", body):
        name = token.group(1)
        if name in ("query", "mutation", "subscription", "fragment", "on", "true",
                    "false", "null"):
            continue
        if name in seen:
            continue
        seen.add(name)
        names.append(name)
        if len(names) >= 120:
            break
    return names
