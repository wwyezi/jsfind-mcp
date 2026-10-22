"""Tree-sitter AST extraction of API calls and their request shape.

What the regex pass cannot do, this module does:

* **bind constants** — follow ``const base = "/api"`` into every later use, so
  ``axios.post(base + "/user")`` resolves to ``/api/user``;
* **fold concatenation** — ``"a" + b + "/" + c``, ``[...].join("")`` and
  ``String.prototype.concat`` chains all collapse into one value;
* **name the verb** — ``xhr.open("DELETE", ...)`` and ``axios.patch(...)``
  bind a real method, while the regex pass can only guess;
* **separate query from body** — ``{params: {...}}``, ``{data: {...}}`` and
  ``{json: {...}}`` become two distinct parameter sets.

Values that cannot be folded keep their *name* (``/api/user/{id}``), so a
fuzzer still knows the shape of the interface it is aiming at.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..model import (
    ContextLine,
    EVIDENCE_FULL_URL,
    EVIDENCE_STATIC,
    Param,
    RequestSpec,
)
from ..utils import (
    CONTEXT_SPAN_LINES,
    decode_js_string,
    extract_context,
    join_base_url,
    line_column,
    looks_like_path,
)
from .jsparser import Kind, parse_javascript
from .types import Candidate, JSResult

# Body-argument selectors. A negative number is a sentinel describing a
# *config object* whose keys name where the payload lives.
BODY_DIRECT = 0
BODY_NONE = -1
BODY_CONFIG_PARAMS_DATA = -2
BODY_CONFIG_BODY = -3
BODY_CONFIG_JSON = -4
BODY_CONFIG_PARAMS_BODY_JSON = -5
BODY_CONFIG_PARAMS_DATA_REQUEST = -6
BODY_CONFIG_AXIOS_TRAILING = -7

_HTTP_VERBS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_WRITE_VERBS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Member names that mean "this is an HTTP verb call" regardless of receiver.
_VERB_MEMBERS = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options", "getJSON",
    "Get", "Post", "Put", "Patch", "Delete", "Head",
})

# Bare call names that are HTTP clients.
_CLIENT_FUNCTIONS = frozenset({
    "fetch", "ajax", "api", "request", "useSWR",
    "$fetch", "ofetch", "$ofetch", "ky", "getJSON", "postJSON",
})

# Receivers that qualify a member call as HTTP (mini programs, WeChat, Alipay…).
_MINI_PROGRAM_RECEIVERS = frozenset({
    "wx", "my", "tt", "swan", "qq", "ks", "qg", "dd", "jsBridge", "anchored",
})

# Builders whose ``append("k", v)`` chain declares request fields.
_BODY_BUILDERS = frozenset({"URLSearchParams", "FormData", "SearchParams"})

_CONTENT_TYPE_JSON = ("application/json", "text/json")
_CONTENT_TYPE_FORM = ("application/x-www-form-urlencoded", "multipart/form-data")

# Guard against pathological recursion through deeply nested expressions.
_MAX_FOLD_DEPTH = 8


@dataclass
class ApiCall:
    """One recovered request call site."""

    raw: str = ""
    method: str = ""
    evidence: str = ""
    line: int = 0
    column: int = 0
    context: list[ContextLine] = field(default_factory=list)
    spec: RequestSpec | None = None

    def dedup_key(self) -> str:
        return f"{self.method}\x00{self.raw}"


class Walker:
    """Single-pass request-oriented walker with per-function scope tables."""

    def __init__(self, source: str, max_bytes: int = 8 * 1024 * 1024):
        self.source = source
        self.tree = parse_javascript(source, max_bytes=max_bytes)
        self.calls: list[ApiCall] = []
        # string constants bound by identifier, per function scope
        self.constants: dict[tuple[int, str], str] = {}
        # object-literal bindings, so a wrapper called with a variable can
        # still resolve its fields: {"url": "/x", "data": t}
        self.object_bindings: dict[tuple[int, str], list] = {}
        # axios instance -> declared baseURL
        self.instance_base: dict[tuple[int, str], str] = {}
        self.instance_base_kind: dict[tuple[int, str], str] = {}
        # variable -> URLSearchParams/FormData builder
        self.builders: dict[tuple[int, str], str] = {}
        # variable -> [(key, value_node)] from append() chains
        self.appends: dict[tuple[int, str], list] = {}
        # object name -> [(key, value_node)] from o.key = value statements
        self.member_writes: dict[tuple[int, str], list] = {}
        self.func_stack: list[int] = []
        self.line_starts: list[int] | None = None
        self._line_index: list[int] | None = None

    # -- node helpers ---------------------------------------------------

    def lookup(self, table: dict, name: str, default=None):
        """Read a binding, walking outward through enclosing scopes.

        Exact-scope lookup alone meant a file-scope constant was invisible from
        inside any function — which is how most bundles actually use them. Inner
        scopes shadow outer ones, matching JavaScript resolution.
        """
        if not name:
            return default
        for scope in reversed(self.func_stack):
            found = table.get((scope, name))
            if found is not None:
                return found
        found = table.get((0, name))
        return default if found is None else found

    @property
    def available(self) -> bool:
        return self.tree is not None

    def text(self, node) -> str:
        if node is None:
            return ""
        return self.source[node.start_byte:node.end_byte]

    def field(self, node, name: str):
        if node is None:
            return None
        return node.child_by_field_name(name)

    def unwrap(self, node):
        """Strip parentheses so a wrapped expression looks like its core."""
        while node is not None and node.type in Kind.TRANSPARENT_KINDS:
            children = node.named_children
            if not children:
                break
            node = children[0]
        return node

    def named_children(self, node) -> list:
        return list(node.named_children) if node is not None else []

    def arguments(self, call) -> list:
        node = self.field(call, "arguments")
        if node is None:
            return []
        return [child for child in node.named_children
                if child.type != "comment"]

    def property_name(self, node) -> str:
        node = self.unwrap(node)
        if node is None:
            return ""
        if node.type == Kind.STRING:
            return decode_js_string(self.text(node))
        if node.type in Kind.KEY_KINDS:
            return self.text(node)
        return ""

    def object_value(self, obj, wanted: str):
        """The value node for one key of an object literal, or None."""
        obj = self.unwrap(obj)
        if obj is None or obj.type != Kind.OBJECT:
            return None
        for pair in obj.named_children:
            if pair.type != Kind.PAIR:
                continue
            if self.property_name(self.field(pair, "key")) == wanted:
                return self.field(pair, "value")
        return None

    def object_pairs(self, obj) -> list:
        obj = self.unwrap(obj)
        if obj is None or obj.type != Kind.OBJECT:
            return []
        out = []
        for pair in obj.named_children:
            if pair.type != Kind.PAIR:
                continue
            key = self.property_name(self.field(pair, "key"))
            if key:
                out.append((key, self.field(pair, "value")))
        return out

    def member_parts(self, node) -> tuple[object, str] | None:
        """Split ``a.b.c`` into ``(a, "b.c")``; None for anything else."""
        node = self.unwrap(node)
        if node is None or node.type != Kind.MEMBER_EXPRESSION:
            return None
        obj = self.unwrap(self.field(node, "object"))
        prop = self.field(node, "property")
        if obj is None or prop is None:
            return None
        # A computed key (a["b"]) is a runtime decision, not a fixed path.
        if prop.type not in (Kind.PROPERTY_IDENTIFIER, Kind.IDENTIFIER, Kind.STRING):
            return None
        name = decode_js_string(self.text(prop)) if prop.type == Kind.STRING \
            else self.text(prop)
        if not name:
            return None
        return obj, name

    # -- scopes ---------------------------------------------------------

    @property
    def scope(self) -> int:
        """Current function scope key (0 = file scope)."""
        return self.func_stack[-1] if self.func_stack else 0

    def push_scope(self, node) -> int:
        start = node.start_byte
        self.func_stack.append(start)
        return start

    def pop_scope(self) -> None:
        self.func_stack.pop()

    # -- constant folding -----------------------------------------------

    def line_col(self, offset: int) -> tuple[int, int]:
        if self._line_index is None:
            from ..utils import line_starts

            self._line_index = line_starts(self.source)
        return line_column(self.source, offset, self._line_index)

    def static_string(self, node, depth: int = 0) -> str | None:
        """Fold a node to a string constant, or None when it is dynamic.

        An identifier that was never bound folds to the ``{}`` placeholder
        rather than failing: ``"/api/" + userId + "/info"`` is still a usable
        endpoint shape, and reporting the name is what a fuzzer needs.
        """
        node = self.unwrap(node)
        if node is None or depth > _MAX_FOLD_DEPTH:
            return None
        if node.type == Kind.STRING:
            return decode_js_string(self.text(node))
        if node.type == Kind.NUMBER:
            return self.text(node)
        if node.type == Kind.IDENTIFIER:
            name = self.text(node)
            bound = self.lookup(self.constants, name)
            if bound is not None:
                return bound
            if name in ("undefined", "null"):
                return ""
            # Keep the symbol as a placeholder: "/user/" + userId becomes
            # "/user/{userId}", which tells a fuzzer exactly what to substitute.
            return "{" + name + "}"
        if node.type == Kind.TEMPLATE_STRING:
            return self.template_value(node)
        if node.type == Kind.BINARY_EXPRESSION:
            operator = self.text(self.field(node, "operator"))
            if operator != "+":
                return None
            left = self.static_string(self.field(node, "left"), depth + 1)
            right = self.static_string(self.field(node, "right"), depth + 1)
            if left is None or right is None:
                return None
            return left + right
        if node.type == Kind.CALL_EXPRESSION:
            return self.fold_call(node, depth)
        if node.type == Kind.SUBSCRIPT_EXPRESSION:
            return self.fold_subscript(node, depth)
        if node.type == Kind.CONDITIONAL_EXPRESSION:
            # Both branches are plausible request targets; the first wins here
            # and the caller adds the other as a separate candidate.
            return self.static_string(self.field(node, "consequence"), depth + 1)
        if node.type == Kind.SEQUENCE_EXPRESSION:
            children = self.named_children(node)
            if not children:
                return None
            return self.static_string(children[-1], depth + 1)
        if node.type == Kind.MEMBER_EXPRESSION:
            # window.location.origin and friends: keep the dotted name so the
            # report shows what the code referenced.
            parts = self.member_parts(node)
            if not parts:
                return None
            obj, name = parts
            root = self.static_string(obj, depth + 1)
            return f"{root}.{name}" if root else None
        return None

    def template_value(self, node) -> str:
        """Render a template literal, keeping holes as ``{expression}``."""
        out: list[str] = []
        for child in node.named_children:
            if child.type == Kind.TEMPLATE_SUBSTITUTION:
                inner = self.named_children(child)
                if inner:
                    folded = self.static_string(inner[0])
                    if folded is not None and folded != "{}":
                        out.append(folded)
                        continue
                    out.append("{" + self.text(inner[0]).strip() + "}")
                continue
            out.append(decode_js_string(self.text(child)))
        return "".join(out)

    def fold_call(self, node, depth: int = 0) -> str | None:
        """Fold ``concat`` / ``join`` / ``atob`` chains the way ``+`` folds."""
        callee = self.unwrap(self.field(node, "function"))
        args = self.arguments(node)

        if callee is not None and callee.type == Kind.IDENTIFIER:
            name = self.text(callee)
            if name == "atob" and len(args) == 1:
                import base64
                import binascii

                raw = self.static_string(args[0])
                if raw:
                    try:
                        return base64.b64decode(raw + "===").decode("utf-8", "replace")
                    except (binascii.Error, ValueError, UnicodeDecodeError):
                        return raw
                return None
            if name in ("encodeURIComponent", "encodeURI", "String") and args:
                return self.static_string(args[0])
            return None

        parts = self.member_parts(callee) if callee is not None else None
        if not parts:
            return None
        obj, name = parts
        obj = self.unwrap(obj)

        if name == "concat":
            folded = self.static_string(obj)
            if folded is None:
                return None
            for arg in args:
                piece = self.static_string(arg)
                if piece is None:
                    return None
                folded += piece
            return folded

        if name == "join":
            if obj is None or obj.type != Kind.ARRAY:
                return None
            separator = self.static_string(args[0]) if args else ""
            if separator is None:
                separator = ""
            pieces: list[str] = []
            for element in obj.named_children:
                piece = self.static_string(element)
                if piece is None:
                    return None
                pieces.append(piece)
            return separator.join(pieces)

        if name == "toString" and not args:
            return self.static_string(obj)
        return None

    def fold_subscript(self, node, depth: int = 0) -> str | None:
        """Fold ``obj[key]`` when both sides are statically known."""
        obj = self.unwrap(self.field(node, "object"))
        index = self.unwrap(self.field(node, "index"))
        if obj is None or index is None:
            return None
        if obj.type != Kind.OBJECT or index.type != Kind.STRING:
            return None
        key = decode_js_string(self.text(index))
        value = self.object_value(obj, key)
        return self.static_string(value) if value is not None else None

    # -- binding --------------------------------------------------------

    def bind(self, name_node, value_node) -> None:
        """Record identifier -> constant/object/builder bindings."""
        name_node = self.unwrap(name_node)
        value_node = self.unwrap(value_node)
        if name_node is None or value_node is None:
            return
        if name_node.type != Kind.IDENTIFIER:
            return
        name = self.text(name_node)
        scope = self.scope
        self.object_bindings.pop((scope, name), None)
        self.builders.pop((scope, name), None)

        folded = self.static_string(value_node)
        if folded is not None and value_node.type in (
            Kind.STRING, Kind.TEMPLATE_STRING, Kind.BINARY_EXPRESSION,
        ):
            self.constants[(scope, name)] = folded
            return
        if folded is not None and value_node.type == Kind.IDENTIFIER:
            self.constants[(scope, name)] = folded
            return

        if value_node.type == Kind.OBJECT:
            self._bind_object(scope, name, value_node)
            return

        if value_node.type == Kind.CALL_EXPRESSION:
            # axios.create({baseURL}) / new Ajax({url}) — the declared prefix
            # lives one call deeper than the assignment.
            config = self._config_argument(value_node)
            if config is not None:
                self._bind_object(scope, name, config)
            return

        if value_node.type == Kind.NEW_EXPRESSION:
            builder = constructor_name(value_node)
            if builder in _BODY_BUILDERS:
                self.builders[(scope, name)] = builder

    def _base_kind(self, node) -> str:
        node = self.unwrap(node)
        if node is None:
            return ""
        if node.type == Kind.STRING:
            return "literal"
        if node.type == Kind.IDENTIFIER:
            return "constant"
        return "inferred"

    def _bind_object(self, scope: int, name: str, obj) -> None:
        """Record what an object literal tells us about a binding.

        It may be an ``axios.create`` config (declaring an interface prefix), a
        ``params`` config (whose keys are query names), or a request payload.
        Both readings are recorded; the report decides which one mattered.
        """
        self.object_bindings[(scope, name)] = obj
        base = self.object_value(obj, "baseURL") or self.object_value(obj, "baseUrl")
        if base is not None:
            resolved = self.static_string(base)
            if resolved:
                self.instance_base[(scope, name)] = resolved
                self.instance_base_kind[(scope, name)] = self._base_kind(base)
        params = self.object_value(obj, "params")
        if params is not None and self.unwrap(params).type == Kind.OBJECT:
            self.constants[(scope, name)] = self._query_of(self.unwrap(params))

    def _config_argument(self, call):
        """The config object of a builder call, if there is one."""
        for arg in self.arguments(call):
            arg = self.unwrap(arg)
            if arg is not None and arg.type == Kind.OBJECT:
                return arg
        return None

    def _query_of(self, params_node) -> str:
        pieces = []
        for key, value in self.object_pairs(params_node):
            folded = self.static_string(value)
            pieces.append(f"{key}={folded}" if folded is not None else key)
        return "?" + "&".join(pieces) if pieces else ""

    # -- payload extraction ---------------------------------------------

    def build_spec(self, args: list, body_arg: int) -> RequestSpec | None:
        """Normalized request shape (query/body params, content type, baseURL)."""
        query_nodes: list[tuple[str, object]] = []
        body_nodes: list[tuple[str, object]] = []

        def add(config, key: str, into_query: bool) -> None:
            value = self.object_value(config, key)
            if value is None:
                return
            (query_nodes if into_query else body_nodes).append((key, value))

        if body_arg == BODY_CONFIG_PARAMS_DATA:
            if args:
                add(args[0], "params", True)
                add(args[0], "data", False)
        elif body_arg == BODY_CONFIG_BODY:
            if len(args) > 1:
                add(args[1], "body", False)
        elif body_arg == BODY_CONFIG_JSON:
            if len(args) > 1:
                add(args[1], "json", False)
        elif body_arg == BODY_CONFIG_PARAMS_BODY_JSON:
            if len(args) > 1:
                add(args[1], "params", True)
                add(args[1], "body", False)
                add(args[1], "json", False)
        elif body_arg == BODY_CONFIG_PARAMS_DATA_REQUEST:
            if len(args) > 1:
                add(args[1], "params", True)
                add(args[1], "data", False)
        elif body_arg == BODY_CONFIG_AXIOS_TRAILING:
            if len(args) > 1:
                add(args[1], "params", True)
                add(args[1], "data", False)
                add(args[1], "body", False)
                add(args[1], "json", False)
        elif 0 <= body_arg < len(args):
            body_nodes.append(("data", args[body_arg]))
        elif body_arg == BODY_NONE and args and len(args) > 1:
            # A GET with a trailing config object still carries query fields.
            add(args[1], "params", True)

        spec = RequestSpec()
        spec.query = self._params_from(query_nodes, source="config")
        spec.body = self._params_from(body_nodes, source="config")
        content_type, evidence = self._detect_content_type(args, body_nodes)
        if content_type:
            spec.content_type = content_type
            spec.content_type_evidence = evidence
        return spec

    def _params_from(self, pairs: list, source: str) -> list[Param]:
        out: list[Param] = []
        for key, node in pairs:
            node = self.unwrap(node)
            if node is None:
                continue
            if node.type == Kind.OBJECT:
                out.extend(self._object_params(node, source=source))
                continue
            if node.type == Kind.NEW_EXPRESSION:
                builder = constructor_name(node)
                if builder in _BODY_BUILDERS:
                    name = self._builder_name(node)
                    for entry_key, _entry_value in self.lookup(self.appends, name, []) or []:
                        out.append(Param(key=entry_key, evidence="inferred"))
                    continue
                out.append(Param(key="data", evidence="inferred"))
                continue
            if node.type == Kind.IDENTIFIER:
                # A variable payload: resolve an object binding, then the
                # incrementally-assembled o.key = value form.
                name = self.text(node)
                binding = self.lookup(self.object_bindings, name)
                if binding is not None:
                    out.extend(self._object_params(binding, source=source))
                    continue
                writes = self.lookup(self.member_writes, name)
                if writes:
                    for entry_key, _value in writes:
                        out.append(Param(key=entry_key, evidence="inferred"))
                    continue
                out.append(Param(key=name, evidence="inferred"))
                continue
            out.append(Param(key=key, value=self.static_string(node) or "",
                             evidence="inferred"))
        return _dedupe_params(out)

    def _object_params(self, obj_node, source: str = "object") -> list[Param]:
        out: list[Param] = []
        for key, value in self.object_pairs(obj_node):
            value = self.unwrap(value)
            evidence = "inferred"
            literal = ""
            if value is not None:
                if value.type == Kind.STRING:
                    literal = decode_js_string(self.text(value))
                    evidence = "literal"
                elif value.type == Kind.NUMBER:
                    literal = self.text(value)
                    evidence = "literal"
                elif value.type == Kind.TEMPLATE_STRING:
                    literal = self.template_value(value)
                    evidence = "constant"
                elif value.type == Kind.IDENTIFIER:
                    bound = self.lookup(self.constants, self.text(value))
                    if bound is not None:
                        literal = bound
                        evidence = "constant"
                    else:
                        literal = "{" + self.text(value).strip() + "}"
                        evidence = "placeholder"
                elif value.type in (Kind.OBJECT, Kind.ARRAY):
                    evidence = "inferred"
                else:
                    folded = self.static_string(value)
                    literal = folded if folded is not None else ""
                    evidence = "inferred"
            out.append(Param(key=key, value=literal, evidence=evidence))
        return _dedupe_params(out)

    def _builder_name(self, new_node) -> str:
        for child in new_node.named_children:
            if child.type == Kind.IDENTIFIER:
                return self.text(child)
        return ""

    def _detect_content_type(self, args: list, body_nodes: list) -> tuple[str, str]:
        """Content type from an explicit header, else inferred from the payload."""
        for arg in args:
            headers = self.object_value(arg, "headers")
            if headers is None:
                continue
            for key, value in self.object_pairs(headers):
                if key.lower() != "content-type":
                    continue
                folded = self.static_string(value)
                if folded:
                    return folded, "literal"
        for _key, node in body_nodes:
            node = self.unwrap(node)
            if node is None:
                continue
            builder = self.lookup(self.builders, self.text(node)) \
                if node.type == Kind.IDENTIFIER else ""
            if builder == "FormData":
                return "multipart/form-data", "inferred"
            if builder == "URLSearchParams":
                return "application/x-www-form-urlencoded", "inferred"
            folded = (self.static_string(node) or "").lower()
            if "formdata" in folded or "urlsearchparams" in folded:
                return "multipart/form-data", "inferred"
        return ("application/json", "inferred") if body_nodes else ("", "")

    def record_append(self, builder_name: str, key: str, value_node) -> None:
        self.appends.setdefault((self.scope, builder_name), []).append((key, value_node))

    def record_member_write(self, object_name: str, key: str, value_node) -> None:
        self.member_writes.setdefault((self.scope, object_name), []).append(
            (key, value_node)
        )

    # -- call recording -------------------------------------------------

    def record_call(self, callee, raw: str, method: str, args: list, body_arg: int) -> None:
        if not raw or not looks_like_path(raw):
            return
        evidence = EVIDENCE_FULL_URL if "://" in raw else EVIDENCE_STATIC
        offset = callee.start_byte if callee is not None else 0
        line, column = self.line_col(offset)
        spec = self.build_spec(args, body_arg)

        receiver = self.outermost_identifier(self.member_parts(callee)[0]) \
            if self.member_parts(callee) else ""
        base = self.lookup(self.instance_base, receiver, "") if receiver else ""
        if base and spec is not None and not spec.base_url:
            spec.base_url = base
            spec.base_url_kind = self.lookup(self.instance_base_kind, receiver, "")

        # A concat whose base never folded leaves a placeholder at the
        # front: `D.a + "/downloadList"` becomes `{D}.a/downloadList`,
        # and that is not a URL anyone can use. The path half is what a
        # tester wants, and the regex pass already records it cleanly,
        # so keep only the path and drop the fold when there is none.
        if raw.startswith("{"):
            slash = raw.find("/")
            if slash < 0:
                return
            raw = raw[slash:]
        self.calls.append(ApiCall(
            raw=raw, method=method, evidence=evidence, line=line, column=column,
            context=extract_context(self.source, offset, CONTEXT_SPAN_LINES, raw),
            spec=spec,
        ))
        # Both the raw path and the joined full URL are useful; record the
        # joined form too so a consumer can copy either.
        if base and evidence == EVIDENCE_STATIC:
            joined = join_base_url(base, raw)
            if joined:
                self.calls.append(ApiCall(
                    raw=joined, method=method, evidence=EVIDENCE_FULL_URL,
                    line=line, column=column,
                    context=extract_context(self.source, offset, CONTEXT_SPAN_LINES, raw),
                    spec=spec,
                ))

    def outermost_identifier(self, node) -> str:
        """``a.b.c`` -> ``a``; used to key axios-instance lookups."""
        node = self.unwrap(node)
        if node is None:
            return ""
        if node.type == Kind.IDENTIFIER:
            return self.text(node)
        if node.type == Kind.MEMBER_EXPRESSION:
            return self.outermost_identifier(self.field(node, "object"))
        return ""

    # -- the walk -------------------------------------------------------

    def run(self) -> list[ApiCall]:
        if self.tree is None:
            return []
        self._walk(self.tree.root_node)
        return _dedupe_calls(self.calls)

    def _walk(self, node) -> None:
        if node is None:
            return
        node_type = node.type
        if node_type == Kind.VARIABLE_DECLARATOR:
            self.bind(self.field(node, "name"), self.field(node, "value"))
            self._walk_children(node)
            return
        if node_type == Kind.ASSIGNMENT_EXPRESSION:
            self._on_assignment(node)
            return
        if node_type == Kind.CALL_EXPRESSION:
            self._on_call(node)
            return
        if node_type == Kind.NEW_EXPRESSION:
            self._on_new_expression(node)
            return
        if node_type in Kind.FUNCTION_KINDS:
            self.push_scope(node)
            self._walk_children(node)
            self.pop_scope()
            return
        self._walk_children(node)

    def _walk_children(self, node) -> None:
        for child in node.named_children:
            self._walk(child)

    def _on_assignment(self, node) -> None:
        left = self.unwrap(self.field(node, "left"))
        right = self.unwrap(self.field(node, "right"))
        self.bind(left, right)
        # o.key = value — the incremental payload builder.
        if left is not None and left.type == Kind.MEMBER_EXPRESSION:
            obj = self.unwrap(self.field(left, "object"))
            prop = self.field(left, "property")
            if obj is not None and obj.type == Kind.IDENTIFIER and \
                    prop is not None and prop.type in (Kind.PROPERTY_IDENTIFIER, Kind.IDENTIFIER):
                self.record_member_write(self.text(obj), self.text(prop), right)
        self._walk_children(node)

    def _on_new_expression(self, node) -> None:
        name = constructor_name(node)
        # new URL(path, base) is a request target worth reporting; URLSearchParams
        # and FormData are recorded as builders when bound to a variable.
        if name == "URL":
            for child in self.named_children(node):
                folded = self.static_string(child)
                if folded and looks_like_path(folded):
                    self.record_call(node, folded, "GET", [], BODY_NONE)
                    break
        self._walk_children(node)

    def _on_call(self, call) -> None:
        callee = self.unwrap(self.field(call, "function"))
        args = self.arguments(call)
        if callee is None:
            return

        self._record_builder_appends(callee, args)

        method, url_arg, body_arg = "", BODY_NONE, BODY_DIRECT
        url_override = None
        parts = self.member_parts(callee)
        if parts:
            obj, name = parts
            receiver = self.outermost_identifier(obj)
            if name == "open":
                # XMLHttpRequest.open(method, url, ...)
                if len(args) >= 2 and self.unwrap(args[0]) is not None and \
                        self.unwrap(args[0]).type == Kind.STRING:
                    method = decode_js_string(self.text(args[0])).upper()
                    url_arg, body_arg = 1, BODY_NONE
            elif name in _VERB_MEMBERS:
                method = name[:-4] if name.endswith("JSON") else name
                method = method.upper()
                url_arg = 0
                obj_call = self.unwrap(obj)
                if obj_call is not None and obj_call.type == Kind.CALL_EXPRESSION:
                    # wretch("/api/x").post(body) — the URL is in the head call.
                    head = self.unwrap(self.field(obj_call, "function"))
                    head_args = self.arguments(obj_call)
                    if head is not None and self.text(head) == "wretch" and head_args:
                        url_override = head_args[0]
                        url_arg = BODY_NONE
                        body_arg = 0 if method in _WRITE_VERBS else BODY_NONE
                if receiver == "ky" and len(args) > 1:
                    body_arg = BODY_CONFIG_JSON
                elif method in _WRITE_VERBS and body_arg == 0:
                    body_arg = 1
                elif len(args) > 1:
                    body_arg = BODY_CONFIG_AXIOS_TRAILING
            elif name in ("request", "ajax", "api") or \
                    (name == "request" and receiver in _MINI_PROGRAM_RECEIVERS):
                method, url_override, body_arg = self._config_call(args)
            elif name == "fetch":
                method, url_arg = "GET", 0
                if len(args) > 1:
                    method = self._options_method(args[1]) or method
                    body_arg = BODY_CONFIG_BODY
        elif callee.type == Kind.IDENTIFIER and self.text(callee) in _CLIENT_FUNCTIONS:
            name = self.text(callee)
            if name == "fetch":
                method, url_arg = "GET", 0
                if len(args) > 1:
                    method = self._options_method(args[1]) or method
                    body_arg = BODY_CONFIG_BODY
            elif name in ("ajax", "api"):
                method, url_override, body_arg = self._config_call(args)
            elif name == "request":
                method, url_arg = "GET", 0
                if len(args) > 1:
                    method = self._options_method(args[1]) or method
                    body_arg = BODY_CONFIG_PARAMS_DATA_REQUEST
            elif name == "useSWR":
                method, url_arg = "GET", 0
            else:  # $fetch / ofetch / ky
                method, url_arg = "GET", 0
                if len(args) > 1:
                    method = self._options_method(args[1]) or method
                    body_arg = BODY_CONFIG_PARAMS_BODY_JSON

        if url_override is None and url_arg == BODY_NONE and args:
            # A wrapper hides the shape behind a call expression, e.g.
            # Object(service["a"])({url:"/soap/x", method:"post"}).
            first = self.unwrap(args[0])
            if first is not None and first.type == Kind.OBJECT and \
                    self.object_value(first, "url") is not None:
                method, url_override, body_arg = self._config_call(args)

        if url_override is not None:
            url_node = url_override
        elif 0 <= url_arg < len(args):
            url_node = args[url_arg]
        else:
            return

        for raw in self._url_candidates(url_node):
            self.record_call(callee, raw, method, args, body_arg)

    def _record_builder_appends(self, callee, args: list) -> None:
        parts = self.member_parts(callee)
        if not parts or parts[1] != "append" or not args:
            return
        obj = self.unwrap(parts[0])
        if obj is None or obj.type != Kind.IDENTIFIER:
            return
        name = self.text(obj)
        if not self.lookup(self.builders, name):
            return
        key_node = self.unwrap(args[0])
        if key_node is None or key_node.type != Kind.STRING:
            return  # a computed key is a runtime decision, not a field name
        value = args[1] if len(args) > 1 else None
        self.record_append(name, decode_js_string(self.text(key_node)), value)

    def _config_call(self, args: list):
        """Interpret a ``{url, method, data, params}``-style config call.

        Returns ``(method, url_node_or_None, body_selector)``. The URL is
        returned as a *node* because it lives inside the config object, not in
        an argument slot.
        """
        if not args:
            return "", None, BODY_CONFIG_PARAMS_DATA
        first = self.unwrap(args[0])
        if first is None or first.type != Kind.OBJECT:
            return "", None, BODY_CONFIG_PARAMS_DATA
        method = ""
        for key in ("method", "type"):
            value = self.unwrap(self.object_value(first, key))
            if value is not None and value.type == Kind.STRING:
                method = decode_js_string(self.text(value)).upper()
                break
        url_node = None
        for key in ("url", "path", "uri", "action"):
            url_node = self.object_value(first, key)
            if url_node is not None:
                break
        return method, url_node, BODY_CONFIG_PARAMS_DATA

    def _options_method(self, node) -> str:
        node = self.unwrap(node)
        if node is None or node.type != Kind.OBJECT:
            return ""
        for key in ("method", "type"):
            value = self.unwrap(self.object_value(node, key))
            if value is not None and value.type == Kind.STRING:
                verb = decode_js_string(self.text(value)).upper()
                if verb in _HTTP_VERBS:
                    return verb
        return ""

    def _url_candidates(self, node) -> list[str]:
        """All plausible static values of one URL expression.

        A conditional URL yields both branches; they are reported separately so
        neither endpoint is lost.
        """
        node = self.unwrap(node)
        if node is None:
            return []
        if node.type == Kind.CONDITIONAL_EXPRESSION:
            out: list[str] = []
            for field_name in ("consequence", "alternative"):
                for value in self._url_candidates(self.field(node, field_name)):
                    if value not in out:
                        out.append(value)
            return out
        value = self.static_string(node)
        return [value] if value else []


def constructor_name(node) -> str:
    """The constructor of a ``new_expression`` (``new URL(...)`` -> ``URL``)."""
    if node is None:
        return ""
    target = node.child_by_field_name("constructor")
    if target is None:
        children = node.named_children
        target = children[0] if children else None
    return _node_label(target)


def _node_label(node) -> str:
    """Dotted label for an identifier or member expression node."""
    if node is None:
        return ""
    if node.type == Kind.IDENTIFIER:
        return node.text.decode("utf-8", "replace")
    if node.type == Kind.MEMBER_EXPRESSION:
        obj = _node_label(node.child_by_field_name("object"))
        prop = _node_label(node.child_by_field_name("property"))
        return f"{obj}.{prop}" if obj and prop else (obj or prop)
    return ""


def _dedupe_params(params: list) -> list[Param]:
    seen: set[str] = set()
    out: list[Param] = []
    for param in params:
        if not param.key or param.key in seen:
            continue
        seen.add(param.key)
        out.append(param)
    return out


def _dedupe_calls(calls: list) -> list[ApiCall]:
    calls.sort(key=lambda call: (call.line, call.raw))
    seen: set[str] = set()
    out: list[ApiCall] = []
    for call in calls:
        if not call.raw or call.dedup_key() in seen:
            continue
        seen.add(call.dedup_key())
        out.append(call)
    return out


def analyze_js(source_url: str, body: str, max_bytes: int = 8 * 1024 * 1024) -> JSResult:
    """Recover API call sites, request specs and base paths from one script."""
    result = JSResult()
    if not body:
        return result

    walker = Walker(body, max_bytes=max_bytes)
    if not walker.available:
        return result

    for call in walker.run():
        spec = call.spec
        result.candidates.append(Candidate(
            raw=call.raw,
            kind="endpoint",
            source_url=source_url,
            method=call.method,
            evidence=call.evidence,
            line=call.line,
            column=call.column,
            context_lines=call.context,
            body_params=spec.param_keys() if spec else [],
            spec=spec,
            source="ast",
        ))

    result.base_paths = _base_paths_from(walker)
    return result


def _base_paths_from(walker: Walker):
    """Interface prefixes declared through an axios instance or a named constant."""
    from .basepath import normalize_base_path
    from .types import BasePathCandidate

    out: list[BasePathCandidate] = []
    seen: set[str] = set()

    for (_scope, _name), base in walker.instance_base.items():
        normalized = normalize_base_path(base)
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(BasePathCandidate(raw=normalized, kind="ast"))

    for (_scope, _name), value in walker.constants.items():
        if not value.startswith(("/api", "/v", "http")):
            continue
        normalized = normalize_base_path(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(BasePathCandidate(raw=normalized, kind="ast"))
    return out
