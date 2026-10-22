"""Tree-sitter AST extraction of parameter names by code shape.

A parameter's *name* is usually visible even when its value is not:
``const {a, b} = res.data`` and ``axios.post(url, {userId})`` both tell a
fuzzer which fields an interface expects. This module recovers those names and
tags each with the code shape it came from.

Scenarios (stable identifiers): ``object_property``, ``destructuring``,
``nested_destructuring``, ``function_param``, ``variable``, ``api_request``,
``url_query``, ``config_object``, ``route_param``.
"""

from __future__ import annotations

import re

from ..model import (
    SCENARIO_API_REQUEST,
    SCENARIO_CONFIG_OBJECT,
    SCENARIO_DESTRUCTURING,
    SCENARIO_FUNCTION_PARAM,
    SCENARIO_NESTED_DESTRUCTURING,
    SCENARIO_OBJECT_PROPERTY,
    SCENARIO_ROUTE_PARAM,
    SCENARIO_URL_QUERY,
    SCENARIO_VARIABLE,
    ParamHit,
    route_param_names,
)
from ..utils import (
    CONTEXT_SPAN_LINES,
    decode_js_string,
    extract_context,
    line_column,
    line_starts,
)
from .jsparser import Kind, parse_javascript
from .types import JSResult

# Config keys whose object literal configures the client, not a payload.
_CONFIG_KEYS = frozenset({
    "baseurl", "base_url", "timeout", "headers", "withcredentials",
    "responsetype", "adapter", "transformrequest", "transformresponse",
    "maxredirects", "validatestatus", "auth", "params", "data", "body",
    "json", "method", "url",
})

# Only short, plausible field names are worth reporting; anything else is an
# i18n label or a minified internal.
_FIELD_NAME_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{1,48}$")

# Names so generic they say nothing about the interface.
_COMMON_NAMES = frozenset({
    "e", "t", "n", "r", "i", "o", "a", "s", "c", "u", "l", "d", "p", "f", "m",
    "data", "res", "resp", "response", "result", "results", "list", "obj",
    "options", "option", "params", "param", "config", "cb", "callback", "next",
    "err", "error", "value", "val", "item", "items", "index", "idx",
    "ctx", "context", "state", "store", "props", "self", "args",
})

# Shapes where even a short name carries meaning: it was destructured out of a
# response, listed in a payload, or bound as a route placeholder.
_MEANINGFUL_SHAPES = frozenset({
    SCENARIO_DESTRUCTURING, SCENARIO_NESTED_DESTRUCTURING,
    SCENARIO_API_REQUEST, SCENARIO_ROUTE_PARAM, SCENARIO_FUNCTION_PARAM,
})


class ParamCollector:
    """Single walk collecting parameter names from every recognized shape."""

    def __init__(self, source: str, source_url: str = "",
                 max_bytes: int = 8 * 1024 * 1024):
        self.source = source
        self.source_url = source_url
        self.tree = parse_javascript(source, max_bytes=max_bytes)
        self.hits: list[ParamHit] = []
        self._starts = line_starts(source)
        self._seen: set[tuple[str, str, int]] = set()

    @property
    def available(self) -> bool:
        return self.tree is not None

    # -- helpers --------------------------------------------------------

    def text(self, node) -> str:
        if node is None:
            return ""
        return self.source[node.start_byte:node.end_byte]

    def field(self, node, name: str):
        return node.child_by_field_name(name) if node is not None else None

    def unwrap(self, node):
        while node is not None and node.type in Kind.TRANSPARENT_KINDS:
            children = node.named_children
            if not children:
                break
            node = children[0]
        return node

    def children(self, node) -> list:
        return list(node.named_children) if node is not None else []

    def property_name(self, node) -> str:
        node = self.unwrap(node)
        if node is None:
            return ""
        if node.type == Kind.STRING:
            return decode_js_string(self.text(node))
        if node.type in Kind.KEY_KINDS:
            return self.text(node)
        return ""

    def pairs(self, node) -> list:
        """``key -> value node`` for every pair of an object literal."""
        node = self.unwrap(node)
        if node is None or node.type not in (Kind.OBJECT, Kind.OBJECT_PATTERN):
            return []
        out = []
        for pair in node.named_children:
            if pair.type != Kind.PAIR:
                continue
            key = self.property_name(self.field(pair, "key"))
            if key:
                out.append((key, self.field(pair, "value")))
        return out

    def add(self, name: str, scenario: str, value: str, evidence: str, node) -> None:
        """Record one parameter hit, skipping names that say nothing."""
        name = (name or "").strip()
        if not name or not _FIELD_NAME_RE.match(name):
            return
        if name in _COMMON_NAMES and scenario not in _MEANINGFUL_SHAPES:
            return
        line, column = line_column(self.source, node.start_byte, self._starts)
        key = (name, scenario, line)
        if key in self._seen:
            return
        self._seen.add(key)
        self.hits.append(ParamHit(
            name=name,
            scenario=scenario,
            value=value or "",
            evidence=evidence,
            source_url=self.source_url,
            line=line,
            column=column,
            context_lines=extract_context(self.source, node.start_byte,
                                          CONTEXT_SPAN_LINES, name),
        ))

    # -- the walk -------------------------------------------------------

    def run(self) -> list[ParamHit]:
        if self.tree is None:
            return []
        self._walk(self.tree.root_node)
        return self.hits

    def _walk(self, node) -> None:
        if node is None:
            return
        node_type = node.type

        if node_type == Kind.OBJECT_PATTERN:
            self._object_pattern(node, nested=False)
            return
        if node_type == Kind.ARRAY_PATTERN:
            for child in self.children(node):
                self._pattern(child, SCENARIO_DESTRUCTURING, nested=False)
            return
        if node_type in Kind.FUNCTION_KINDS:
            self._formal_parameters(self.field(node, "parameters"))
            for child in self.children(node):
                self._walk(child)
            return
        if node_type == Kind.VARIABLE_DECLARATOR:
            self._variable_declarator(node)
            return
        if node_type == Kind.CALL_EXPRESSION:
            self._call(node)
        elif node_type == Kind.STRING:
            self._string(node)
        elif node_type == Kind.OBJECT:
            self._object_literal(node)

        for child in self.children(node):
            self._walk(child)

    # -- shapes ---------------------------------------------------------

    def _formal_parameters(self, params) -> None:
        """``function getUser(userId, token)`` -> function_param hits."""
        for child in self.children(params):
            self._pattern(child, SCENARIO_FUNCTION_PARAM, nested=False)

    def _pattern(self, node, scenario: str, nested: bool) -> None:
        node = self.unwrap(node)
        if node is None:
            return
        if node.type == Kind.IDENTIFIER:
            self.add(self.text(node), scenario, "", "", node)
        elif node.type == Kind.ASSIGNMENT_PATTERN:
            # ``function f(userId = 1)`` — the default value is still a field.
            self._pattern(self.field(node, "left"), scenario, nested)
        elif node.type in (Kind.REST_PATTERN, "rest_pattern"):
            self._pattern(self.field(node, "pattern"), scenario, nested)
        elif node.type == Kind.OBJECT_PATTERN:
            self._object_pattern(node, nested=True)
        elif node.type == Kind.ARRAY_PATTERN:
            for child in self.children(node):
                self._pattern(child, scenario, nested)
        elif node.type in Kind.FUNCTION_KINDS:
            self._walk(node)

    def _object_pattern(self, node, nested: bool) -> None:
        """``const {a, b} = x`` and ``const {profile: {email}} = data``."""
        for child in self.children(node):
            child = self.unwrap(child)
            if child is None:
                continue
            if child.type == Kind.PAIR:
                key = self.property_name(self.field(child, "key"))
                value = self.unwrap(self.field(child, "value"))
                if nested and value is not None and value.type in (
                    Kind.OBJECT_PATTERN, Kind.ARRAY_PATTERN
                ):
                    # {profile: {email}} — report the leaf, not the container.
                    self._pattern(value, SCENARIO_NESTED_DESTRUCTURING, nested=True)
                    continue
                self.add(key, SCENARIO_NESTED_DESTRUCTURING if nested
                         else SCENARIO_DESTRUCTURING, "", "", child)
                continue
            if child.type == "shorthand_property_identifier_pattern":
                self.add(self.text(child), SCENARIO_DESTRUCTURING, "", "", child)
                continue
            if child.type in (Kind.REST_PATTERN, "rest_pattern"):
                self._pattern(child, SCENARIO_DESTRUCTURING, nested)
                continue
            if child.type in Kind.FUNCTION_KINDS:
                self._walk(child)
                continue
            self._pattern(child, SCENARIO_DESTRUCTURING, nested)

    def _variable_declarator(self, node) -> None:
        """Classify ``const x = <pattern|literal|object>``."""
        name_node = self.unwrap(self.field(node, "name"))
        value = self.unwrap(self.field(node, "value"))
        if name_node is None or name_node.type != Kind.IDENTIFIER:
            return
        if value is None:
            return
        name = self.text(name_node)

        if value.type == Kind.STRING:
            self.add(name, SCENARIO_VARIABLE, decode_js_string(self.text(value)),
                     "literal", name_node)
        elif value.type == Kind.TEMPLATE_STRING:
            self.add(name, SCENARIO_VARIABLE, "", "constant", name_node)
        elif value.type == Kind.OBJECT:
            if self._is_config(value):
                self._config_object(value)
            else:
                for key, _value in self.pairs(value):
                    self.add(key, SCENARIO_OBJECT_PROPERTY, "", "inferred", value)
        elif value.type == Kind.ARRAY:
            for element in self.children(value):
                element = self.unwrap(element)
                if element is not None and element.type == Kind.OBJECT:
                    for key, _v in self.pairs(element):
                        self.add(key, SCENARIO_OBJECT_PROPERTY, "", "inferred", element)

    def _object_literal(self, node) -> None:
        """An object literal sitting in a call's argument list is a payload."""
        parent = node.parent
        if parent is None or parent.type != Kind.ARGUMENTS:
            return
        call = parent.parent
        if call is None or call.type != Kind.CALL_EXPRESSION:
            return
        if self._is_config(node):
            self._config_object(node)
            return
        for key, _value in self.pairs(node):
            self.add(key, SCENARIO_API_REQUEST, "", "inferred", node)

    def _config_object(self, node) -> None:
        for key, _value in self.pairs(node):
            self.add(key, SCENARIO_CONFIG_OBJECT, "", "inferred", node)

    def _call(self, node) -> None:
        """Payload shapes: ``.post(url, {a})`` and ``fetch(url, {body: {a}})``."""
        args = [child for child in self.children(node) if child.type != "comment"]
        for index, arg in enumerate(args):
            arg = self.unwrap(arg)
            if arg is None or arg.type != Kind.OBJECT:
                continue
            # A first-argument object carrying url/method is a request config,
            # not a payload.
            if index == 0 and any(
                self.property_name(self.field(pair, "key")) in ("url", "method", "type")
                for pair in arg.named_children if pair.type == Kind.PAIR
            ):
                self._config_object(arg)
                continue
            if self._is_config(arg):
                self._config_object(arg)
                continue
            for key, _value in self.pairs(arg):
                self.add(key, SCENARIO_API_REQUEST, "", "inferred", arg)

    def _string(self, node) -> None:
        """URL-shaped strings contribute query names and route placeholders."""
        value = decode_js_string(self.text(node))
        if not value or len(value) > 1024:
            return
        if "?" not in value and ":" not in value and "{" not in value:
            return
        for name in route_param_names(value):
            self.add(name, SCENARIO_ROUTE_PARAM, "", "inferred", node)
        query = value.split("?", 1)[1] if "?" in value else ""
        query = query.split("#", 1)[0]
        for pair in query.split("&"):
            key = pair.split("=", 1)[0].strip()
            if key and _FIELD_NAME_RE.match(key):
                self.add(key, SCENARIO_URL_QUERY, "", "inferred", node)

    # -- classification -------------------------------------------------

    def _is_config(self, obj) -> bool:
        """Whether an object literal configures a client rather than carrying data."""
        keys = [name.lower() for name, _value in self.pairs(obj)]
        if not keys:
            return False
        config_hits = sum(1 for key in keys if key in _CONFIG_KEYS)
        return config_hits > 0 and config_hits * 2 >= len(keys)


def params_from_ast(source_url: str, body: str,
                    max_bytes: int = 8 * 1024 * 1024) -> list[ParamHit]:
    """Recover parameter names from one JavaScript body."""
    if not body:
        return []
    collector = ParamCollector(body, source_url=source_url, max_bytes=max_bytes)
    if not collector.available:
        return []
    return collector.run()


def params_from_ast_result(source_url: str, body: str,
                           max_bytes: int = 8 * 1024 * 1024) -> JSResult:
    """Same as :func:`params_from_ast` but shaped for the pipeline."""
    result = JSResult()
    result.params = params_from_ast(source_url, body, max_bytes=max_bytes)
    return result
