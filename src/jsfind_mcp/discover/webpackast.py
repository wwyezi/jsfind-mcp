"""Webpack runtime AST extraction: public path and chunk filename templates.

The regex pass in :mod:`webpack` cannot read the four shapes modern runtimes use:

* a plain function runtime — ``r.u = e => "static/js/" + e + "." + {...}[e] + ".js"``
* a template literal — ``__webpack_require__.u = e => `${e}.${{...}[e]}.js```
* a subscript property — ``r["u"] = e => "js/" + e + "." + {3: "x9y8"}[e] + ".js"``
* a ``concat``/``join`` chain instead of ``+``

Each is read here by walking the assignment rather than matching text, and the
result is unioned with the regex pass because the two have disjoint blind spots.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..utils import decode_js_string
from .jsparser import Kind, parse_javascript

# A runtime body larger than this is not worth parsing: the chunk map it would
# carry is small, and the parse cost dominates.
MAX_AST_WEBPACK_BYTES = 4 * 1024 * 1024

_MAX_EVAL_DEPTH = 8


@dataclass
class Segment:
    """One piece of a chunk filename template."""

    kind: str            # literal | param | map
    literal: str = ""
    pairs: dict = field(default_factory=dict)


@dataclass
class WebpackRuntime:
    """A recovered ``.u`` filename template plus its ``.p`` public path."""

    segments: list[Segment] = field(default_factory=list)
    public_path: str = ""
    chunk_ids: list[str] = field(default_factory=list)

    def has_param(self) -> bool:
        return any(segment.kind == "param" for segment in self.segments)

    def filenames(self) -> list[str]:
        """Expand the template into one filename per known chunk id."""
        out: list[str] = []
        for chunk_id in self.chunk_ids:
            name = self._render(chunk_id)
            if name and name not in out:
                out.append(name)
        # A map indexed by the chunk id enumerates itself when the runtime never
        # revealed the ids: iterate the map keys instead.
        if not out:
            for segment in self.segments:
                if segment.kind == "map":
                    for chunk_id in sorted(segment.pairs):
                        name = self._render(chunk_id)
                        if name and name not in out:
                            out.append(name)
        return out

    def pair_maps(self) -> tuple[dict, dict]:
        """Split the maps into (name map, hash map) by hash-likeness."""
        maps = [segment.pairs for segment in self.segments if segment.kind == "map"]
        if not maps:
            return {}, {}
        if len(maps) < 2:
            return {}, maps[0]
        first, second = maps[0], maps[1]
        if set(first) != set(second):
            return {}, first
        if _hash_score(second) > _hash_score(first):
            return first, second
        return second, first

    def _render(self, chunk_id: str) -> str:
        pieces: list[str] = []
        for segment in self.segments:
            if segment.kind == "literal":
                pieces.append(segment.literal)
            elif segment.kind == "param":
                pieces.append(chunk_id)
            else:
                pieces.append(segment.pairs.get(chunk_id, ""))
        name = "".join(pieces)
        return name if name.lower().endswith(".js") else name + ".js"


def webpack_ast_extract(body: str) -> tuple[str, list[str]]:
    """Return ``(public_path, chunk_filenames)`` from one webpack runtime."""
    tree = parse_javascript(body, max_bytes=MAX_AST_WEBPACK_BYTES)
    if tree is None:
        return "", []

    finder = RuntimeFinder(body)
    finder.walk(tree.root_node)
    runtime = finder.runtime
    if runtime is None:
        return finder.public_path, []

    if not runtime.chunk_ids:
        names, hashes = runtime.pair_maps()
        for chunk_id, name in sorted(names.items()):
            digest = hashes.get(chunk_id, "")
            runtime.chunk_ids.append(f"{name}.{digest}" if digest else chunk_id)
    return runtime.public_path or finder.public_path, runtime.filenames()


class RuntimeFinder:
    """Walks a bundle looking for the ``.p`` / ``.u`` webpack runtime."""

    def __init__(self, source: str):
        self.source = source
        self.runtime: WebpackRuntime | None = None
        self.public_path = ""
        self.lazy_ids: list[str] = []

    # -- helpers --------------------------------------------------------

    def text(self, node) -> str:
        if node is None:
            return ""
        return self.source[node.start_byte:node.end_byte]

    def unwrap(self, node):
        while node is not None and node.type in Kind.TRANSPARENT_KINDS:
            children = node.named_children
            if not children:
                break
            node = children[0]
        return node

    def children(self, node) -> list:
        return list(node.named_children) if node is not None else []

    def member_parts(self, node) -> tuple[object, str] | None:
        node = self.unwrap(node)
        if node is None or node.type != Kind.MEMBER_EXPRESSION:
            return None
        obj = self.unwrap(node.child_by_field_name("object"))
        prop = node.child_by_field_name("property")
        if obj is None or prop is None:
            return None
        if prop.type not in (Kind.PROPERTY_IDENTIFIER, Kind.IDENTIFIER, Kind.STRING):
            return None
        return obj, decode_js_string(self.text(prop))

    # -- walk -----------------------------------------------------------

    def walk(self, node) -> None:
        if node is None:
            return
        if node.type == Kind.ASSIGNMENT_EXPRESSION:
            self.visit_assignment(node)
            return
        if node.type == Kind.CALL_EXPRESSION:
            self.visit_lazy_load(node)
        # Always descend: a webpack runtime is usually wrapped in an IIFE
        # (``(function(){ var r = {}; r.p = "..."; })()``), so stopping at the
        # outer call would miss every runtime assignment inside it.
        for child in self.children(node):
            self.walk(child)

    def visit_assignment(self, node) -> None:
        left = self.unwrap(node.child_by_field_name("left"))
        right = self.unwrap(node.child_by_field_name("right"))
        prop = self.assigned_property(left)
        if prop == "p":
            value = self.static_string(right)
            if value:
                self.public_path = value
            self.walk(right)
        elif prop == "u":
            runtime = self.evaluate_runtime(right)
            if runtime is not None:
                runtime.public_path = self.public_path
                runtime.chunk_ids.extend(self.lazy_ids)
                self.runtime = runtime
            else:
                self.walk(right)
        else:
            self.walk(right)

    def visit_lazy_load(self, node) -> None:
        """``__webpack_require__.e(11)`` names a chunk the runtime will build."""
        callee = self.unwrap(node.child_by_field_name("function"))
        parts = self.member_parts(callee)
        if not parts or parts[1] != "e":
            return
        for child in node.named_children:
            if child.type in (Kind.STRING, Kind.NUMBER):
                self.lazy_ids.append(decode_js_string(self.text(child)))
                return

    def assigned_property(self, left) -> str:
        """``r.u`` and ``r["u"]`` both name the same runtime slot."""
        if left is None:
            return ""
        if left.type == Kind.SUBSCRIPT_EXPRESSION:
            index = self.unwrap(left.child_by_field_name("index"))
            if index is not None and index.type == Kind.STRING:
                return decode_js_string(self.text(index))
            return ""
        if left.type == Kind.MEMBER_EXPRESSION:
            return self.text(left.child_by_field_name("property"))
        return ""

    # -- evaluation -----------------------------------------------------

    def evaluate_runtime(self, node) -> WebpackRuntime | None:
        fn = self.unwrap(node)
        if fn is None or fn.type not in (
            Kind.ARROW_FUNCTION, Kind.FUNCTION_EXPRESSION,
            Kind.FUNCTION, Kind.GENERATOR_FUNCTION,
        ):
            return None
        expression = self._returned_expression(fn.child_by_field_name("body"))
        if expression is None:
            return None
        segments = self.evaluate(expression)
        if not segments:
            return None
        # Without an indexed map the template cannot enumerate its own chunks;
        # the regex pass handles static name lists.
        if not any(segment.kind == "map" for segment in segments):
            return None
        return WebpackRuntime(segments=segments)

    def _returned_expression(self, body):
        if body is None:
            return None
        if body.type != "statement_block":
            return body
        for child in reversed(self.children(body)):
            if child.type == "return_statement":
                named = self.children(child)
                return self.unwrap(named[0]) if named else None
        return None

    def evaluate(self, node, depth: int = 0) -> list[Segment]:
        """Flatten a filename expression into literal/param/map segments."""
        if node is None or depth > _MAX_EVAL_DEPTH:
            return []
        node = self.unwrap(node)
        node_type = node.type

        if node_type == Kind.STRING:
            return [Segment(kind="literal", literal=decode_js_string(self.text(node)))]
        if node_type == Kind.IDENTIFIER:
            return [Segment(kind="param", literal=self.text(node))]
        if node_type == Kind.TEMPLATE_STRING:
            segments: list[Segment] = []
            for child in node.named_children:
                if child.type == Kind.TEMPLATE_SUBSTITUTION:
                    inner = self.children(child)
                    segments.extend(self.evaluate(inner[0] if inner else None,
                                                  depth + 1))
                else:
                    segments.append(Segment(kind="literal",
                                            literal=decode_js_string(self.text(child))))
            return segments
        if node_type == Kind.BINARY_EXPRESSION:
            if self.text(node.child_by_field_name("operator")) != "+":
                return []
            return (self.evaluate(node.child_by_field_name("left"), depth + 1)
                    + self.evaluate(node.child_by_field_name("right"), depth + 1))
        if node_type == Kind.SUBSCRIPT_EXPRESSION:
            return self._evaluate_map(node, depth)
        if node_type == Kind.CALL_EXPRESSION:
            return self._evaluate_call(node, depth)
        if node_type == Kind.PARENTHESIZED_EXPRESSION:
            inner = self.children(node)
            return self.evaluate(inner[0] if inner else None, depth + 1)
        return []

    def _evaluate_map(self, node, depth: int) -> list[Segment]:
        """``{1:"m4n5"}[e]`` -> a map segment."""
        obj = self.unwrap(node.child_by_field_name("object"))
        if obj is None or obj.type != Kind.OBJECT:
            return []
        pairs: dict[str, str] = {}
        for pair in obj.named_children:
            if pair.type != Kind.PAIR:
                continue
            key = pair.child_by_field_name("key")
            value = pair.child_by_field_name("value")
            if key is None or value is None:
                continue
            pairs[_literal_or_text(self.text(key), key.type)] = \
                _literal_or_text(self.text(value), value.type)
        return [Segment(kind="map", pairs=pairs)] if pairs else []

    def _evaluate_call(self, node, depth: int) -> list[Segment]:
        callee = self.unwrap(node.child_by_field_name("function"))
        parts = self.member_parts(callee) if callee is not None else None
        if not parts:
            return []
        obj, name = parts
        obj = self.unwrap(obj)
        args = self.children(node.child_by_field_name("arguments"))

        if name == "concat":
            segments = self.evaluate(obj, depth + 1)
            for arg in args:
                segments.extend(self.evaluate(arg, depth + 1))
            return segments

        if name == "join":
            separator = ""
            if args:
                first = self.unwrap(args[0])
                if first is not None and first.type == Kind.STRING:
                    separator = decode_js_string(self.text(first))
            if obj is None or obj.type != Kind.ARRAY:
                return []
            segments = []
            for index, element in enumerate(self.children(obj)):
                if index:
                    segments.append(Segment(kind="literal", literal=separator))
                segments.extend(self.evaluate(element, depth + 1))
            return segments
        return []

    def static_string(self, node) -> str:
        node = self.unwrap(node)
        if node is None:
            return ""
        if node.type == Kind.STRING:
            return decode_js_string(self.text(node))
        if node.type == Kind.TEMPLATE_STRING:
            pieces = []
            for child in node.named_children:
                if child.type == Kind.TEMPLATE_SUBSTITUTION:
                    inner = self.children(child)
                    pieces.append("{" + self.text(inner[0]).strip() + "}" if inner else "{}")
                else:
                    pieces.append(decode_js_string(self.text(child)))
            return "".join(pieces)
        return ""


def _literal_or_text(raw: str, node_type: str) -> str:
    return decode_js_string(raw) if node_type == Kind.STRING else raw


def _hash_score(values: dict) -> float:
    """Fraction of values that look like content hashes rather than names."""
    if not values:
        return 0.0
    scored = sum(
        1 for value in values.values()
        if value and len(value) >= 2 and any(c.isdigit() for c in value)
    )
    return scored / len(values)
