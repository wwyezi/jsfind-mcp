"""Tree-sitter parser binding shared by the AST extractors.

The parser is optional: when ``tree-sitter`` and ``tree-sitter-javascript`` are
not installed, :func:`parse_javascript` returns None and every caller falls back
to its regex pass, so the scanner still works — just with less precision.
"""

from __future__ import annotations

import threading
from typing import Any

_LOCK = threading.Lock()
_PARSER: Any = None
_LANGUAGE: Any = None
_LOAD_ERROR: str = ""


def load_parser() -> tuple[Any, Any] | None:
    """Return ``(parser, language)`` once, or None when unavailable."""
    global _PARSER, _LANGUAGE, _LOAD_ERROR
    if _PARSER is not None:
        return _PARSER, _LANGUAGE
    with _LOCK:
        if _PARSER is not None:
            return _PARSER, _LANGUAGE
        try:
            import tree_sitter_javascript  # type: ignore
            from tree_sitter import Language, Parser  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            _LOAD_ERROR = str(exc)
            return None
        try:
            language = Language(tree_sitter_javascript.language())
            parser = Parser(language)
        except Exception as exc:  # noqa: BLE001 - version mismatch surfaces here
            _LOAD_ERROR = f"{type(exc).__name__}: {exc}"
            return None
        _PARSER = parser
        _LANGUAGE = language
        return _PARSER, _LANGUAGE


def parser_error() -> str:
    """Why the parser is unavailable (empty when it loaded fine)."""
    load_parser()
    return _LOAD_ERROR


def parser_available() -> bool:
    return load_parser() is not None


def parse_javascript(source: str, max_bytes: int = 8 * 1024 * 1024) -> Any:
    """Parse JavaScript into a tree, or None when the parser cannot run.

    Oversized bodies are refused rather than truncated: a half-parsed bundle
    produces confidently wrong URLs, which is worse than no AST results at all.
    """
    if not source:
        return None
    if len(source.encode("utf-8", "replace")) > max_bytes:
        return None
    loaded = load_parser()
    if loaded is None:
        return None
    parser, _language = loaded
    try:
        return parser.parse(source.encode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - a parse crash must not abort a scan
        return None


# Node kinds this codebase cares about. Keeping them in one place documents the
# grammar surface the extractors depend on.
class Kind:
    STRING = "string"
    TEMPLATE_STRING = "template_string"
    TEMPLATE_SUBSTITUTION = "template_substitution"
    IDENTIFIER = "identifier"
    PROPERTY_IDENTIFIER = "property_identifier"
    NUMBER = "number"
    OBJECT = "object"
    ARRAY = "array"
    PAIR = "pair"
    CALL_EXPRESSION = "call_expression"
    NEW_EXPRESSION = "new_expression"
    MEMBER_EXPRESSION = "member_expression"
    SUBSCRIPT_EXPRESSION = "subscript_expression"
    ARGUMENTS = "arguments"
    VARIABLE_DECLARATOR = "variable_declarator"
    ASSIGNMENT_EXPRESSION = "assignment_expression"
    BINARY_EXPRESSION = "binary_expression"
    CONDITIONAL_EXPRESSION = "conditional_expression"
    FUNCTION_DECLARATION = "function_declaration"
    FUNCTION_EXPRESSION = "function_expression"
    ARROW_FUNCTION = "arrow_function"
    GENERATOR_FUNCTION = "generator_function"
    GENERATOR_FUNCTION_DECLARATION = "generator_function_declaration"
    FUNCTION = "function"
    OBJECT_PATTERN = "object_pattern"
    ARRAY_PATTERN = "array_pattern"
    ASSIGNMENT_PATTERN = "assignment_pattern"
    LEXICAL_DECLARATION = "lexical_declaration"
    VARIABLE_DECLARATION = "variable_declaration"
    FORMAL_PARAMETERS = "formal_parameters"
    PARENTHESIZED_EXPRESSION = "parenthesized_expression"
    SEQUENCE_EXPRESSION = "sequence_expression"
    PROGRAM = "program"

    #: every node kind that introduces a function scope
    FUNCTION_KINDS = frozenset({
        FUNCTION_DECLARATION, FUNCTION_EXPRESSION, ARROW_FUNCTION,
        GENERATOR_FUNCTION, GENERATOR_FUNCTION_DECLARATION, FUNCTION,
    })

    #: node kinds whose only purpose is to wrap another expression
    TRANSPARENT_KINDS = frozenset({PARENTHESIZED_EXPRESSION})

    #: ``function f(...rest)`` binding form
    REST_PATTERN = "rest_pattern"

    #: object shorthand inside a destructuring pattern
    SHORTHAND_PATTERN = "shorthand_property_identifier_pattern"

    #: identifier-ish key nodes an object property may use
    KEY_KINDS = frozenset({
        IDENTIFIER, PROPERTY_IDENTIFIER, STRING,
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
        "private_property_identifier",
    })
