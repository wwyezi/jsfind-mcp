"""JSON response shape extraction.

Only field *names* are kept: response bodies are never persisted, and the names
are what a fuzzer needs to try a field the front end never sent.
"""

from __future__ import annotations

import json
import re

_MAX_DEPTH = 6
_MAX_FIELDS = 500
_MAX_LIST_ITEMS = 20

_IDENTIFIER_KEY = re.compile(r"^[A-Za-z_$][\w$-]*$")

# A JSON body starts with one of these; anything else is not worth parsing.
_JSON_HEAD = set("[{\"-0123456789tfn")


def json_field_names(body: str) -> list[str]:
    """Field names observed anywhere in a JSON response body."""
    if not body:
        return []
    document = _loads(body)
    if document is None:
        return []
    found: list[str] = []
    seen: set[str] = set()

    def walk(node, depth: int) -> None:
        if depth > _MAX_DEPTH or len(found) >= _MAX_FIELDS:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                name = str(key)
                if name not in seen and _IDENTIFIER_KEY.match(name):
                    seen.add(name)
                    found.append(name)
                walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node[:_MAX_LIST_ITEMS]:
                walk(item, depth + 1)

    walk(document, 0)
    return found


def _loads(body: str):
    stripped = body.lstrip()
    if not stripped or stripped[0] not in _JSON_HEAD:
        return None
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        return None
