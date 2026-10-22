"""Webpack chunk discovery: public path, chunk maps and inline runtimes.

Two independent passes are unioned: the regex pass copes with mangled or
truncated runtimes the parser chokes on, and the AST pass (:mod:`webpackast`)
reads template strings, subscript property access and ``concat``/``join``
chains the regex cannot express.
"""

from __future__ import annotations

import re

from ..utils import ensure_directory_url, resolve_url
from .types import Candidate, Kind

# __webpack_require__.p / r.p — the public path chunks are served from.
WEBPACK_PUBLIC_PATH = re.compile(
    r"""(?:__webpack_require__|[A-Za-z_$][\w$]*)\.p\s*=\s*["']([^"']*)["']"""
)
WEBPACK_EVIDENCE = re.compile(
    r"""(?i)(?:(?:__webpack_require__|[A-Za-z_$][\w$]*)\.(?:p|u)\s*=|webpackchunk)"""
)
# The .u loader: __webpack_require__.u = e => "js/" + e + "." + {...}[e] + ".js"
WEBPACK_U_FUNCTION = re.compile(
    r"""(?s)(?:__webpack_require__|[A-Za-z_$][\w$]*)\.u\s*=\s*\(?\s*"""
    r"""([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*([^;]*)"""
)
WEBPACK_OBJECT = re.compile(
    r"""(?s)\{(?:\s*["']?[A-Za-z0-9_-]+["']?\s*:\s*["'][^"']+["']\s*,?)+\s*\}"""
)
WEBPACK_NAMED_OBJECT = re.compile(
    r"""(?s)(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*"""
    r"""(\{(?:\s*["']?[A-Za-z0-9_-]+["']?\s*:\s*["'][^"']+["']\s*,?)+\s*\})"""
)
WEBPACK_PAIR = re.compile(r"""["']?([A-Za-z0-9_-]+)["']?\s*:\s*["']([^"']+)["']""")
# webpack inlines the chunk-filename expression into the HTML entry: a literal
# directory prefix, a chunk id, a dot, a {name: hash} map indexed by that id and
# ".js". Vue CLI writes it as a plain function rather than
# __webpack_require__.u, so the .u matcher never sees it.
WEBPACK_INLINE_CHUNK = re.compile(
    r"""(?s)["']([^"']*/)["'][^:;]{1,80}\+\s*["']\.["']\s*\+\s*"""
    r"""(\{(?:\s*["']?[A-Za-z0-9_-]+["']?\s*:\s*["'][^"']+["']\s*,?)+\})\s*\["""
)
# Every token shape webpack uses for chunk hashes: hex, base64url fragments and
# short content hashes. A hex-only check discards whole chunk maps whenever one
# hash carries a letter past "f" or a "-" / "_".
CHUNK_HASH_TOKEN = re.compile(r"^[A-Za-z0-9_-]{2,}$")


def from_webpack(source: str, body: str, limit: int) -> list[Candidate]:
    """Resolve bounded chunk URLs from a common webpack runtime."""
    if not source or limit <= 0:
        return []
    inline_chunks = WEBPACK_INLINE_CHUNK.findall(body)
    if not WEBPACK_EVIDENCE.search(body) and not inline_chunks:
        return []

    public_base = _resolve_public_path(source, body)
    maps = _chunk_maps(body)

    filenames: list[str] = []
    consumed: set[int] = set()
    _pair_name_hash_maps(maps, filenames, consumed)
    _single_maps(maps, body, filenames, consumed)

    # Inline runtimes name every chunk in one expression, so the map is already
    # complete: emit <prefix><name>.<hash>.js for each entry.
    for prefix, pairs in inline_chunks:
        for chunk_id, chunk_hash in WEBPACK_PAIR.findall(pairs):
            filenames.append(f"{prefix}{chunk_id}.{chunk_hash}.js")

    # Union in the AST pass filenames; the resolve loop deduplicates.
    from .webpackast import webpack_ast_extract

    _ast_public_path, ast_filenames = webpack_ast_extract(body)
    filenames.extend(ast_filenames)

    return _resolve_all(public_base, source, filenames, limit)


def _resolve_public_path(source: str, body: str) -> str:
    """Where chunks live: an explicit ``.p``, else the runtime's own directory."""
    from .webpackast import webpack_ast_extract

    match = WEBPACK_PUBLIC_PATH.search(body)
    if match:
        resolved = resolve_url(source, match.group(1))
        if resolved:
            return ensure_directory_url(resolved)
    ast_path, _ = webpack_ast_extract(body)
    if ast_path:
        resolved = resolve_url(source, ast_path)
        if resolved:
            return ensure_directory_url(resolved)
    return ensure_directory_url(resolve_url(source, ".") or source)


def _chunk_maps(body: str) -> list[dict]:
    """Every ``{id: "value"}`` object that a webpack runtime indexes."""
    out: list[dict] = []
    loader = WEBPACK_U_FUNCTION.search(body)
    if loader:
        for blob in WEBPACK_OBJECT.findall(loader.group(2)):
            parsed = _parse_pairs(blob)
            if parsed:
                out.append(parsed)
        if out:
            return out

    for name, blob in WEBPACK_NAMED_OBJECT.findall(body):
        if _referenced_by_chunk_expression(body, name):
            parsed = _parse_pairs(blob)
            if parsed:
                out.append(parsed)
    return out


def _parse_pairs(blob: str) -> dict:
    return {chunk_id: value for chunk_id, value in WEBPACK_PAIR.findall(blob)}


def _pair_name_hash_maps(maps, filenames, consumed) -> None:
    """webpack 5 keeps the name map and the hash map separately; pair them up."""
    for i in range(len(maps)):
        for j in range(i + 1, len(maps)):
            if not _same_keys(maps[i], maps[j]):
                continue
            names, hashes = maps[i], maps[j]
            if _hash_score(names) > _hash_score(hashes):
                names, hashes = hashes, names
            if _hash_score(hashes) < 1 or _hash_score(names) >= _hash_score(hashes):
                # Ambiguous pair: neither side is clearly the hash map.
                continue
            for chunk_id in sorted(names):
                filenames.append(f"{names[chunk_id]}.{hashes[chunk_id]}.js")
            consumed.update({i, j})
            break


def _single_maps(maps, body, filenames, consumed) -> None:
    """A lone map is either ``name.hash`` or a bare filename per chunk id."""
    id_hash_template = _uses_id_hash_template(body)
    for index, values in enumerate(maps):
        if index in consumed:
            continue
        for chunk_id in sorted(values):
            value = values[chunk_id]
            if id_hash_template and _hash_score(values) >= 1:
                value = f"{chunk_id}.{value}"
            if not value.lower().endswith(".js"):
                value += ".js"
            filenames.append(value)


def _referenced_by_chunk_expression(body: str, name: str) -> bool:
    """Whether ``name[...]`` is indexed inside a statement that also holds ".js"."""
    start_from = 0
    while start_from < len(body):
        relative = body.find(name, start_from)
        if relative < 0:
            return False
        start = start_from + relative
        after = start + len(name)
        if start > 0 and _is_identifier_byte(body[start - 1]):
            start_from = after
            continue
        cursor = after
        while cursor < len(body) and body[cursor] in " \t\r\n":
            cursor += 1
        if cursor >= len(body) or body[cursor] != "[":
            start_from = after
            continue
        statement_start = body.rfind(";", 0, start) + 1
        statement_end = len(body)
        relative_end = body.find(";", cursor)
        if relative_end >= 0:
            statement_end = cursor + relative_end
        if statement_end - statement_start <= 2000 and ".js" in body[statement_start:statement_end]:
            return True
        start_from = after
    return False


def _is_identifier_byte(char: str) -> bool:
    return char == "_" or char == "$" or char.isalnum()


def _uses_id_hash_template(body: str) -> bool:
    loader = WEBPACK_U_FUNCTION.search(body)
    if not loader:
        return False
    identifier = re.escape(loader.group(1))
    return bool(re.search(identifier + r"""\s*\+\s*["']\.["']\s*\+\s*\{""", loader.group(2)))


def _same_keys(left: dict, right: dict) -> bool:
    return len(left) == len(right) and set(left) == set(right)


def _hash_score(values: dict) -> float:
    """Fraction of values that look like opaque content hashes.

    Chunk names are readable words ("users") while chunk hashes are opaque and
    almost always carry a digit; scoring rather than a boolean keeps the
    two-map form unambiguous and still accepts base64url hashes.
    """
    if not values:
        return 0.0
    scored = sum(
        1 for value in values.values()
        if CHUNK_HASH_TOKEN.match(value) and any(c.isdigit() for c in value)
    )
    return scored / len(values)


def _resolve_all(public_base, source, filenames, limit) -> list[Candidate]:
    out: list[Candidate] = []
    seen: set[str] = set()
    for filename in filenames:
        if len(out) >= limit:
            break
        resolved = resolve_url(public_base, filename)
        if not resolved or resolved in seen:
            continue
        seen.add(resolved)
        out.append(Candidate(raw=resolved, kind=Kind.CHUNK, source_url=source,
                             source="regex"))
    return out
