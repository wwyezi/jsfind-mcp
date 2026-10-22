"""Dynamic JavaScript discovery.

Static rules find the scripts a page *declares*. They miss the ones it *loads
after boot*, which in a modern SPA is most of the application:

* ``import('./views/Foo-a1b2c3.js')`` — route-level code splitting
* ``__vite__mapDeps(['assets/a.js','assets/b.js'], 0)`` — Vite's chunk map
* ``importScripts('./worker.js')`` and ``new Worker(new URL('./w.js', ...))``
* ``import.meta.glob('./modules/*.js')`` — a family, not a file

Every candidate returned here is a **fetchable URL**. Patterns that cannot be
resolved to one — a glob, or a template whose middle is a runtime map — come
back as hints instead, so a consumer learns that code lives there rather than
missing it silently.
"""

from __future__ import annotations

import re

from .types import Candidate, Kind

#: Comments may sit between ``import(`` and its specifier:
#: ``import(/* webpackChunkName: "x" */ './x.js')``. This eats block and line
#: comments so the specifier is reached either way.
_COMMENT = r"(?:\s|/\*[\s\S]*?\*/|//[^\n]*)*"

#: ``import('<literal>')`` — the specifier is a plain string.
IMPORT_LITERAL = re.compile(
    rf"""(?<![A-Za-z0-9_$.])import\s*\(\s*{_COMMENT}(["'`])([^"'`]+)\1"""
)

#: ``import(`./locales/${lang}.js`)`` — foldable to ``./locales/{lang}.js``.
IMPORT_TEMPLATE = re.compile(
    r"""(?<![A-Za-z0-9_$.])import\s*\(\s*(`[^`]*`)\s*\)"""
)

#: Vite's preloader chunk map: every lazily-loaded asset is listed up front.
VITE_MAP_DEPS = re.compile(
    r"""__vite__mapDeps\s*\(\s*\[(?P<items>[^\]]*)\]""", re.S
)
QUOTED = re.compile(r"""["'`]([^"'`]+)["'`]""")

#: ``import.meta.glob('./modules/*.js')``
IMPORT_GLOB = re.compile(
    rf"""import\.meta\.glob(?:Eager)?\s*\(\s*{_COMMENT}(["'`])([^"'`]+)\1"""
)

#: ``new Worker(new URL('./worker.js', import.meta.url))``
WORKER_URL = re.compile(
    r"""new\s+Worker\s*\(\s*new\s+URL\s*\(\s*(["'`])(\.{0,2}/[^"'`]+)\1"""
)
#: ``new Worker('/worker.js')`` — the plain-string form.
WORKER_PLAIN = re.compile(
    r"""new\s+Worker\s*\(\s*(["'`])([^"'`]+)\1"""
)
#: ``importScripts('./a.js')`` — classic workers, including cross-origin.
IMPORT_SCRIPTS = re.compile(
    rf"""importScripts\s*\(\s*{_COMMENT}(["'`])([^"'`]+)\1"""
)

#: Hashed chunk filenames in the Vite/Rollup convention, wherever they appear.
HASHED_CHUNK = re.compile(
    r"""["'](?:\.{0,2}/)?(?:assets|static|chunks)/"""
    r"""[A-Za-z0-9_.\-]*[.\-][A-Fa-f0-9]{6,}\.js["'"]"""
)

#: a webpackChunkName comment names the logical chunk right before the call
_CHUNK_NAME = re.compile(r"""webpackChunkName\s*:\s*["']([^"']+)["']""")
_PLACEHOLDER_NAME = re.compile(r"[^A-Za-z0-9_]+")
_TEMPLATE_HOLE = re.compile(r"\$\{[^}]*\}")

#: a specifier longer than this is not a file reference
_MAX_SPECIFIER = 512

#: hints are capped so one bundle cannot flood the result
_MAX_HINTS = 40


def from_dynamic(source_url: str, body: str, limit: int = 500,
                 ) -> tuple[list[Candidate], list[str]]:
    """Recover dynamically loaded scripts from one script body.

    Returns ``(candidates, hints)``: candidates are fetchable URLs, hints
    describe dynamic code that exists but has no single resolvable file.
    """
    if not body or limit <= 0:
        return [], []

    candidates: list[Candidate] = []
    hints: list[str] = []
    seen: set[str] = set()

    def add(raw: str, kind: str = Kind.CHUNK, rule: str = "dynamic",
            offset: int = 0) -> None:
        raw = (raw or "").strip()
        if not raw or len(raw) > _MAX_SPECIFIER:
            return
        # A specifier still holding a hole belongs to the template rule, which
        # folds it into a substitutable shape; adding it raw here would report
        # the same reference twice, once wrong.
        if "${" in raw:
            return
        if raw in seen:
            return
        seen.add(raw)
        candidates.append(Candidate(
            raw=raw, kind=kind, source_url=source_url, source="regex",
            rule_id=rule, offset=offset,
        ))

    def hint(text: str) -> None:
        if len(hints) < _MAX_HINTS and text not in hints:
            hints.append(text)

    # 1. Vite's chunk map — the highest-value source, since it names every
    #    lazily-loaded asset in one array.
    for match in VITE_MAP_DEPS.finditer(body):
        for specifier in QUOTED.findall(match.group("items")):
            add(specifier, rule="vite-map-deps")

    # 2. import() with a literal specifier, comments and all.
    for match in IMPORT_LITERAL.finditer(body):
        add(match.group(2), rule="dynamic-import", offset=match.start())
        name = _CHUNK_NAME.search(body[max(0, match.start() - 120):match.start()])
        if name:
            hint(f"webpackChunkName 注释声明的逻辑 chunk: {name.group(1)}")

    # 3. import() with a template literal.
    for match in IMPORT_TEMPLATE.finditer(body):
        folded = fold_template(match.group(1))
        if folded:
            add(folded, rule="dynamic-import-template", offset=match.start())
        else:
            hint(f"模板动态 import 无法静态解析: {match.group(1)[:80]}")

    # 4. Glob families: real code, unknowable filenames.
    for match in IMPORT_GLOB.finditer(body):
        hint(f"import.meta.glob 匹配到一族模块，静态无法枚举: {match.group(2)}")

    # 5. Workers, both the URL and the plain-string form.
    for match in WORKER_URL.finditer(body):
        add(match.group(2), kind=Kind.SCRIPT, rule="worker-url",
            offset=match.start())
    for match in WORKER_PLAIN.finditer(body):
        specifier = match.group(2)
        if not specifier.startswith(("http://", "https://", "/", "./", "../")):
            continue
        add(specifier, kind=Kind.SCRIPT, rule="worker-plain",
            offset=match.start())

    # 6. Classic workers, including cross-origin ones.
    for match in IMPORT_SCRIPTS.finditer(body):
        add(match.group(2), kind=Kind.SCRIPT, rule="import-scripts",
            offset=match.start())

    # 7. Hashed chunk filenames wherever they appear.
    for match in HASHED_CHUNK.finditer(body):
        add(match.group(0).strip("\"'`"), rule="hashed-chunk",
            offset=match.start())

    return candidates[:limit], hints


def fold_template(raw: str) -> str:
    """Render a template literal into a usable path shape.

    ``./locales/${lang}.js`` becomes ``./locales/{lang}.js``: fetchable after
    substitution, and it tells a consumer exactly which variable to vary.

    Validation is deliberately looser than :func:`looks_like_path`: that helper
    rejects ``./x`` because a relative module specifier is not a request target,
    whereas here a relative specifier is exactly what we want. Returns "" when
    the template carries no literal substance.
    """
    inner = raw.strip().strip("`").strip()
    if not inner:
        return ""
    holes = _TEMPLATE_HOLE.findall(inner)
    pieces = _TEMPLATE_HOLE.split(inner)
    folded = ""
    for index, piece in enumerate(pieces):
        folded += piece
        if index < len(pieces) - 1:
            # Keep the variable name: ``./locales/{lang}.js`` tells a consumer
            # exactly what to vary, where ``./locales/{}.js`` does not.
            name = _PLACEHOLDER_NAME.sub("", holes[index])
            folded += "{" + name + "}" if name else "{}"
    if not folded or len(folded) > _MAX_SPECIFIER:
        return ""
    if "://" not in folded:
        # A bare identifier such as ``${view}`` names a module, not a path;
        # a template is only useful when something path-shaped survives.
        stripped = folded.replace("{", "").replace("}", "")
        if "/" not in stripped and "." not in stripped:
            return ""
    # A template made only of holes names no path at all.
    stripped = folded.replace("{", "").replace("}", "")
    if len(stripped) < 2 or stripped in ("./", "/"):
        return ""
    return folded
