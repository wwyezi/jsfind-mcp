"""A big bundle must be analyzed in pieces, not in one hopeless gulp.

A minified SPA bundle runs to tens of megabytes on one line. Extracting over all
of it at once is minutes of CPU — which is why ``jsfind_analyze_file`` on a 23 MB
``index.js`` timed out instead of answering. The pipeline now cuts oversized
bodies at line boundaries and feeds each piece through the same extractors.

    python devtools/chunk_check.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from jsfind_mcp.chunking import (  # noqa: E402
    AST_MAX_BYTES,
    MAX_CHUNK_BYTES,
    is_rejected,
    split_by_lines,
    wants_ast,
)
from jsfind_mcp.analyze import Engine  # noqa: E402
from jsfind_mcp.config import Config  # noqa: E402
from jsfind_mcp.localfile import analyze_local  # noqa: E402

FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


def bundle(count: int) -> str:
    """A minified bundle: one line, ``count`` fetchable endpoints in it.

    The planted secret matches the shipped AWS-key rule exactly
    (``AKIA`` + 16 alphanumerics), so findings are expected from every piece.
    """
    return "var a=1;" + "".join(
        f'function f{i}(){{fetch("/api/v1/resource{i}/detail?token=abc{i}");'
        f'var k="AKIA{"%016d" % i}";return k;}}'
        for i in range(count)
    )


def main() -> int:
    print("chunked extraction\n")

    print("[split_by_lines]")
    small = bundle(10)
    check("small body is one piece", split_by_lines(small) == [small])
    check("small body wants AST", wants_ast(small))
    check("small body is not rejected", not is_rejected(small))

    big = bundle(20000)  # ~1.5 MB
    pieces = split_by_lines(big)
    check("oversized body is split", len(pieces) > 1, f"{len(pieces)} pieces")
    check("no piece exceeds the limit",
          all(len(p.encode("utf-8")) <= MAX_CHUNK_BYTES + 64 for p in pieces),
          str(max(len(p.encode("utf-8")) for p in pieces)))
    joined = "".join(p.lstrip("\n") for p in pieces)
    check("splitting loses no source text", joined == big)

    # A body with real newlines: the padding is what keeps line numbers
    # meaningful across the cut.
    lined = "\n".join(f'var v{i}="secret{i}value{i}";' for i in range(40000))
    lined_pieces = split_by_lines(lined)
    check("multi-line body is split", len(lined_pieces) > 1,
          f"{len(lined_pieces)} pieces")
    check("pieces carry line padding",
          all(p.startswith("\n") for p in lined_pieces[1:]))
    check("padding preserves line numbers",
          sum(p.count("\n") for p in lined_pieces) == lined.count("\n") +
          sum(len(p) - len(p.lstrip("\n")) for p in lined_pieces[1:]))

    print("\n[analyze_local on a 1.5 MB bundle]")
    with tempfile.TemporaryDirectory(prefix="jsfind-chunk-") as tmp:
        path = Path(tmp) / "app.js"
        path.write_text(big, encoding="utf-8")
        config = Config()
        engine = Engine(Engine.default_ruleset())
        started = time.monotonic()
        local = analyze_local(config, engine, [str(path)],
                              base_url="http://target.example/")
        elapsed = time.monotonic() - started
        result = local.result
        print(f"    elapsed={elapsed:.1f}s endpoints={len(result.endpoints)} "
              f"findings={len(result.findings)} params={len(result.params)}")
        check("answers instead of timing out", elapsed < 120, f"{elapsed:.1f}s")
        check("endpoints recovered across chunks", len(result.endpoints) > 50,
              str(len(result.endpoints)))
        check("findings recovered across chunks", len(result.findings) > 20,
              str(len(result.findings)))
        # Dedup must hold: the same endpoint found in two pieces is one entry.
        keys = [(e.method, e.url) for e in result.endpoints]
        check("no duplicate endpoints after merging",
              len(keys) == len(set(keys)), f"{len(keys)} entries")

    print("\n[AST cutoff]")
    huge = bundle(200000)  # ~15 MB
    check("huge body skips AST", not wants_ast(huge),
          f"{len(huge.encode('utf-8'))} bytes vs {AST_MAX_BYTES}")
    check("huge body is still analyzed (regex only)", not is_rejected(huge))

    print("\n[rejection threshold]")
    monster = "x" * (51 * 1024 * 1024)
    check("monster body is refused", is_rejected(monster))

    print("\n" + ("ALL PASS" if not FAILURES
                  else f"{len(FAILURES)} FAILED: {FAILURES}"))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
