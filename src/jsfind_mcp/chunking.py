"""Splitting oversized source so the extractors can digest it.

A minified SPA bundle runs to tens of megabytes on one line. Running the regex
passes over all of it at once is minutes of CPU, and running the Tree-sitter
passes over it is worse — which is what made ``jsfind_analyze_file`` on a 23 MB
``index.js`` time out rather than answer.

The remedy is to cut the source into pieces at line boundaries and feed each
piece through the same extractors, then let the caller's existing seen-sets merge
the outcome. Line numbers survive the cut: each piece carries as many newlines
as preceded it in the original, so a finding's line still points at the right
place in the whole file.

Three thresholds, all overridable from the environment:

* ``JSFIND_MAX_CHUNK_BYTES`` — one piece's size (default 700 KB)
* above ``AST_MAX_BYTES`` the AST passes are skipped; regex still runs
* above ``REJECT_MAX_BYTES`` the file is refused outright, with a hint to slice

The AST cutoff exists separately because parsing costs far more than matching:
regex is linear and cheap enough to keep running on a body the parser should
not be handed.
"""

from __future__ import annotations

import os

#: One analysis piece. Small enough that every pass over it is quick, large
#: enough that a cut does not scatter one logical statement over many pieces.
MAX_CHUNK_BYTES = int(os.getenv("JSFIND_MAX_CHUNK_BYTES", "700000"))

#: Above this the AST passes are turned off for the body: regex still runs.
AST_MAX_BYTES = int(os.getenv("JSFIND_AST_MAX_BYTES", str(5 * 1024 * 1024)))

#: Above this the body is refused. Analyzing it in pieces would take long
#: enough that the caller is better off slicing the interesting regions out
#: first — which is what the hint says.
REJECT_MAX_BYTES = int(os.getenv("JSFIND_REJECT_MAX_BYTES",
                                 str(50 * 1024 * 1024)))

#: Characters carried from one piece into the next so a regex match that
#: straddles a cut is still seen whole by one piece. Merge-time
#: de-duplication collapses the double hit. Used by :class:`PieceCutter`;
#: the batch :func:`split_by_lines` keeps its historical no-overlap cuts.
PIECE_OVERLAP = 4096


def body_bytes(body: str) -> int:
    """UTF-8 size of ``body`` — the measure every threshold is stated in."""
    return len(body.encode("utf-8", "replace"))


def is_rejected(body: str) -> bool:
    """Whether the body is too large to analyze at all."""
    return body_bytes(body) > REJECT_MAX_BYTES


def wants_ast(body: str) -> bool:
    """Whether the AST passes are worth running over this body."""
    return body_bytes(body) <= AST_MAX_BYTES


def split_by_lines(body: str, max_bytes: int = MAX_CHUNK_BYTES) -> list[str]:
    """Cut ``body`` into pieces of at most ``max_bytes``, on line boundaries.

    Each piece is prefixed with the newlines that preceded it, so line numbers
    computed against a piece mean the same thing as against the whole file. The
    padding costs a few kilobytes at worst and is the difference between a
    finding that points at the right line and one that points at line 1.

    A single line longer than ``max_bytes`` (a minified bundle) has no boundary
    to cut at near the start, so it is cut mid-line: for these files every line
    is line 1 anyway, and half a statement beats never finishing.
    """
    size = len(body)
    if size <= max_bytes:
        return [body]

    pieces: list[str] = []
    pos = 0
    already = 0  # newlines consumed, i.e. the line this piece starts on
    while pos < size:
        end = min(pos + max_bytes, size)
        if end < size:
            newline = body.rfind("\n", pos, end)
            # Only back up to a boundary that keeps most of the piece; cutting
            # at a newline that sits just past the previous one would produce
            # a swarm of tiny pieces.
            if newline > pos + max_bytes // 2:
                end = newline + 1
        piece = body[pos:end]
        if already:
            piece = "\n" * already + piece
        pieces.append(piece)
        already += body.count("\n", pos, end)
        pos = end
    return pieces


class PieceCutter:
    """Incremental :func:`split_by_lines` for text that is still arriving.

    Feed decoded text as it streams in; whole pieces come back as soon as one
    is full, so a body far past the response cap can be extracted window by
    window without ever holding it whole. The cutting rules are the batch
    function's: line boundaries preferred, mid-line only when one line outgrows
    the piece size, newline padding so line numbers stay absolute.

    Two additions the streaming case needs: ``initial_lines`` seeds the line
    counter with the newlines that preceded the window (the retained prefix of
    a truncated download), and consecutive pieces overlap by ``overlap``
    characters so a regex match that straddles a cut is still seen whole by
    one piece — the merge sets de-duplicate the double hit.
    """

    def __init__(self, max_bytes: int = MAX_CHUNK_BYTES,
                 overlap: int = PIECE_OVERLAP,
                 initial_lines: int = 0):
        self.max_bytes = max_bytes
        self.overlap = max(0, min(overlap, max_bytes // 2))
        self._buf = ""
        self._already = initial_lines

    def feed(self, text: str) -> list[str]:
        """Consume decoded text, return every piece it completed."""
        if not text:
            return []
        self._buf += text
        return self._cut(final=False)

    def flush(self) -> list[str]:
        """Return whatever is left — call once at end of stream."""
        return self._cut(final=True)

    def _cut(self, final: bool) -> list[str]:
        pieces: list[str] = []
        max_bytes = self.max_bytes
        while self._buf and (len(self._buf) > max_bytes or final):
            if len(self._buf) <= max_bytes:
                end = len(self._buf)
            else:
                end = max_bytes
                newline = self._buf.rfind("\n", 0, end)
                if newline > max_bytes // 2:
                    end = newline + 1
            piece = self._buf[:end]
            if self._already:
                piece = "\n" * self._already + piece
            pieces.append(piece)
            # Step back by the overlap so the next piece re-sees the boundary
            # region; the newline counter must step back with it.
            keep = self.overlap if not final else 0
            step = end - keep
            self._already += self._buf.count("\n", 0, step)
            self._buf = self._buf[step:]
            if final:
                break
        return pieces
