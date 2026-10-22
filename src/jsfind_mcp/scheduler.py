"""Bounded work queue for the collection phase.

The queue is breadth-first by depth so the entry document's scripts are always
fetched before the chunks those scripts reference. Every cap is explicit: a
crawler without limits is a denial-of-service tool aimed at its own target.
"""

from __future__ import annotations

import heapq
import threading
from dataclasses import dataclass, field

from .discover.types import Kind
from .utils import normalize_url


@dataclass(order=True)
class Item:
    """One unit of work, ordered by depth then insertion."""

    sort_key: tuple = field(compare=True)
    url: str = field(compare=False)
    kind: str = field(compare=False, default=Kind.SCRIPT)
    source_url: str = field(compare=False, default="")
    depth: int = field(compare=False, default=0)
    method: str = field(compare=False, default="")
    evidence: str = field(compare=False, default="")
    source: str = field(compare=False, default="")
    spec: object = field(compare=False, default=None)


class Queue:
    """Thread-safe depth-first-bounded queue with per-URL deduplication."""

    def __init__(self, max_depth: int = 5, max_items: int = 0):
        self.max_depth = max_depth
        self.max_items = max_items
        self._heap: list[Item] = []
        self._queued: set[str] = set()
        self._done: set[str] = set()
        self._counter = 0
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._heap)

    def push(self, url: str, kind: str, source_url: str = "", depth: int = 0,
             **extra) -> bool:
        """Queue one URL. Returns False when it was rejected or already known."""
        normalized = normalize_url(url)
        if not normalized:
            return False
        if depth > self.max_depth:
            return False
        with self._lock:
            key = f"{kind}\x00{normalized}"
            if key in self._queued or key in self._done:
                return False
            if self.max_items and len(self._queued) + len(self._done) >= self.max_items:
                return False
            self._counter += 1
            self._queued.add(key)
            item = Item(
                sort_key=(depth, self._counter),
                url=normalized,
                kind=kind,
                source_url=source_url,
                depth=depth,
                **extra,
            )
            heapq.heappush(self._heap, item)
            return True

    def pop(self) -> Item | None:
        """Next item, or None when the queue is drained."""
        with self._lock:
            if not self._heap:
                return None
            item = heapq.heappop(self._heap)
            self._done.add(f"{item.kind}\x00{item.url}")
            return item

    def seed(self, url: str, kind: str = Kind.SCRIPT, source_url: str = "",
             **extra) -> bool:
        """Queue an item with depth 0, for content the scan starts from."""
        return self.push(url, kind, source_url=source_url, depth=0, **extra)

    @property
    def exhausted(self) -> bool:
        with self._lock:
            return not self._heap

    def stats(self) -> dict:
        with self._lock:
            return {"pending": len(self._heap), "seen": len(self._done)}
