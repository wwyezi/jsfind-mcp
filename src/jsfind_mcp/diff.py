"""Compare a scan against an endpoint list the tester already has.

The workflow this serves: a team has a list of interfaces from last quarter,
and needs to know which ones the current build exposes that the list does not
mention -- and, just as usefully, which entries the list still claims but the
current build no longer serves.

Matching is deliberately forgiving. A hand-maintained list rarely carries the
method, rarely carries the host, and often carries a different query string
than the code does today. Comparing on anything stricter than the path shape
would report a wall of false "new" endpoints, which is worse than useless.
"""
from __future__ import annotations

from urllib.parse import urlparse


def path_of(value: str) -> str:
    """The path shape of a URL or path, with parameters collapsed.

    ``/user/42`` and ``/user/{userId}`` are the same interface as far as a
    tester is concerned, so numeric segments and ``{placeholders}`` both become
    ``*``. A path that already uses ``:id`` style keeps its shape.
    """
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        raw = urlparse(raw).path or "/"
    else:
        raw = raw.split("?", 1)[0].split("#", 1)[0]
    if not raw:
        return "/"
    segments = []
    for part in raw.strip("/").split("/"):
        if not part:
            continue
        if part.startswith("{") and part.endswith("}"):
            segments.append("*")
        elif part.startswith(":") or part.isdigit():
            segments.append("*")
        else:
            segments.append(part)
    return "/" + "/".join(segments) if segments else "/"


def method_of(value: str) -> str:
    """The HTTP method a list entry names, or "" when it names none."""
    raw = (value or "").strip()
    head = raw.split(None, 1)[0] if " " in raw else ""
    if head.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
                        "OPTIONS", "TRACE", "CONNECT"):
        return head.upper()
    return ""


def split_entry(entry: str) -> tuple:
    """(method, path) for one entry of a known-endpoint list."""
    raw = (entry or "").strip()
    if not raw:
        return "", ""
    method = method_of(raw)
    if method:
        raw = raw.split(None, 1)[1]
    return method, path_of(raw)


def _matches(known_path: str, found_path: str, suffix: bool) -> bool:
    """Whether a known entry covers a found path.

    Exact match first. With ``suffix`` on, a known path that is a whole-segment
    suffix of the found path also matches: a list that says ``/order/submit``
    means the same interface as ``/api/v2/order/submit``, and reporting that
    as "new" every time would bury the genuinely new endpoints in noise.
    """
    if known_path == found_path:
        return True
    if not suffix or not known_path or not found_path:
        return False
    if known_path == "/":
        # The root would match every path, which is not what "the list has
        # / in it" means.
        return False
    if not found_path.endswith(known_path):
        return False
    # The segment boundary is carried by the known path itself: it starts with
    # "/", so "/order/submit" joins onto "/api/v2" cleanly, while
    # "/submit" would not match "/api/v2/order/submitx".
    return known_path.startswith("/")


def diff_endpoints(endpoints, known, suffix: bool = True) -> dict:
    """Split the scan's endpoints into new and already-known.

    ``known`` entries may be a bare path, a full URL, or ``METHOD path``. An
    entry without a method matches the path under any method, because a
    hand-kept list is usually a list of paths.

    With ``suffix`` on (the default), a known path also matches when it is a
    whole-segment suffix of the found path, so version prefixes such as
    ``/api/v2/`` do not turn every known interface into a false "new" one.
    """
    known_methods: set = set()
    known_paths: set = set()
    for entry in known or []:
        method, path = split_entry(str(entry))
        if not path:
            continue
        known_paths.add(path)
        if method:
            known_methods.add(f"{method} {path}")

    new_rows = []
    seen_new = set()
    for endpoint in endpoints:
        if getattr(endpoint, "type", "") != "api":
            continue
        method = (getattr(endpoint, "method", "") or "").upper()
        path = path_of(getattr(endpoint, "url", "") or "")
        if not path:
            continue
        known_by_path = path in known_paths
        known_by_method = f"{method} {path}" in known_methods
        if known_by_path or known_by_method:
            continue
        if suffix and any(_matches(candidate, path, True)
                          for candidate in known_paths):
            continue
        key = f"{method} {path}"
        if key in seen_new:
            continue
        seen_new.add(key)
        new_rows.append({
            "method": method,
            "path": path,
            "url": getattr(endpoint, "url", ""),
            "evidence": getattr(endpoint, "evidence", ""),
            "signal": getattr(endpoint, "signal", ""),
            "authorized": bool(getattr(endpoint, "authorized", False)),
            "body_params": list(getattr(endpoint, "body_params", []) or []),
        })

    found = {path_of(getattr(e, "url", "") or "") for e in endpoints
             if getattr(e, "type", "") == "api"}
    stale = sorted(
        path for path in known_paths
        if not any(_matches(path, candidate, suffix) for candidate in found))

    new_rows.sort(key=lambda row: (row["method"], row["path"]))
    return {
        "new_endpoints": new_rows,
        "new_count": len(new_rows),
        "stale_known": stale,
        "stale_count": len(stale),
        "known_count": len(known_paths),
        "scanned_count": len(found),
    }
