"""Probe the banner engine against single header sets (development aid).

    python devtools/probe_banner.py "X-Powered-By: PHP/8.2.1" "Server: nginx"
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from jsfind_mcp.banner import BannerEngine  # noqa: E402


def main(argv: list[str]) -> int:
    engine = BannerEngine.default()
    print(f"rules: {len(engine)}")
    for diagnostic in engine.diagnostics:
        print(f"  ! {diagnostic}")

    if not argv:
        for headers in (
            {"Server": "nginx/1.18.0 (Ubuntu)", "X-Powered-By": "PHP/8.2.1"},
            {"X-Powered-By": "PHP/8.2.1"},
            {"Server": "nginx"},
            {"X-Powered-By": "Express"},
        ):
            found = engine.match_headers(headers)
            pairs = [(b.product, b.version, b.header) for b in found]
            print(f"  {headers}\n    -> {pairs}")
        return 0

    for raw in argv:
        name, _, value = raw.partition(":")
        found = engine.match_headers({name.strip(): value.strip()})
        pairs = [(b.product, b.version, b.header) for b in found]
        print(f"  {raw}\n    -> {pairs}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
