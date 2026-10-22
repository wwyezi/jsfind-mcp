"""Third-party library bundle detection.

Identifying a bundled library by its license banner lets the scan skip (or tag)
code that describes neither the target's own interfaces nor its own secrets.
"""

from __future__ import annotations

import re

# /*! ... */, @license, Copyright — the markers bundlers preserve for legal
# notices. They appear in the first few hundred bytes of a library bundle.
_LICENSE_BANNER = re.compile(
    r"""(?i)(?:\/\*!|@license|@preserve|\bcopyright\b|\bMIT License\b"""
    r"""|\bApache License\b|\bBSD\b|\bGNU\b|\bLGPL\b)"""
)
_LIBRARY_MARKERS = re.compile(
    r"""(?i)(?:lodash|jquery|axios|vue(?:\.runtime)?|react(?:-dom)?|moment"""
    r"""|element-ui|antd|echarts|highlight\.js|core-js|regenerator-runtime"""
    r"""|zone\.js|bootstrap|polyfill)"""
)

_HEAD_BYTES = 4096


def is_third_party_bundle(body: str) -> bool:
    """Whether a body is a recognizable third-party library bundle.

    A license banner alone is too weak (application bundles often carry one
    too), so a banner *and* a library fingerprint are both required.
    """
    if not body:
        return False
    head = body[:_HEAD_BYTES]
    if not _LICENSE_BANNER.search(head):
        return False
    return bool(_LIBRARY_MARKERS.search(head)) or bool(_LIBRARY_MARKERS.search(body[:200_000]))


def library_name(body: str) -> str:
    """The library a bundle was identified as, for the report's vendor column."""
    if not body:
        return ""
    match = _LIBRARY_MARKERS.search(body[:200_000])
    return match.group(0).lower() if match else ""
