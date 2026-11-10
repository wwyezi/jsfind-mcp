"""Joined-prefix resolution (report T7): D.a+"/path" endpoints.

Pins the resolution of a relative path built from a prefix expression: when the
prefix's value is in the same file the endpoint carries a full ``resolved``
URL, and when it is not, it carries ``unresolved_prefix`` so probe skips it.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jsfind_mcp.discover.basepath import (  # noqa: E402
    joined_prefixes,
    prefix_values,
    resolve_joined,
)

BODY = (
    'var D = {};\n'
    'D.a = "https://api.taikang.com";\n'
    'var u = url: D.a + "/downloadList";\n'
    'var v = this.url + "/getSign/";\n'
)


def test_joined_prefixes_and_values():
    joined = joined_prefixes(BODY)
    values = prefix_values(BODY)
    assert joined.get("/downloadList") == "D.a"
    assert joined.get("/getSign/") == "this.url"
    assert values.get("D.a") == "https://api.taikang.com"


def test_resolve_joined_known():
    resolved, unresolved = resolve_joined(
        "/downloadList", joined_prefixes(BODY), prefix_values(BODY))
    assert resolved == "https://api.taikang.com/downloadList"
    assert unresolved is False


def test_resolve_joined_unknown_prefix():
    resolved, unresolved = resolve_joined(
        "/getSign/", joined_prefixes(BODY), prefix_values(BODY))
    assert resolved == ""
    assert unresolved is True


def test_resolve_joined_plain_path_untouched():
    resolved, unresolved = resolve_joined(
        "/api/users", joined_prefixes(BODY), prefix_values(BODY))
    assert (resolved, unresolved) == ("", False)
