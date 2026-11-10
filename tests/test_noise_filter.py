"""Regression tests for the output-purification fixes (evaluation report).

Each test pins one of the three noise classes the tester report flagged as the
last short board: property-chain hosts (R1/T4), credential right-hand-side
identifier false positives (R3/T3), and webpack module keys filed as endpoints
(R2/T2). Minimal inline samples only; run under pytest or directly.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jsfind_mcp.analyze import Engine, ResourceRef  # noqa: E402
from jsfind_mcp.discover.hosts import hosts_from_text  # noqa: E402


def _sensitive_values(body: str) -> set:
    engine = Engine()
    result = engine.analyze(ResourceRef(url="http://t/x.js"), body)
    return {f.value for f in result.findings}


def _candidates(body: str) -> set:
    engine = Engine()
    result = engine.analyze(ResourceRef(url="http://t/x.js"), body)
    return {c.raw for c in result.candidates}


def test_credential_rules_reject_identifiers():
    # function / Object / Password dominated the report's high-severity noise.
    body = "var a={password:function, secret:Object, pwd:Password};"
    values = _sensitive_values(body)
    assert "function" not in values
    assert "Object" not in values
    assert "Password" not in values


def test_credential_rules_keep_literal_values():
    body = 'var a={password:"abc-123xyz", token:"sk_abc123"};'
    values = _sensitive_values(body)
    assert "abc-123xyz" in values


def test_hosts_reject_property_chains():
    body = "var x = a.alias; var y = a.bankaccountno; var z = a.haveparttimejob;"
    hosts = {h.raw for h in hosts_from_text("http://t/x.js", body)}
    assert "a.alias" not in hosts
    assert "a.bankaccountno" not in hosts
    assert "a.haveparttimejob" not in hosts


def test_hosts_keep_real_domains():
    body = 'var h = "webuat-vss.95522.cn";'
    hosts = {h.raw for h in hosts_from_text("http://t/x.js", body)}
    assert "webuat-vss.95522.cn" in hosts


def test_quoted_rejects_webpack_module_key():
    body = 'var m={"/ocq":function(e,t,n){}, "/PVX":function(){}};'
    candidates = _candidates(body)
    assert "/ocq" not in candidates
    assert "/PVX" not in candidates


def test_quoted_keeps_real_paths():
    body = 'var p = "/api/users";'
    candidates = _candidates(body)
    assert "/api/users" in candidates
