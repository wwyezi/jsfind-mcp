"""Proxy configuration: parsing, validation and safe reporting.

A proxy URL carries credentials, and scan results get logged, pasted into
reports and shown to a model. So the rule throughout this module is that a
password may go *into* an httpx client and may never come back *out* of one.

Two things this exists to fix about the previous behaviour:

* ``config.request.proxy`` was handed straight to httpx, so a typo like
  ``127.0.0.1:8888`` or ``htp://x`` raised an opaque error from deep inside
  client construction and killed the whole scan with no usable message.
* nothing reported which proxy was in effect, so a scan silently going direct
  looked identical to one going through the operator's proxy.
"""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse

#: Schemes worth routing through a proxy. ``socks5h`` resolves DNS at the
#: proxy, which is the point of using a proxy for recon at all.
HTTP_SCHEMES = frozenset({"http", "https"})
SOCKS_SCHEMES = frozenset({"socks4", "socks5", "socks5h"})
SUPPORTED_SCHEMES = HTTP_SCHEMES | SOCKS_SCHEMES

#: Environment variables httpx honours when trust_env is on. Named here so
#: diagnostics can say which one is actually in play instead of leaving the
#: operator to guess.
ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


class ProxyError(ValueError):
    """A proxy setting that cannot be used, phrased for the operator."""


def normalize(value: str) -> str:
    """Return a proxy URL httpx accepts, or raise :class:`ProxyError`.

    Accepts what people actually type: a bare ``host:port`` is assumed to be an
    HTTP proxy, because that is what it almost always is.
    """
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
    except ValueError as exc:
        raise ProxyError(f"代理地址无法解析：{value!r}（{exc}）") from None
    scheme = (parsed.scheme or "").lower()
    if scheme not in SUPPORTED_SCHEMES:
        supported = "、".join(sorted(SUPPORTED_SCHEMES))
        raise ProxyError(
            f"不支持的代理协议 {scheme!r}；支持：{supported}"
            "（协议://主机:端口，可含 user:password@）")
    if not parsed.hostname:
        raise ProxyError(
            f"代理地址缺少主机名：{value!r}；"
            "正确形式如 http://127.0.0.1:8080 或 socks5://user:pass@host:1080")
    try:
        parsed.port
    except ValueError:
        raise ProxyError(f"代理端口无效：{value!r}") from None
    return urlunparse(parsed)


def is_socks(value: str) -> bool:
    """Whether this proxy needs the optional SOCKS dependency."""
    raw = (value or "").strip()
    if not raw:
        return False
    if "://" not in raw:
        raw = "http://" + raw
    return (urlparse(raw).scheme or "").lower() in SOCKS_SCHEMES


def socks_available() -> bool:
    """Whether ``httpx[socks]`` is installed in this environment."""
    try:
        import socksio  # noqa: F401
    except ImportError:
        return False
    return True


def redact(value: str) -> str:
    """A proxy URL safe to log: the password is replaced, never trimmed.

    The username is kept -- "which account am I using" is usually the thing an
    operator needs to see, and it is not itself a secret.
    """
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    if not parsed.password:
        return raw
    user = parsed.username or ""
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunparse(parsed._replace(netloc=f"{user}:***@{host}"))


def bypass_hosts(value: str) -> list:
    """Parse a ``no_proxy`` list into bare hostnames.

    httpx applies an explicit bypass by mounting a ``None`` transport for the
    pattern, so entries have to be hostnames without a scheme or a port.
    """
    hosts = []
    for item in (value or "").replace(";", ",").split(","):
        host = item.strip().lower()
        if not host:
            continue
        if "://" in host:
            host = urlparse(host).hostname or ""
        host = host.split("@")[-1]
        if host.startswith("["):
            host = host[1:].split("]")[0]
        elif ":" in host:
            host = host.split(":")[0]
        if host:
            hosts.append(host)
    return hosts


def mounts_for(hosts: list) -> dict:
    """httpx mounts that skip the proxy for the given hosts."""
    return {f"all://{host}": None for host in hosts}


def describe(proxy: str, no_proxy: str, trust_env: bool) -> dict:
    """What is in effect, safe to print, for ``jsfind_diagnostics``."""
    try:
        effective = normalize(proxy) if (proxy or "").strip() else ""
        problem = ""
    except ProxyError as exc:
        effective, problem = "", str(exc)
    report = {
        "proxy": redact(effective),
        "proxy_configured": bool(effective),
        "no_proxy": sorted(bypass_hosts(no_proxy)),
        "trust_env": bool(trust_env),
        "env_in_effect": {},
    }
    if trust_env:
        import os
        report["env_in_effect"] = {
            name: redact(os.environ[name])
            for name in ENV_VARS if os.environ.get(name)
        }
    notes = []
    if problem:
        notes.append(problem)
    if effective and is_socks(effective) and not socks_available():
        notes.append(
            "配置了 SOCKS 代理但当前环境未安装 socksio；"
            "请执行 pip install \"httpx[socks]\"，否则请求会失败。")
    if notes:
        report["notes"] = notes
    return report
