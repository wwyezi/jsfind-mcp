"""Host discovery from analyzed content.

A host found inside JavaScript is an *observation*, not a reachability claim:
being listed here means the value appeared in the code. Validation and
classification (domain vs IP vs internal candidate, private/loopback attributes)
happen once per unique host in the pipeline, not once per occurrence.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..model import ContextLine, HostEvidence
from ..utils import extract_context, line_column, line_starts

# Hostname shapes: labels of letters/digits/hyphens, or a bracketed IPv6.
_HOSTNAME_RE = re.compile(
    r"""(?<![A-Za-z0-9_-])"""
    r"""((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"""
    r"""[A-Za-z]{2,24})"""
    r"""(?![A-Za-z0-9_-])"""
)
_URL_RE = re.compile(r"""(?i)\b(?:https?|wss?)://([^/\s"'`<>()\\]+)""")
_IPV4_RE = re.compile(
    r"""(?<![0-9.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"""
    r"""(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![0-9.])"""
)
_IPV6_RE = re.compile(r"""(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])""")

# Suffixes that mark a host as internal rather than publicly resolvable.
_INTERNAL_SUFFIXES = frozenset({
    "corp", "lan", "internal", "intranet", "local", "localhost", "home", "test",
})

# Obvious non-hosts: version strings, file names and CSS units get caught by the
# generic pattern often enough to be worth filtering explicitly.
_NOT_HOST_SUFFIXES = frozenset({
    "js", "ts", "css", "json", "xml", "html", "htm", "php", "asp", "aspx",
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "pdf", "doc",
    "docx", "xls", "xlsx", "ppt", "pptx", "zip", "rar", "gz", "tar", "exe",
    "dll", "map", "min", "min.js", "woff", "woff2", "ttf", "eot", "txt",
})

# TLDs that are really file extensions or version markers.
_PSEUDO_TLDS = frozenset({
    "version", "mod", "min", "latest", "debug", "release", "beta", "alpha",
    "inc", "obj", "lib", "src", "dist", "build", "tmp", "bak", "old", "new",
    # Common JavaScript identifiers that a bare "x.y" pattern mistakes for a
    # hostname: a.min, app.call, obj.value and friends.
    "create", "get", "set", "post", "put", "patch", "delete", "head", "call",
    "apply", "bind", "push", "pop", "shift", "unshift", "slice", "splice",
    "concat", "map", "filter", "reduce", "find", "join", "split", "trim",
    "replace", "test", "exec", "log", "warn", "error", "info", "trace",
    "config", "prototype", "constructor", "length", "name", "value", "type",
    "url", "json", "text", "html", "body", "head", "form", "list", "item",
    "items", "node", "element", "class", "style", "css", "less", "scss",
    "prototype", "then", "catch", "keys", "values", "entries", "assign",
    # Property names that appear as "obj.name" all over a bundle.
    "endpoint", "secret", "token", "query", "params", "options", "request",
    "response", "result", "status", "payload", "props", "state", "store",
    "action", "reducer", "meta", "rows", "records", "total", "count", "limit",
    "offset", "index", "parent", "children", "source", "target", "origin",
    "next", "prev", "last", "first", "done", "code", "msg", "message", "env",
    "auth", "ids", "href", "dataset", "onclick", "onerror", "innerhtml",
    "textcontent", "classname", "maxlength", "placeholder", "required",
    "readonly", "selected", "disabled", "controls", "colspan", "rowspan",
    "datetime", "formaction", "contenteditable", "tabindex", "loading",
    "webpackjsonp", "webpackchunk", "jsonp", "chunk",
})

# TLDs a tester actually meets. A bare "label.label" that ends in one of these
# is a host; one that ends in an arbitrary property name (a.alias,
# a.bankaccountno, a.haveparttimejob) is a member access, not a host. This
# positive check is what the _PSEUDO_TLDS blacklist could never finish — there
# are more property names than could be listed. Internal/loopback suffixes are
# kept so classify() can still label them internal_host rather than dropping
# them outright.
_KNOWN_TLDS = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "dev", "app",
    "ai", "co", "me", "info", "biz", "name", "pro", "top", "xyz", "vip",
    "club", "site", "online", "tech", "store", "shop", "cloud", "work",
    "live", "link", "cc", "tv", "fm", "mobi", "asia", "travel",
    "cn", "hk", "tw", "mo", "jp", "kr", "sg", "in", "uk", "de", "fr",
    "ru", "br", "au", "ca", "us", "eu", "it", "es", "nl", "se", "ch",
    "pl", "ua", "tr", "vn", "th", "my", "ph", "id", "kz", "il", "ir",
    # internal / test suffixes — classify() marks these internal_host
    "corp", "lan", "internal", "intranet", "local", "localhost", "home",
    "test", "dev", "stage", "staging", "qa",
})

_MAX_HOSTS_PER_FILE = 200
_MAX_HOST_EVIDENCE = 20


@dataclass
class HostCandidate:
    """One raw host observation, before validation."""

    raw: str = ""
    source_url: str = ""
    line: int = 0
    column: int = 0
    method: str = "regex"          # url | regex
    associated_url: str = ""
    note: str = ""
    context_lines: list[ContextLine] = field(default_factory=list)

    def to_evidence(self) -> HostEvidence:
        return HostEvidence(
            source_url=self.source_url,
            raw=self.raw,
            line=self.line,
            column=self.column,
            method=self.method,
            associated_url=self.associated_url,
            note=self.note,
            context_lines=self.context_lines,
        )


def hosts_from_text(source_url: str, body: str) -> list[HostCandidate]:
    """Recover host candidates from a body with the regex pass.

    URLs are read first so a host found inside one keeps the full URL it came
    from; bare hostnames and IPs follow.
    """
    out: list[HostCandidate] = []
    seen: set[str] = set()
    starts = line_starts(body)

    def add(raw: str, offset: int, method: str, url: str = "", note: str = "") -> None:
        if not raw or len(raw) > 255 or len(out) >= _MAX_HOSTS_PER_FILE:
            return
        key = f"{raw}\x00{url}"
        if key in seen:
            return
        seen.add(key)
        line, column = line_column(body, offset, starts)
        out.append(HostCandidate(
            raw=raw.lower().rstrip("."),
            source_url=source_url,
            line=line,
            column=column,
            method=method,
            associated_url=url,
            note=note,
            context_lines=extract_context(body, offset, 2, raw),
        ))

    for match in _URL_RE.finditer(body):
        authority = match.group(1)
        if "@" in authority:
            # Credentials in a URL are a sensitive finding, not a host; keep
            # only the host part.
            authority = authority.rsplit("@", 1)[1]
        host = _strip_port(authority)
        if _plausible(host):
            add(host, match.start(1), "url",
                url=f"{match.group(0)[:match.end() - match.start(1)]}{host}")

    for match in _IPV4_RE.finditer(body):
        if _plausible_ip(match.group(0)):
            add(match.group(0), match.start(), "regex", note="ipv4")

    for match in _IPV6_RE.finditer(body):
        candidate = match.group(0)
        if candidate.count(":") >= 2 and _plausible_ip(candidate):
            add(candidate, match.start(), "regex", note="ipv6")

    for match in _HOSTNAME_RE.finditer(body):
        candidate = match.group(1)
        before = body[match.start(1) - 1] if match.start(1) else ""
        after = body[match.end(1)] if match.end(1) < len(body) else ""
        # "http.get(" and "axios.create(" are member accesses, not hosts.
        if after == "(" or after in "@_":
            continue
        if _plausible(candidate) and _known_tld(candidate):
            add(candidate, match.start(1), "regex",
                note="email_domain" if before == "@" else "")

    return out


def _known_tld(host: str) -> bool:
    """Whether a bare hostname ends in a TLD a tester actually meets.

    Hosts read out of a ``://`` URL and IP literals are gated elsewhere, so
    only the bare-``label.label`` pass calls this — exactly the shapes
    ``obj.property`` shares, and the ones the blacklist could never exhaust.
    """
    suffix = (host or "").lower().rstrip(".").rsplit(".", 1)[-1]
    return suffix in _KNOWN_TLDS


def _strip_port(authority: str) -> str:
    if authority.startswith("["):          # [::1]:8080
        end = authority.find("]")
        return authority[: end + 1] if end > 0 else authority
    if authority.count(":") == 1:          # host:port
        return authority.split(":", 1)[0]
    return authority


def _plausible(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if host.startswith("-") or host.endswith("-"):
        return False
    lowered = host.lower()
    suffix = lowered.rsplit(".", 1)[-1]
    if suffix in _NOT_HOST_SUFFIXES or suffix in _PSEUDO_TLDS:
        return False
    if not 2 <= len(suffix) <= 24 or not suffix.isalpha():
        return False
    # Every label must look like a hostname label, not a path or a token.
    for label in lowered.split("."):
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(char.isalnum() or char == "-" for char in label):
            return False
        # Numeric labels are legal and common -- 95522.cn, 95588.cn -- and
        # rejecting them dropped exactly the corporate domains a tester
        # most wants. Version-looking strings are already excluded: the
        # matcher requires an alphabetic TLD, so 1.2.3 and v1.2.3 never
        # reach here.
    return True


def _plausible_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def classify(host: str, internal_suffixes: tuple[str, ...] = ()) -> dict:
    """Validate one host and describe it.

    Returns ``kind``, ``attributes`` and ``is_internal``. A host is only ever
    called a domain when it parses as one; everything else is reported as an IP
    or as an internal-host candidate rather than folded into a domain count.
    """
    value = (host or "").strip().lower().rstrip(".")
    result = {"kind": "internal_host", "attributes": [], "is_internal": True}

    if not value:
        return result

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None

    if address is not None:
        result["kind"] = "ipv4" if address.version == 4 else "ipv6"
        result["is_internal"] = bool(address.is_private or address.is_loopback
                                     or address.is_link_local)
        attributes = []
        if address.is_private:
            attributes.append("private")
        if address.is_loopback:
            attributes.append("loopback")
        if address.is_link_local:
            attributes.append("link_local")
        if address.is_multicast:
            attributes.append("multicast")
        if address.is_unspecified:
            attributes.append("unspecified")
        result["attributes"] = attributes or ["unclassified"]
        return result

    # A hostname: internal when it has no public suffix or a configured one.
    suffixes = tuple(internal_suffixes) or _INTERNAL_SUFFIXES
    labels = value.split(".")
    if any(label in suffixes for label in labels[1:]):
        result["kind"] = "internal_host"
        result["is_internal"] = True
        result["attributes"] = ["internal_suffix"]
        return result

    if len(labels) < 2 or not _plausible(value):
        result["kind"] = "internal_host"
        return result

    result["kind"] = "domain"
    result["is_internal"] = False
    result["attributes"] = ["unclassified"]
    result["registrable_domain"] = ".".join(labels[-2:])
    result["subdomain"] = ".".join(labels[:-2])
    result["public_suffix"] = labels[-1]
    return result


def host_from_url(url: str) -> str | None:
    """Host part of a network URL, or None when there is none."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if not parsed.netloc:
        return None
    host = parsed.hostname
    return host.lower().rstrip(".") if host else None
