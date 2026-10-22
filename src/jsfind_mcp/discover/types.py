"""Discovery layer: extractors that turn page/script bodies into queue items."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..model import ContextLine, Finding, RequestSpec, SPAEvidence


class Kind:
    """How a discovered URL should be processed by the scan queue."""

    SCRIPT = "script"
    CHUNK = "chunk"
    ENDPOINT = "endpoint"
    ROUTE = "route"
    ASSET = "asset"
    SOURCEMAP = "sourcemap"

    ALL = (SCRIPT, CHUNK, ENDPOINT, ROUTE, ASSET, SOURCEMAP)


@dataclass
class Candidate:
    """A URL-like value plus the resource that exposed it."""

    raw: str = ""
    kind: str = Kind.ENDPOINT
    source_url: str = ""
    depth: int = 0
    method: str = ""
    evidence: str = ""
    line: int = 0
    column: int = 0
    #: byte offset of the match in the source body, used to derive line/column
    offset: int = 0
    context_lines: list[ContextLine] = field(default_factory=list)
    body_params: list[str] = field(default_factory=list)
    spec: RequestSpec | None = None
    vendor: bool = False
    source: str = ""              # ast | regex | cdp | sourcemap | html
    rule_id: str = ""

    def dedup_key(self) -> str:
        return f"{self.kind}\x00{self.method}\x00{self.raw}"


def is_noise_endpoint(raw: str) -> bool:
    """Whether a candidate is an extraction artifact rather than a reference.

    A value consisting of slashes only ("//", "///") comes from regexes running
    over comment markers.
    """
    return raw.strip("/") == ""


@dataclass
class BasePathCandidate:
    """An interface prefix a bundle declares, e.g. axios baseURL "/api"."""

    raw: str = ""
    kind: str = "ast"             # ast | text
    source_url: str = ""
    line: int = 0


@dataclass
class JSResult:
    """Everything one JavaScript body contributed."""

    candidates: list[Candidate] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    params: list = field(default_factory=list)          # list[ParamHit]
    hosts: list = field(default_factory=list)           # list[HostCandidate]
    base_paths: list[BasePathCandidate] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    spa: SPAEvidence = field(default_factory=SPAEvidence)


@dataclass
class HTMLResult:
    """Resources, inline scripts and SPA signals extracted from a document."""

    candidates: list[Candidate] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    spa: SPAEvidence = field(default_factory=SPAEvidence)