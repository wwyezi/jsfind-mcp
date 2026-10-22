"""Scan execution.

One class, one method. Everything the MCP server needs is ``Scanner.scan``;
the batch and library conveniences existed for a human-facing CLI and went away
with it.

A failed collection is reported as an issue on the result rather than raised:
an agent driving this tool is better served by a partial answer plus a
diagnostic than by an exception that aborts a whole engagement's worth of work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .analyze import Engine
from .config import Config, load_config
from .model import Mode, Result, ResourceType, Statistics
from .pipeline import Pipeline
from .scope import Scope

__all__ = ["Scanner", "Target"]


@dataclass
class Target:
    """One scan target and its request state."""

    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Scanner:
    """Config-bound scanner. Compiles the rule set once, reuses it."""

    def __init__(self, config: Config | None = None, engine: Engine | None = None):
        self.config = config or load_config()
        if engine is None:
            engine = Engine(Engine.default_ruleset(
                rules_file=self.config.rules_file,
            ))
        self.engine = engine

    @property
    def diagnostics(self) -> list[str]:
        """Rule-load problems worth surfacing before trusting a scan."""
        return list(self.engine.diagnostics)

    async def scan(self, target: Target | str,
                   mode: str | Mode | None = None) -> Result:
        """Scan one target and return its result.

        Raises ``ValueError`` for an empty target and ``RuntimeError`` when
        collection itself failed; every other failure lands in
        ``result.issues``.
        """
        if isinstance(target, str):
            target = Target(url=target)
        if not (target.url or "").strip():
            raise ValueError("target url is required")

        result = Result(
            target=target.url.strip(),
            started_at=_now(),
            mode=_resolve_mode(mode, self.config),
            user_agent=self.config.request.user_agent,
        )

        pipeline = Pipeline(self.config, self.engine)
        scope = Scope(result.target, self.config.scope)
        try:
            await pipeline.run(target, result, scope)
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            from .model import Issue

            result.issues.append(Issue(
                code="collection_failed", stage="collect", url=result.target,
                message=f"{type(exc).__name__}: {exc}",
            ))

        result.finished_at = _now()
        result.statistics = _statistics(result)
        return result


def _resolve_mode(mode: str | Mode | None, config: Config) -> Mode:
    if mode is None:
        return config.mode
    if isinstance(mode, Mode):
        return mode
    try:
        return Mode(str(mode).lower())
    except ValueError:
        return config.mode


def _statistics(result: Result) -> Statistics:
    scripts = sum(1 for r in result.resources
                  if r.type is ResourceType.SCRIPT)
    chunks = sum(1 for r in result.resources if r.type is ResourceType.CHUNK)
    routes = sum(1 for e in result.endpoints if e.type == "route")
    names = {hit.name for hit in result.params if hit.name}
    return Statistics(
        resources=len(result.resources),
        scripts=scripts,
        chunks=chunks,
        endpoints=len(result.endpoints),
        findings=len(result.findings),
        routes=routes,
        hosts=len(result.hosts),
        parameters=len(names),
        banners=len(result.banners),
    )
