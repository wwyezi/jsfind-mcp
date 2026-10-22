"""Regex analysis engine: rule matching over one resource body.

The engine produces two products per body:

* **Findings** — sensitive-information matches, each keeping its rule, severity,
  value, source location and surrounding source lines.
* **Extracted candidates** — URL-like values recovered by the URL rules, each
  tagged with the rule that found it so the discovery layer can classify it as a
  script, chunk, asset, route or endpoint.

AST analysis runs alongside this engine (see :mod:`jsfind_mcp.discover.astapi`); the
two have disjoint blind spots, so their results are unioned rather than one
overriding the other.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..model import Finding, ResourceType, RuleCategory
from ..rules import RuleSet
from ..utils import CONTEXT_SPAN_LINES, extract_context, line_column, line_starts
from .builtin import RULE_KIND, api_rules


@dataclass
class ExtractedCandidate:
    """One URL-like value produced by a URL rule."""

    raw: str = ""
    rule_id: str = ""
    method: str = ""
    offset: int = 0
    hint: str = "candidate"      # candidate | endpoint | route | resource | chunk


@dataclass
class ResourceRef:
    url: str = ""
    type: ResourceType = ResourceType.SCRIPT


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    candidates: list[ExtractedCandidate] = field(default_factory=list)


class Engine:
    """Compiles the rule set once and reuses it across every resource."""

    def __init__(self, ruleset: RuleSet | None = None, context_span: int = CONTEXT_SPAN_LINES):
        self.rules = ruleset if ruleset is not None else Engine.default_ruleset()
        self.context_span = context_span

    @staticmethod
    def default_ruleset(
        rules_file: str = "",
        include: tuple[str, ...] = (),
        disabled: tuple[str, ...] = (),
        custom: tuple[dict, ...] = (),
    ) -> RuleSet:
        from ..rules import build_ruleset

        return build_ruleset(
            api_rules(),
            rules_file=rules_file,
            extra_files=include,
            custom=custom,
            disabled=disabled,
        )

    @property
    def diagnostics(self) -> list[str]:
        return list(self.rules.diagnostics)

    def analyze(self, ref: ResourceRef, body: str) -> AnalysisResult:
        """Run every rule over one resource body."""
        result = AnalysisResult()
        if not body:
            return result
        starts = line_starts(body)
        seen_findings: set[tuple[str, str, int]] = set()
        seen_candidates: set[tuple[str, str]] = set()

        for rule in self.rules.sensitive:
            for value, start, _end, _match in rule.iter_matches(body):
                line, column = line_column(body, start, starts)
                key = (rule.id, value, line)
                if key in seen_findings:
                    continue
                seen_findings.add(key)
                result.findings.append(Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    category=RuleCategory.SENSITIVE,
                    severity=rule.severity,
                    value=value,
                    source_url=ref.url,
                    line=line,
                    column=column,
                    context_lines=extract_context(body, start, self.context_span, value),
                ))

        for rule in self.rules.url:
            hint = RULE_KIND.get(rule.id, "candidate")
            for value, start, _end, match in rule.iter_matches(body):
                key = (rule.id, value)
                if key in seen_candidates:
                    continue
                seen_candidates.add(key)
                result.candidates.append(ExtractedCandidate(
                    raw=value,
                    rule_id=rule.id,
                    method=rule.method_of(body, match),
                    offset=start,
                    hint=hint,
                ))
        return result

    def sensitive_count(self) -> int:
        return len(self.rules.sensitive)

    def url_count(self) -> int:
        return len(self.rules.url)

    def describe(self) -> list[dict]:
        """Rule inventory, for the MCP ``jsfind_rules`` tool."""
        return [{
            "id": rule.id,
            "name": rule.name,
            "category": rule.category.value,
            "severity": rule.severity.value,
            "pattern": rule.source_pattern,
        } for rule in self.rules.all()]