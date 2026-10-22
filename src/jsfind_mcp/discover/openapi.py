"""OpenAPI / Swagger specification discovery.

A published API specification is the highest-value artifact a target can leak:
it names every path, every method, every parameter and every declared security
scheme — authoritatively, rather than inferred from a bundle. When one is
found it outranks everything the static analysis recovered, so it is worth
probing for even though nothing on the page references it.

The probe is a short list of well-known locations. That is deliberately
bounded: the paths are conventional, and an unbounded wordlist against a
third-party host is not something this tool should do.
"""

from __future__ import annotations

import json
import re

#: Conventional specification locations, cheapest and most likely first.
SPEC_PATHS = (
    "/v3/api-docs",
    "/v2/api-docs",
    "/v3/api-docs/swagger-config",
    "/swagger.json",
    "/swagger-resources",
    "/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/api/swagger.json",
    "/api/v3/api-docs",
    "/doc.json",
    "/api-docs.json",
)

#: A specification referenced from a page or bundle.
_SPEC_REFERENCE = re.compile(
    r"""(?i)(?<![\w./-])["'](?P<path>/[\w./-]{0,80}"""
    r"""(?:api-docs|swagger|openapi|swagger-config|api-docs\.json)"""
    r"""(?:\.json|\.yaml)?)["']"""
)
_SPEC_URL = re.compile(
    r"""(?i)(?<![\w./-])(?P<url>https?://[A-Za-z0-9._-]+(?::\d+)?"""
    r"""/[\w./-]{0,80}(?:api-docs|swagger|openapi)[\w./-]*)"""
)
#: Springdoc/Knife4j hand out a pointer to the real document.
_SWAGGER_CONFIG = re.compile(
    r"""(?is)["'](?P<key>urls?["']?\s*:\s*\[[^\]]*["'])(?P<path>/[\w./-]+)["']"""
)

_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")

#: Endpoints marked deprecated still exist and are often forgotten.
_MAX_SPEC_PATHS = 500
_MAX_PARAMS_PER_OP = 60


class SpecOperation:
    """One operation declared by a specification."""

    def __init__(self, method: str = "", path: str = "", spec_url: str = "",
                 summary: str = "", operation_id: str = "",
                 parameters: list[str] | None = None,
                 request_body: list[str] | None = None,
                 deprecated: bool = False, security: list[str] | None = None,
                 tags: list[str] | None = None):
        self.method = method.upper()
        self.path = path
        self.spec_url = spec_url
        self.summary = summary
        self.operation_id = operation_id
        self.parameters = list(parameters or [])
        self.request_body = list(request_body or [])
        self.deprecated = deprecated
        self.security = list(security or [])
        self.tags = list(tags or [])

    @property
    def requires_auth(self) -> bool:
        return bool(self.security)

    def param_names(self) -> list[str]:
        """Every declared field name, query and body alike."""
        out: list[str] = []
        for name in self.parameters + self.request_body:
            if name and name not in out:
                out.append(name)
        return out

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "path": self.path,
            "spec_url": self.spec_url,
            "summary": self.summary,
            "operation_id": self.operation_id,
            "parameters": self.parameters,
            "request_body": self.request_body,
            "deprecated": self.deprecated,
            "security": self.security,
            "tags": self.tags,
        }


class ApiSpec:
    """One parsed specification document."""

    def __init__(self, url: str = "", title: str = "", version: str = "",
                 operations: list[SpecOperation] | None = None,
                 notes: list[str] | None = None):
        self.url = url
        self.title = title
        self.version = version
        self.operations = list(operations or [])
        self.notes = list(notes or [])

    def __bool__(self) -> bool:
        return bool(self.operations)

    def to_dict(self) -> dict:
        return {"url": self.url, "title": self.title, "version": self.version,
                "operation_count": len(self.operations), "notes": self.notes}


def find_spec_references(source_url: str, body: str) -> list[str]:
    """Specification paths referenced by a page or bundle."""
    out: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        value = (value or "").strip()
        if not value or value in seen or len(value) > 256:
            return
        seen.add(value)
        out.append(value)

    for match in _SPEC_REFERENCE.finditer(body):
        add(match.group("path"))
    for match in _SPEC_URL.finditer(body):
        add(match.group("url"))
    for match in _SWAGGER_CONFIG.finditer(body):
        add(match.group("path"))
    return out


def parse_spec(url: str, body: str) -> ApiSpec:
    """Parse an OpenAPI 2 / 3 document, or a Swagger 2 document.

    YAML is accepted but parsed as JSON: every bundler-adjacent tool emits JSON,
    and a YAML dependency is not worth carrying for the rare YAML case. A YAML
    body is reported as a note rather than silently yielding nothing.
    """
    text = (body or "").strip()
    if not text:
        return ApiSpec(url=url, notes=["空响应"])

    if not text.startswith("{"):
        if ":" in text and "openapi" in text.lower() or "swagger" in text[:400].lower():
            return ApiSpec(url=url, notes=["疑似 YAML 规范，未解析（仅支持 JSON）"])
        return ApiSpec(url=url, notes=["不是 JSON 文档"])

    try:
        document = json.loads(text)
    except (ValueError, TypeError) as exc:
        return ApiSpec(url=url, notes=[f"JSON 解析失败：{exc}"])
    if not isinstance(document, dict):
        return ApiSpec(url=url, notes=["顶层不是对象"])

    info = document.get("info") if isinstance(document.get("info"), dict) else {}
    spec = ApiSpec(
        url=url,
        title=str(info.get("title", "")),
        version=str(info.get("version", "")),
    )

    paths = document.get("paths")
    if not isinstance(paths, dict):
        spec.notes.append("没有 paths 字段")
        return spec

    for path, definition in list(paths.items())[:_MAX_SPEC_PATHS]:
        if not isinstance(path, str) or not isinstance(definition, dict):
            continue
        shared = _parameters(definition.get("parameters"), document)
        shared_refs = {name for _where, name in shared if _where == "$ref"}
        for method, operation in definition.items():
            if method.lower() not in _METHODS or not isinstance(operation, dict):
                continue
            declared = list(definition.get("parameters") or []) + \
                list(operation.get("parameters") or [])
            parameters = list(shared)
            parameters.extend(_parameters(operation.get("parameters"), document))
            body_fields = _dedupe(
                _request_body(operation.get("requestBody"), document)
                + _body_fields(declared, document)
            )
            spec.operations.append(SpecOperation(
                method=method,
                path=path,
                spec_url=url,
                summary=str(operation.get("summary", ""))[:200],
                operation_id=str(operation.get("operationId", ""))[:120],
                parameters=_dedupe([n for _w, n in parameters
                                    if n not in shared_refs])[:_MAX_PARAMS_PER_OP],
                request_body=body_fields[:_MAX_PARAMS_PER_OP],
                deprecated=bool(operation.get("deprecated")),
                security=_security(operation, document),
                tags=[str(t) for t in (operation.get("tags") or [])][:8],
            ))
    return spec


def _resolve(document, ref: str, depth: int = 0):
    """Follow one local ``#/...`` JSON pointer, with a depth cap."""
    if not ref.startswith("#/") or depth > 4:
        return None
    node = document
    for token in ref[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or token not in node:
            return None
        node = node[token]
    return node


def _parameters(raw, document) -> list[tuple[str, str]]:
    """``[(where, name)]`` for a parameter list, following one ``$ref``."""
    out: list[tuple[str, str]] = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        if not isinstance(item, dict):
            continue
        ref = str(item.get("$ref", ""))
        if ref:
            resolved = _resolve(document, ref)
            # A $ref here names a shared *parameter* object, so the useful
            # value is the field name inside it, not the pointer's last token.
            if isinstance(resolved, dict):
                name = resolved.get("name")
                if isinstance(name, str) and name:
                    out.append(("$ref", name))
            continue
        name = item.get("name")
        if isinstance(name, str) and name:
            out.append(("inline", name))
    return out


def _body_fields(raw: list, document) -> list[str]:
    """Swagger 2 declares a body as a parameter with ``in: body``."""
    out: list[str] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        target = _resolve(document, str(item.get("$ref", "")))
        if not isinstance(target, dict):
            continue
        if str(target.get("in", "")).lower() == "body":
            out.extend(_schema_fields(target.get("schema"), document))
    return out


def _request_body(raw, document) -> list[str]:
    """Field names declared by an OpenAPI 3 request body, following $ref."""
    if not isinstance(raw, dict):
        return []
    content = raw.get("content")
    if not isinstance(content, dict):
        return _schema_fields(raw.get("schema"), document)
    out: list[str] = []
    for media in content.values():
        if isinstance(media, dict):
            out.extend(_schema_fields(media.get("schema"), document))
    return out


def _schema_fields(schema, document, depth: int = 0) -> list[str]:
    """Property names of a schema, following ``$ref`` and combinators."""
    if not isinstance(schema, dict) or depth > 4:
        return []
    out: list[str] = []
    if isinstance(schema.get("properties"), dict):
        out.extend(str(key) for key in schema["properties"])
    ref = str(schema.get("$ref", ""))
    if ref:
        resolved = _resolve(document, ref, depth)
        if isinstance(resolved, dict):
            out.extend(_schema_fields(resolved, document, depth + 1))
    for key in ("allOf", "oneOf", "anyOf"):
        branch = schema.get(key)
        if isinstance(branch, list):
            for item in branch:
                out.extend(_schema_fields(item, document, depth + 1))
    return out


def _security(operation: dict, document: dict) -> list[str]:
    """Which security schemes apply, by name."""
    schemes = operation.get("security")
    if not isinstance(schemes, list) or not schemes:
        # An operation with no explicit security inherits the global one; an
        # empty list explicitly means "public", which is the interesting case.
        return []
    out: list[str] = []
    for entry in schemes:
        if isinstance(entry, dict):
            out.extend(str(name) for name in entry)
    return out


def requires_auth_spec(document: dict) -> bool:
    """Whether the document declares a global security requirement."""
    schemes = document.get("security")
    return bool(isinstance(schemes, list) and schemes)


def _dedupe(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
