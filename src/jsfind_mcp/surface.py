"""Ranked attack-surface overview.

An agent driving this tool does not want seven list endpoints and a synthesis
of its own — it wants to be told *where to start* and *why*, then be able to
drill into any thread. This module builds that shortlist from evidence the scan
already gathered, and — just as importantly — states what the scan could not
see, so the model does not treat an empty list as an absent risk.

Each lead carries a ``why`` string rather than a bare score: a number is not
actionable, a reason is.
"""

from __future__ import annotations

from .model import Mode, RuleCategory, Severity, severity_rank

#: write verbs that change server state; reachable without auth these are the
#: first thing to try
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: path segments that usually mean an administrative surface
_ADMIN_MARKERS = (
    "admin", "manage", "console", "system", "sys/", "internal", "backend",
    "ops", "debug", "test", "config", "setting", "upload", "download",
    "export", "import", "batch", "job", "task", "cron", "callback", "hook",
    "webhook", "notify", "payment", "pay", "refund", "order", "invoice",
    "download", "file", "upload", "user", "account", "auth", "token", "role",
    "permission", "menu", "dict", "sql", "log", "exec", "eval", "shell",
)

#: parameters that are worth probing for injection or authorization bypass
_INTERESTING_PARAMS = (
    "id", "ids", "uid", "userid", "user_id", "roleid", "role_id", "orgid",
    "tenantid", "tenant_id", "file", "filename", "path", "dir", "url", "uri",
    "redirect", "next", "returnurl", "callback", "cmd", "command", "exec",
    "query", "sql", "filter", "sort", "order", "keyword", "search", "page",
    "size", "limit", "offset", "no", "pageNo", "pageSize",
)

#: middleware whose versions carry known-vulnerability weight. A version match
#: does not prove exploitability, so the wording stays "check for" not "is".
_RISKY_MIDDLEWARE = {
    "Apache Tomcat": "Tomcat 低于最新补丁版本时存在 Ghostcat 等历史漏洞",
    "Apache HTTP Server": "Apache 2.4.x 需关注 CVE-2021-41773 / 2.4.49 及以下路径穿越",
    "Oracle WebLogic": "WebLogic 多个版本存在反序列化远程代码执行",
    "IBM WebSphere": "WebSphere 存在反序列化与文件上传漏洞",
    "JBoss": "JBoss EAP / WildFly 存在管理后台未授权与反序列化问题",
    "Spring Boot": "Spring Boot Actuator 端点未授权时可直接读取配置与环境变量",
    "Eclipse Jetty": "Jetty 低版本存在路径穿越与信息泄露",
    "Nginx": "Nginx 需确认是否误暴露 stub_status、目录列表或错误页版本信息",
    "PHP": "PHP 版本决定可用函数与已知反序列化链",
    "Redis": "Redis 未授权访问可直接读取或写入数据",
    "Elasticsearch": "Elasticsearch 未授权时可读取索引数据",
    "MongoDB": "MongoDB 未授权时可导出数据库内容",
}


def _lead_builders() -> tuple:
    """Lead builders, most actionable first.

    Built on call rather than at import: these functions are defined below
    this one, so a module-level tuple would evaluate before they exist.
    """
    return (
        _credential_leads,
        _write_endpoint_leads,
        _admin_route_leads,
        _middleware_leads,
        _internal_host_leads,
        _spec_leads,
        _socket_leads,
        _graphql_leads,
        _injection_param_leads,
    )


def _safe(builder, result) -> list:
    """Run one lead builder, degrading instead of taking down the view.

    This is the overview tool: it is what a model reads first to decide where
    to look. A single field that a future extractor changes shape on must not
    cost the caller the credential leads, the coverage caveats and the next
    steps along with it. Partial output beats an exception.
    """
    try:
        return builder(result)
    except Exception as exc:  # noqa: BLE001 - deliberately broad
        _DEGRADED.append(f"{builder.__name__}: {type(exc).__name__}: {exc}")
        return []


#: Builders that failed during the current build_surface call. Reported in the
#: payload so a degraded view is visible rather than silently shorter.
_DEGRADED: list = []


def build_surface(result) -> dict:
    """Build the ranked shortlist plus the coverage caveats.

    Never raises on unexpected data shape. Sections that cannot be built are
    dropped and named under ``degraded``; an offline run with no endpoints at
    all still returns hosts, banners and sensitive findings.
    """
    _DEGRADED.clear()
    leads: list[dict] = []
    for builder in _lead_builders():
        leads.extend(_safe(builder, result))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    leads.sort(key=lambda lead: (order.get(lead["severity"], 5), lead["title"]))

    payload = {
        "scan_id_note": "pass the scan_id you got from jsfind_scan",
        "summary": _safe_one(lambda r: _summary(r), result),
        "lead_count": len(leads),
        "leads": leads[:40],
        "coverage": _safe_one(lambda r: _coverage(r), result),
        "next_steps": _safe_one(lambda r: _next_steps(r, leads), result),
    }
    if _DEGRADED:
        payload["degraded"] = list(_DEGRADED)
        payload["degraded_note"] = (
            "以上部分未能生成，其余内容仍然有效；"
            "若是离线结果，通常意味着该来源不适用（无 HTTP 响应 / 无清单）。")
    return payload


def _safe_one(builder, result):
    """Same contract as :func:`_safe` for the non-list sections."""
    try:
        return builder(result)
    except Exception as exc:  # noqa: BLE001 - deliberately broad
        _DEGRADED.append(f"{getattr(builder, '__name__', 'section')}: "
                         f"{type(exc).__name__}: {exc}")
        return {}


def _lead(severity: str, kind: str, title: str, why: str,
          **evidence) -> dict:
    return {"severity": severity, "kind": kind, "title": title,
            "why": why, "evidence": evidence}


def _credential_leads(result) -> list[dict]:
    """Confirmed leaks first — a live key outranks every inferred path."""
    out: list[dict] = []
    findings = [f for f in result.findings
                if f.category is RuleCategory.SENSITIVE]
    # One lead per rule so a hundred matches of one rule do not flood the list.
    best: dict[str, object] = {}
    for finding in findings:
        current = best.get(finding.rule_name)
        if current is None or \
                severity_rank(finding.severity.value) > severity_rank(current.severity.value):
            best[finding.rule_name] = finding
    for rule_name, finding in best.items():
        out.append(_lead(
            finding.severity.value,
            "credential",
            f"泄露的凭据：{rule_name}",
            "前端代码或配置中直接暴露了可用于直接利用的敏感值，"
            "建议立即验证其有效性并扩大影响面。",
            value=finding.value,
            source_url=finding.source_url,
            line=finding.line,
            total_occurrences=sum(
                1 for f in findings if f.rule_name == rule_name),
        ))
    return out


def _write_endpoint_leads(result) -> list[dict]:
    """Unauthenticated write endpoints: the highest-yield functional lead."""
    out: list[dict] = []
    seen: set[str] = set()
    for endpoint in result.endpoints:
        if endpoint.type != "api":
            continue
        verb = (endpoint.method or "").upper()
        if verb not in _WRITE_METHODS:
            continue
        marker = endpoint.url.split("?")[0]
        if marker in seen:
            continue
        seen.add(marker)
        confirmed = endpoint.status_code and endpoint.status_code < 400
        out.append(_lead(
            "high" if confirmed else "medium",
            "write_endpoint",
            f"{verb} {marker}",
            (f"该写接口可直接访问（状态码 {endpoint.status_code}），"
             "可尝试未授权操作、越权与参数注入。"
             if confirmed else
             "前端会调用该写接口，优先测试未授权访问、水平/垂直越权与参数注入。"),
            method=verb,
            url=endpoint.url,
            status_code=endpoint.status_code,
            authorized=endpoint.authorized,
            params=endpoint.body_params[:12],
            evidence=endpoint.evidence,
            source_url=endpoint.source_url,
            line=endpoint.line,
        ))
    return out


def _admin_route_leads(result) -> list[dict]:
    """Front-end routes pointing at administrative surfaces."""
    out: list[dict] = []
    seen: set[str] = set()
    for endpoint in result.endpoints:
        if endpoint.type != "route":
            continue
        path = endpoint.url.split("?")[0].lower()
        if path in seen or not any(marker in path for marker in _ADMIN_MARKERS):
            continue
        seen.add(path)
        out.append(_lead(
            "medium", "admin_route", f"管理面路由 {endpoint.url}",
            "前端存在指向后台/管理功能的路由，"
            "这类页面常缺少前端鉴权保护，可直接访问其背后的接口。",
            url=endpoint.url,
            source_url=endpoint.source_url,
            line=endpoint.line,
        ))
    return out


def _middleware_leads(result) -> list[dict]:
    """Versioned middleware that is worth a CVE check."""
    out: list[dict] = []
    for banner in result.banners:
        note = _RISKY_MIDDLEWARE.get(banner.product)
        if not note:
            continue
        out.append(_lead(
            "medium" if banner.severity is Severity.MEDIUM else "low",
            "middleware",
            f"{banner.product} {banner.version}",
            f"{note}（版本来自 {banner.header or '响应正文'}）。",
            product=banner.product,
            version=banner.version,
            host=banner.host,
            source=banner.header or "body",
        ))
    return out


def _internal_host_leads(result) -> list[dict]:
    """Internal hosts and addresses leaked into the front end."""
    out: list[dict] = []
    internal = [asset for asset in result.hosts
                if asset.kind == "internal_host"
                or "private" in asset.attributes
                or "internal_suffix" in asset.attributes]
    for asset in internal[:10]:
        out.append(_lead(
            "high" if "private" in asset.attributes else "medium",
            "internal_host",
            f"内网资产 {asset.value}",
            "前端代码引用了内网地址，可能存在越权访问内网服务、"
            "SSRF 或通过前端代理访问未暴露后台的可能。",
            host=asset.value,
            host_kind=asset.kind,
            attributes=asset.attributes,
            occurrences=asset.occurrences,
            first_seen=asset.sources[0].source_url if asset.sources else "",
        ))
    return out


def _injection_param_leads(result) -> list[dict]:
    """Parameters whose names suggest injection or authorization surface."""
    by_name: dict[str, dict] = {}
    for hit in result.params:
        name = hit.name
        if name not in _INTERESTING_PARAMS:
            continue
        entry = by_name.setdefault(name, {"scenarios": set(), "sources": []})
        entry["scenarios"].add(hit.scenario)
        if len(entry["sources"]) < 3:
            entry["sources"].append(f"{hit.source_url}:{hit.line}")
    if not by_name:
        return []
    return [_lead(
        "info", "parameter",
        f"值得关注的参数名 {name}",
        "该参数名常见于对象标识、排序、分页或文件路径，"
        "是水平越权与注入测试的高价值入口。",
        parameter=name,
        scenarios=sorted(entry["scenarios"]),
        sources=entry["sources"],
    ) for name, entry in sorted(by_name.items())[:12]]


def _spec_leads(result) -> list[dict]:
    """Operations the target's own published interface declares.

    A specification is the only place a path can be *stated* rather than
    inferred, so a public write operation declared in one is the strongest
    starting point a static scan can offer.
    """
    declared = [e for e in result.endpoints if e.evidence == "spec"]
    if not declared:
        return []
    out: list[dict] = []
    spec_urls = sorted({e.source_url for e in declared})[:3]
    public_writes = [
        e for e in declared
        if (e.method or "").upper() in _WRITE_METHODS and not e.authorized
    ]
    for endpoint in public_writes[:10]:
        out.append(_lead(
            "high", "spec_operation",
            f"接口规范声明的公开写操作 {endpoint.method} {endpoint.raw}",
            "该操作由目标自己发布的接口文档声明，且未声明任何鉴权方案，"
            "属于规范层面的未授权风险面（规范声明不等于服务端未校验，"
            "需实际请求验证）。",
            method=endpoint.method,
            path=endpoint.raw,
            spec_url=endpoint.source_url,
            declared_params=endpoint.body_params,
        ))
    out.append(_lead(
        "info", "spec_document",
        f"目标发布了接口规范，共声明 {len(declared)} 个操作",
        "规范是目标自身的接口清单，比静态分析推断更完整；"
        "其中的路径、参数与鉴权方案可直接用于接口枚举，"
        "但规范本身不证明服务端实际行为。",
        spec_urls=spec_urls,
        operation_count=len(declared),
        public_operations=len([e for e in declared if not e.authorized]),
    ))
    return out


def _socket_leads(result) -> list[dict]:
    """WebSocket addresses, which no HTTP probe can confirm.

    A push or notification channel is frequently authenticated differently from
    the REST API next to it, so it belongs near the top of the list. The tool
    deliberately sends nothing, so the lead says what to do rather than
    pretending it already knows the answer.
    """
    sockets = [e for e in result.endpoints if e.type == "socket"]
    if not sockets:
        return []
    external = [e for e in sockets if not e.authorized]
    detail = (f"\uff0c\u5176\u4e2d {len(external)} "
              f"\u4e2a\u4e0d\u5728\u6388\u6743\u8303\u56f4\u5185"
              if external else "")
    return [_lead(
        "medium" if external else "info",
        "socket",
        f"\u53d1\u73b0 {len(sockets)} \u4e2a WebSocket \u5730\u5740" + detail,
        "WebSocket \u63e1\u624b\u901a\u9053\u7684\u9274\u6743\u65b9\u5f0f"
        "\u7ecf\u5e38\u4e0e\u540c\u7ad9 REST \u63a5\u53e3\u4e0d\u540c\uff0c"
        "\u672a\u6388\u6743\u5373\u53ef\u8fde\u63a5\u7684\u63a8\u9001"
        "\u901a\u9053\u662f\u5e38\u89c1\u95ee\u9898\u3002"
        "\u672c\u5de5\u5177\u4e0d\u53d1\u8d77\u63e1\u624b\u63a2\u6d4b"
        "\uff08\u53ea\u53d1 HTTP GET\uff09\uff0c\u8bf7\u81ea\u884c"
        "\u7528 WebSocket \u5ba2\u6237\u7aef\u9a8c\u8bc1\u63e1\u624b"
        "\u662f\u5426\u9700\u8981\u51ed\u636e\u3002",
        urls=[e.url for e in sockets[:10]],
        unauthorized=[e.url for e in external[:10]],
    )]


def _graphql_leads(result) -> list[dict]:
    """GraphQL operations whose field set says what the server hands over.

    A field selection is a statement about the response, not about the UI: a
    query asking for ``isAdmin`` or ``password`` is evidence the schema offers
    those fields even when the interface never displays them.
    """
    if not result.graphql:
        return []
    out: list[dict] = []
    risky = [op for op in result.graphql if op.get("sensitive_fields")]
    for operation in (risky or result.graphql)[:8]:
        sensitive = operation.get("sensitive_fields") or []
        out.append(_lead(
            "high" if sensitive else "info", "graphql_operation",
            f"GraphQL {operation.get('kind')} "
            f"{operation.get('name') or '(匿名)'}",
            ("字段集里包含敏感字段，schema 很可能对外提供这些数据："
             + "、".join(sensitive[:10]))
            if sensitive else
            "前端内嵌的 GraphQL 操作文档，字段集即服务端会返回的内容，"
            "可用于枚举 schema 与验证字段级越权。",
            kind_of_operation=operation.get("kind"),
            name=operation.get("name"),
            url=operation.get("url", ""),
            sensitive_fields=sensitive,
            field_count=len(operation.get("fields", [])),
            fields=operation.get("fields", [])[:40],
            document=(operation.get("document", "") or "")[:400],
        ))
    return out


def _summary(result) -> dict:
    stats = result.statistics
    return {
        "target": result.target,
        "mode": result.mode.value,
        "resources": stats.resources,
        "scripts": stats.scripts,
        "chunks": stats.chunks,
        "endpoints": stats.endpoints,
        "routes": stats.routes,
        "routes_rendered": sum(1 for r in result.routes if r.get("rendered")),
        "asset_manifests": len(result.assets),
        "api_specs": len(result.specs),
        "spec_operations": sum(1 for e in result.endpoints
                               if e.evidence == "spec"),
        "graphql_operations": len(result.graphql),
        "sensitive_findings": stats.findings,
        "parameters": stats.parameters,
        "hosts": stats.hosts,
        "banners": stats.banners,
        "technologies": result.technologies,
    }


def _coverage(result) -> dict:
    """What the scan could and could not see.

    An agent that does not know a collection phase was skipped will read an
    empty result as an absence of risk, which is the most expensive mistake
    this tool could enable.
    """
    runtime = [e for e in result.endpoints if e.evidence == "runtime"]
    caveats: list[str] = []
    if getattr(result, "mode", None) == Mode.LOCAL:
        caveats.append("离线模式只分析给定文件：未被入口页面引用的后台路径"
                       "不会自动发现，需人工补文件后追加分析。")
    if not runtime:
        caveats.append(
            "没有 runtime 级证据：所有接口均来自静态分析，"
            "前端登录后或交互触发的请求未被观察到。")
    if result.hints:
        caveats.append("存在无法静态解析的动态代码："
                       + "；".join(result.hints[:5]))
    if not result.statistics.parameters:
        caveats.append("未恢复参数名：接口可能全部由运行时拼装，"
                       "建议用 jsfind_js_search 在 JS 中按业务关键字检索。")
    if any(not e.authorized for e in result.endpoints):
        caveats.append("部分接口指向未授权域名，仅做记录、未发起请求。")
    if any(i.code == "target_timeout" for i in result.issues):
        caveats.append("扫描达到单目标超时并提前结束，结果不完整。")

    rendered = [r for r in result.routes if r.get("rendered")]
    unrendered = [r for r in result.routes if not r.get("rendered")]
    if not result.routes:
        caveats.append("未恢复任何前端路由：懒加载视图的脚本不会被采集，"
                       "带参数的路径空间也未被遍历。")
    elif unrendered:
        caveats.append(
            f"{len(rendered)}/{len(result.routes)} 条前端路由完成渲染抓取，"
            f"其余 {len(unrendered)} 条仅记录未访问。")
    if not result.specs:
        caveats.append("未发现已发布的接口规范：接口清单完全来自静态推断，"
                       "可能遗漏仅存在于文档中的路径。")
    sockets = [e for e in result.endpoints if e.type == "socket"]
    if sockets:
        caveats.append(
            f"发现 {len(sockets)} 个 WebSocket 地址，它们均未经探测："
            "本工具只发 HTTP GET，无法确认握手是否需要鉴权。")
    if not result.graphql:
        caveats.append("未发现 GraphQL 操作文档：若目标使用 GraphQL，"
                       "其 schema 与字段级权限无法从前端推断。")
    if not result.assets:
        caveats.append("未发现资源清单或 service-worker 预缓存列表："
                       "构建产物中的文件是否全部覆盖无法确认。")

    return {
        "runtime_endpoints": len(runtime),
        "collection": "static only",
        "asset_manifests": len(result.assets),
        "api_specs": len(result.specs),
        "spec_operations": sum(1 for e in result.endpoints
                               if e.evidence == "spec"),
        "routes_discovered": len(result.routes),
        "routes_rendered": len(rendered),
        "issues": [i.code for i in result.issues][:10],
        "caveats": caveats,
    }


def _next_steps(result, leads: list[dict]) -> list[str]:
    """Concrete follow-ups, chosen from what the evidence actually suggests."""
    steps: list[str] = []
    if any(lead["kind"] == "credential" for lead in leads):
        steps.append("用 jsfind_sensitive 取每条凭据的完整上下文，"
                     "判断它在前端承担什么角色、还有哪些同类值被复用。")
    if any(lead["kind"] == "write_endpoint" for lead in leads):
        steps.append("用 jsfind_endpoints 带 with_request=true 取写接口的请求包，"
                     "替换 {{fuzz:...}} 占位符后重放，验证未授权与越权。")
    if any(lead["kind"] == "spec_operation" for lead in leads):
        steps.append("接口规范已列出目标自己的接口清单，"
                     "优先按 spec 证据的接口逐个验证鉴权与越权，"
                     "不要只依赖静态分析推断出的路径。")
    if any(lead["kind"] == "graphql_operation" for lead in leads):
        steps.append("GraphQL 操作文档已给出服务端会返回的字段集，"
                     "用 introspection 或直接改写查询验证字段级越权，"
                     "并确认敏感字段是否真的受权限控制。")
    if result.routes:
        steps.append("已渲染的前端路由可通过 jsfind_js_search 继续深挖其懒加载脚本，"
                     "带参数的路由只验证了单个样本值。")
    if result.hints:
        steps.append("动态代码未完全枚举，可用 jsfind_js_search 检索业务关键字，"
                     "补齐静态分析看不到的接口。")
    if result.statistics.banners:
        steps.append("按 lead 中的中间件版本核对已知漏洞，确认补丁版本是否落后。")
    steps.append("对确认存在的接口用 jsfind_endpoints 的 response_params "
                 "补充服务端返回字段，扩展测试面。")
    return steps
