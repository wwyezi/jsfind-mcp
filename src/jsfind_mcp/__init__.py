"""jsfind-mcp — JavaScript 信息收集与敏感信息扫描，MCP Server。

收集目标站点的页面、JavaScript、Webpack/RequireJS/Vite chunk 与 source map
还原的原始源码，通过正则与 AST（Tree-sitter）双引擎提取 API 端点、请求参数、
前端路由、服务端版本号和敏感信息（密钥、Token、身份证、内网 IP 等）。

本项目只提供 MCP 能力：所有功能都通过 ``jsfind-mcp-server`` 暴露为 MCP 工具，
供 AI 在授权测试中调用。

> 免责声明：仅可用于已获得明确授权的安全测试环境。结果保留完整敏感值，
> 请严格限制访问并妥善清理。
"""

from .analyze import Engine
from .config import Config, load_config
from .model import (
    Banner,
    Endpoint,
    Finding,
    HostAsset,
    Mode,
    Param,
    ParamHit,
    RequestSpec,
    RequestTemplate,
    Resource,
    Result,
    Severity,
)
from .scanner import Scanner, Target

# Read the version from the installed metadata instead of repeating it here.
# The two had already drifted -- pyproject said 0.1.0 while this said 1.0.0, so
# `pip show` and jsfind_diagnostics disagreed about what was installed.
try:
    from importlib.metadata import PackageNotFoundError as _PkgNotFound
    from importlib.metadata import version as _dist_version

    try:
        __version__ = _dist_version("jsfind-mcp")
    except _PkgNotFound:
        # Running from a source checkout that was never installed.
        __version__ = "0.1.0"
except ImportError:  # pragma: no cover - Python < 3.8
    __version__ = "0.1.0"

__all__ = [
    "Banner",
    "Config",
    "Endpoint",
    "Engine",
    "Finding",
    "HostAsset",
    "Mode",
    "Param",
    "ParamHit",
    "RequestSpec",
    "RequestTemplate",
    "Resource",
    "Result",
    "Scanner",
    "Severity",
    "Target",
    "__version__",
    "load_config",
]
