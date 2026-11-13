# jsfind-mcp



> **免责声明 / Disclaimer**
>
> 本项目是**攻防安全测试的辅助工具**，不是攻击工具，也不包含任何利用、绕过或
> 入侵能力。它做的事情只有一件：**把目标站点前端已经公开暴露的信息读出来并结构化**。
>
> - **只用于已获得明确书面授权的目标。** 未授权使用本工具收集、分析或利用任何
>   系统的信息，在中华人民共和国法律下可能违反《刑法》第 285 条（非法获取计算机
>   信息系统数据罪）、第 286 条（破坏计算机信息系统罪）、第 287 条之一（非法利用
>   计算机信息网络罪），在其他国家与地区同样可能构成刑事犯罪或违反当地数据保护
>   与计算机滥用相关法规。使用者需自行承担全部法律责任。
> - **授权不等于放任。** 即使在授权范围内，也应遵守最小化原则：只测授权资产，
>   不触碰用户数据、不影响业务可用性、发现越权后立即停止扩大范围。
> - **本工具只读。** 采集阶段仅使用 `GET`；接口确认使用只读 `GET` 探测；路由爬取
>   只访问页面、不提交任何表单、不携带任何凭据。它不会写入目标、不会执行目标代码、
>   不会尝试登录。**但请注意：默认开启的路由爬取会对目标产生可观数量的 GET 请求，
>   请先评估目标承载能力再开启。**
> - **结果包含高危数据。** 输出会保留密钥、Token、身份证号、内网地址、员工工号等
>   **完整明文值**（不做脱敏，因为脱敏会让它们失去测试价值）。这些结果等同于
>   生产凭据，请**严格限制访问权限**，按等保/PCI DSS 的要求加密存储，并在测试
>   结束后**立即销毁**。
> - **结果不是结论。** 本工具产出的是**线索**而非漏洞证明。静态分析看不到运行时行为、
>   不代表服务端没有校验；`evidence="spec"` 只说明目标自己这么声明过，不说明服务端
>   真的如此。请结合人工验证，不要把本工具输出直接当作漏洞报告。
> - **作者不对任何使用本工具造成的损失承担责任。** 使用即视为接受上述全部条款。
>
> 本项目仅供学习、研究与合规安全评估使用。

​	感谢使用，这项目还在完善中，随便聊聊为啥要写它。

​	用下来最大的感受是：不管换哪个大模型去分析前端 JS，都会漏东西，而且各家漏的还不太一样。原因也很简单——让 AI 硬啃几百 KB 的压缩 bundle，本来就容易遗漏，懒加载的路由、清单里的 chunk、WebSocket 这些更是经常直接跳过。

​	所以这个 MCP 工具想干的事很明确：把"容易漏"的部分用程序确定性扫一遍，保证每次结果都一样、该覆盖的入口都覆盖到；然后把结构化结果丢给大模型，让它发挥自己理解业务、串逻辑、判断可利用性的能力。工具兜底不漏，模型负责动脑，配合起来命中率比单用任何一边都高。

**jsfind-mcp** 是一个用 Python 编写的 MCP Server，专门为「AI 驱动的渗透测试」设计：
AI 通过 MCP 工具自动完成目标站点的前端信息收集——页面、JavaScript、
Webpack / RequireJS / Vite chunk、source map 还原的原始源码、**资源清单声明的全部文件**、
**逐条渲染路由后懒加载的脚本**、**目标自己发布的接口规范**——再用**正则 + AST
（Tree-sitter）双引擎**提取 API 端点、请求参数、前端路由、服务端中间件版本号，
以及敏感信息（密钥、Token、身份证、员工工号、用户名、OA 协同办公入口、内网 IP、
银行卡号、URL 内嵌账密等）。

**本项目只提供 MCP 能力，没有命令行。** 所有功能都以 MCP 工具暴露，产物直接以
结构化数据返回给模型，不生成面向人的 HTML 报告。

## 核心能力

| 能力             | 说明                                                         |
| ---------------- | ------------------------------------------------------------ |
| **双引擎提取**   | 正则兜底 + Tree-sitter AST 做常量传播、拼接折叠、方法绑定、query/body 拆分 |
| **动态 JS 发现** | Vite `__vite__mapDeps` / `import()` / `Worker(new URL(...))` / `importScripts` |
| **资源清单**     | 探测 `asset-manifest.json` 等 10 个约定位置与 service-worker 预缓存列表，**清单里点名的文件全部入队**——这是全流程唯一确定性的 chunk 发现路径 |
| **路由渲染爬取** | 解析路由配置还原视图路径，**逐条 GET 渲染**，取回该页面懒加载的脚本与接口；带参路径标记 `parameterized`，只验证单个样本值 |
| **接口规范探测** | 探测 12 个约定位置（`/v3/api-docs`、`/swagger.json`…），解析 OpenAPI 3 / Swagger 2 的路径、方法、参数、请求体字段与鉴权方案，证据等级 `spec` |
| **协议层发现**   | WebSocket / SSE / GraphQL 操作文档与敏感字段——这三类都不出现在 `fetch()` / `axios` 的调用形态里，不专门处理就完全看不见 |
| **深度资源发现** | 递归发现脚本、chunk、RequireJS 配置；source map 还原的原始源码**落盘可检索** |
| **JS 全量检索**  | 对收集到的所有 bundle 做正则搜索，含压缩行的上下文窗口       |
| **敏感信息规则** | 61 条 HaE 兼容规则，覆盖密钥凭证、身份标识、OA 协同办公、网络信息等 8 组 |
| **服务版本识别** | 53 条中间件版本规则，**只认带版本号的指纹**                  |
| **攻击面排序**   | 一次调用给出测试切入点，每条带理由，并说明本次**没看到什么** |
| **离线分析**     | 直接分析本地 JS/HTML/目录，不发起任何网络请求                |
| **单文件可执行** | 打包成 Windows `.exe`，目标机无需安装 Python                 |

## 安装

**方式一：直接用 exe（推荐，目标机不需要 Python）**

下载 `jsfind-mcp.exe` 放到任意目录，在 MCP 客户端里指向它的绝对路径即可，
配置写法见下一节。

**方式二：从源码运行（开发用）**

```powershell
git clone <this-repo>
cd jsfind-mcp
pip install .
```

需要 Python 3.10+。Tree-sitter AST 依赖 `tree-sitter` 与
`tree-sitter-javascript`；若安装失败会自动退化为纯正则（接口方法与参数精度下降，
其余功能不受影响），可用 `jsfind_diagnostics` 工具确认当前状态。

## 接入 MCP 客户端

```json
{
  "mcpServers": {
    "jsfind-mcp": {
      "command": "jsfind-mcp"
    }
  }
}
```

启动 `jsfind-mcp` 时会**自动输出可直接粘贴的配置**（见下文）。

## 工具一览（17 个）

### 采集

| 工具                  | 作用                                                         |
| --------------------- | ------------------------------------------------------------ |
| `jsfind_scan`         | 扫描一个目标，返回 `scan_id`；可用 `js_dir` 指定脚本落盘目录、`save_js=false` 完全不落盘、`proxy` 指定出站代理、`max_response_bytes` 限制单响应大小（`"20MB"` 也接受，超出截断保留前缀） |
| `jsfind_analyze_file` | **离线**分析本地 JS/HTML/目录，不发起任何网络请求            |
| `jsfind_diagnostics`  | 报告当前安装**能做什么、不能做什么**（AST 是否可用、规则是否完整） |

### 提取

| 工具                | 作用                                                         |
| ------------------- | ------------------------------------------------------------ |
| `jsfind_endpoints`  | 接口清单：方法、证据等级、`signal`、出处、请求参数、可选请求包。`kind="socket"` 的行是 WebSocket 地址，恒为 `unprobed` |
| `jsfind_sensitive`  | 敏感信息，按严重级别排序，可带源码上下文                     |
| `jsfind_parameters` | 参数名清单，标注恢复场景（解构 / 对象属性 / API 请求…）      |
| `jsfind_routes`     | 前端路由 + **每条路由渲染后加载到的脚本与接口**，`rendered_only` 可只看成功渲染的 |
| `jsfind_specs`      | 目标自述的接口：已发布的 OpenAPI/Swagger 及其声明的操作，资源清单，以及 bundle 里内嵌的 GraphQL 操作文档与字段集 |
| `jsfind_banners`    | 服务端 / 中间件版本号（**只含带版本号的指纹**）              |
| `jsfind_hosts`      | 代码中发现的主机 + 扫描实际访问的主机                        |
| `jsfind_resources`  | 实际下载到的资源                                             |
| `jsfind_rules`      | 已编译规则清单（`kind="body"` 或 `kind="banner"`）           |

### 分析

| 工具               | 作用                                                       |
| ------------------ | ---------------------------------------------------------- |
| `jsfind_surface`   | **从哪开始测**：排序后的切入点，每条带 `why`，附覆盖度说明 |
| `jsfind_js_files`  | 列出已落盘、可检索的 JS 产物                               |
| `jsfind_js_search` | 对所有 bundle 做正则检索（含 source map 还原的源码）       |

### 会话

| 工具           | 作用                                                         |
| -------------- | ------------------------------------------------------------ |
| `jsfind_diff`  | **本次扫描比你的接口清单多了什么**（反向也报清单里已失效的条目） |
| `jsfind_scans` | 当前内存中持有的扫描                                         |



四条设计约束：

| 行为                             | 原因                                                         |
| -------------------------------- | ------------------------------------------------------------ |
| **裸 `host:port` 当 http 处理**  | `127.0.0.1:8888` 是绝大多数人会写的形式，不必先补 `http://`  |
| **凭据永不明文回显**             | 扫描结果会被记日志、进报告、交给模型。返回值里密码一律是 `***`，用户名保留（运维需要知道用的哪个账号） |
| **写错是一句话，不是 traceback** | `htp://x`、`http://`、`http://h:notaport` 都在开扫之前就返回明确错误，而不是在 httpx 构造客户端时炸掉 |
| **实际生效的代理会回报**         | `trust_env=true` 时环境变量可能才是真正生效的那条。**悄悄直连**和**按预期走代理**在结果里长得一样——这是最该被看见的差别 |

SOCKS 需要额外依赖（保持可选，不用 SOCKS 的人不必装）：

```bash
pip install ".[proxy]"        # 从仓库安装时
```

没装却配了 `socks5://` 时，`jsfind_diagnostics` 和扫描结果都会明确提示缺 `socksio`，而不是让请求莫名失败。

> ⚠️ **走代理意味着目标看到的是代理的 IP。** 授权测试里这通常是想要的（不暴露自己的出口 IP、跨地域验证），但也意味着**目标的日志里记的是代理**。用 `no_proxy` 把内网资产排除在代理之外，否则内网接口会变成从外网打不通。

### 落盘目录：由调用方决定

`jsfind_scan` 带 `js_dir` 参数，**模型自己决定写到哪**：

```jsonc
// 让 AI 把凭据写进你指定的隔离目录
{ "url": "https://target.example", "js_dir": "/tmp/recon-acme" }

// 或者干脆不落盘
{ "url": "https://target.example", "save_js": false }
```

三条规则，都是为了让「文件在哪」不需要猜：

| 行为                 | 说明                                                         |
| -------------------- | ------------------------------------------------------------ |
| **传绝对路径就用它** | `~` 会展开；相对路径按**服务进程 cwd** 解析——MCP 客户端从哪启动就落到哪，所以**优先传绝对路径** |
| **返回实际叶子目录** | 实际写入 `<js_dir>/<host_port>/js/`，`js_dir` 字段直接回报这个绝对路径；每个目标一个子目录，多目标不会互相覆盖 |
| **不可写就明说**     | 目录建不出来时不会静默跳过：记 `js_dir_unwritable` issue + hint，并告知 `jsfind_js_files` / `jsfind_js_search` 将无结果 |

`jsfind_js_files` 也会回报同一个 `js_dir`，`jsfind_diagnostics` 回报的是**解析后的绝对默认值**并带 `js_dir_overridable_per_scan: true`——不传参数时会用哪里，AI 一眼可见。

> ⚠️ 收集到的 JS 会**原样保留密钥、Token、身份证号**（脱敏会让它们失去测试价值）。指定路径时请选你自己能管控、且用完即删的位置。

## 为什么这样设计

### 证据等级：把「推断」和「声明」分开

| evidence   | 含义                                             |
| ---------- | ------------------------------------------------ |
| `runtime`  | 运行时观察到的真实请求                           |
| `full-url` | 代码里出现了完整的绝对 URL                       |
| `static`   | 静态推断，**可能不存在**                         |
| `spec`     | 目标自己发布的接口规范里声明的，**未经请求验证** |

不同来源的接口混在一张表里而不标来源，AI 无法判断该不该先测它。

### `signal`：探测状态码的语义

AI 看到 `403` 和 `404` 若没有语义标注，只能靠猜，而且通常往乐观方向猜。

| signal      | 含义                                       |
| ----------- | ------------------------------------------ |
| `exists`    | 2xx，接口真实存在                          |
| `protected` | 401/403，接口存在但需要鉴权——这是目标      |
| `method`    | 405，接口存在，GET 不是正确方法            |
| `error`     | 5xx，接口存在但服务端异常                  |
| `not_found` | 404，**无存在证据**（可能是通用 404 处理） |
| `declared`  | 来自接口规范声明，未发起请求               |
| `unprobed`  | 未发起探测                                 |

### `hints`：明确说出没看到什么

`import.meta.glob('./modules/*.js')` 匹配到一族模块，静态无法枚举。
这种情况会进 `hints` 而不是被静默丢掉——AI 必须知道「没看到」不等于「不存在」。
三个扩展阶段各自也会报告自己做到了什么、没做到什么。

### `coverage.caveats`：覆盖度自陈

`jsfind_surface` 会说明本次采集的边界：没有 runtime 证据、未发现接口规范、
未发现资源清单、多少条路由只记录未渲染、达到超时……避免把「没采到」读成「没有风险」。

### 服务版本号只认带版本号的

`Server: nginx` 只是响应头的默认值，对测试者没有可行动的信息；
`Server: nginx/1.18.0` 直接决定适用的 CVE 集合。收录前者只会稀释信噪比。

### 探测有界

约定路径清单是短列表且有硬上限（清单 12 个、规范 12 个、路由 40 条）。
对一个目标跑无边界字典扫描不是这个工具该做的事。

---

## 启动时自动输出 MCP 配置

启动时会打印可直接粘贴的配置，并写一份 `mcp.json` 到当前目录。
输出走 **stderr**——stdio 传输下 stdout 被 JSON-RPC 占用。

========================================================================
 jsfind-mcp MCP 客户端配置（可复制粘贴）
========================================================================

启动方式: 已安装的命令行入口（PATH 中的 jsfind-mcp）    传输: stdio
命令    : jsfind-mcp

--- Claude Desktop / Cursor / CodeBuddy / VS Code（本地 stdio） -------------
{
  "mcpServers": {
    "jsfind-mcp": {
      "command": "jsfind-mcp",
      "env": { "PYTHONIOENCODING": "utf-8" }
    }
  }
}

--- Claude Code 一行命令 --------------------------------------------
claude mcp add --scope user jsfind-mcp -- jsfind-mcp
========================================================================
```

配置里的命令是**真实启动方式**，由启动器自动判定：

| 启动方式                      | 生成的命令                      |
| ----------------------------- | ------------------------------- |
| 已安装（`pip install .`）     | `jsfind-mcp`（PATH）            |
| `python -m jsfind_mcp.server` | `<python> -m jsfind_mcp.server` |
| 打包二进制                    | 绝对路径（含空格自动加引号）    |

| 开关                 | 行为                                                         |
| -------------------- | ------------------------------------------------------------ |
| `--print-config`     | 打印配置后退出，输出到 stdout，可 `> mcp.json`               |
| `--write-config DIR` | 指定配置落盘目录（默认当前目录）                             |
| `--no-config`        | 关闭自动输出                                                 |
| `--transport http`   | 生成 `{"type":"http","url":"http://127.0.0.1:8765/mcp"}` 形态 |

验证：`python devtools/verify_mcpconfig.py`——会**真的拉起配置里那条命令**并发送
`initialize` 握手，确认它是在服务而不只是会打印。

---

## 配置

加载优先级：`--config` 指定文件 > `./jsfind-mcp.yml` > `~/.jsfind-mcp/config.yml` > 内嵌默认值。

```yaml
request:
  timeout: 15s
  target_timeout: 90s
  max_response_bytes: 10485760   # 单个响应保留上限（解压后计），超出截断保留前缀
  download_timeout: 30s          # 单响应整包传输墙钟；0 不限
  proxy: ""                 # 出站代理；裸 host:port 视为 http
  no_proxy: ""               # 逗号分隔，绕过代理的主机
  trust_env: true            # 采纳 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY
scope:
  fetch_external_scripts: true
  probe_external_endpoints: false   # 探测第三方主机默认关闭
  probe_endpoints: true             # 只读 GET 探测发现的接口
  probe_asset_manifests: true       # 读资源清单，把清单点名的文件全部入队
  crawl_routes: true                # 逐条 GET 渲染前端路由，取回懒加载脚本
  route_budget: 40                  # 单次扫描最多渲染多少条路由
  probe_api_specs: true             # 探测约定位置上的 OpenAPI/Swagger 文档
  probe_source_maps: true
  skip_library_bundles: true
js_dir: ./jsfind-js      # 收集到的 JS 落盘位置，供 jsfind_js_search 读取
save_js: true
request_template: true   # 复原可复制进 Burp/Yakit 的请求包
rules_file: ""           # 自定义敏感信息规则；留空用内置规则集
banners_file: ""         # 自定义版本号规则；留空用内置规则集
```

上面 5 个**顶层键**（`js_dir` / `save_js` / `request_template` / `rules_file` /
`banners_file`）与 `request` / `concurrency` / `limits` / `scope` 四个区块都会被
读取。`save_js: false` 是你要把凭据留在磁盘之外时的那个开关，请确认它生效。

## 项目结构

```text
src/jsfind_mcp/
├── server.py        # MCP Server：17 个工具
├── mcpconfig.py     # 启动时生成可粘贴的客户端配置
├── scanner.py       # 扫描执行
├── pipeline.py      # 收集 + 提取流水线（含三个扩展阶段）
├── collect.py       # 异步 HTTP 客户端
├── scheduler.py     # 有界队列
├── scope.py         # 作用域控制
├── model.py         # 数据模型
├── config.py        # 分层配置加载
├── resources.py     # 内置数据定位（源码 / onefile / onedir 通用）
├── rules.py         # HaE 兼容规则解析与编译
├── banner.py        # 中间件版本识别引擎
├── jssearch.py      # JS 产物检索
├── surface.py       # 攻击面排序
├── localfile.py     # 本地文件离线分析
├── analyze/         # 正则规则引擎
└── discover/        # 提取器
    ├── html / javascript / astapi / astparams
    ├── webpack / requirejs / dynamic      # chunk 发现
    ├── manifest.py                        # 资源清单与预缓存列表
    ├── routes.py                          # 路由表与渲染路径
    ├── openapi.py                         # 接口规范解析
    ├── protocols.py                       # WebSocket / SSE / GraphQL
    ├── sourcemap / hosts / basepath / jsonshape / license

packaging/           # PyInstaller spec + 构建脚本
devtools/            # 验证脚本
tests/               # 单测与本地靶场
```

### 验证脚本

| 脚本                           | 验证什么                                                     |
| ------------------------------ | ------------------------------------------------------------ |
| `devtools/verify_expansion.py` | 本地起一个 SPA 靶场，验证资源清单 / 路由渲染 / 接口规范三个阶段真的能拿到懒加载 chunk |
| `devtools/verify_tools.py`     | 用 MCP 传输层真实调用工具，确认新结果字段可被模型读到        |
| `devtools/verify_banners.py`   | 版本号规则与工具清单                                         |
| `devtools/verify_mcpconfig.py` | 生成的 MCP 配置能真的握手成功                                |
| `devtools/verify_frozen.py`    | 打包后的二进制能真的跑                                       |
| `devtools/verify_offline.py`   | 离线结果的查询与概览层：surface 不抛异常、authorized 有意义、diff 找得到遗漏 |
| `devtools/verify_proxy.py`     | 起一个真实转发代理，验证流量确实经过它、密码不回显、`no_proxy` 与 `trust_env` 真的生效 |
| `devtools/verify_budget.py`    | 一次扫描会在墙钟预算处停下并返回已得结果，而不是跑下去直到客户端断开 |
| `devtools/deadlock_check.py`   | 客户端不读 stderr 管道时服务仍能应答（工具列表不会静默消失） |
| `devtools/responsive_check.py` | 大 bundle 扫描进行中 `tools/list` 仍有响应、取消与坏消息不会杀死会话 |
| `devtools/chunk_check.py`      | 大文件按行分块提取、跨块去重合并、AST 与拒绝阈值生效         |
| `devtools/lifecycle_check.py`  | 扫描缓存 LRU+TTL 与显式释放、纯 JS 目标跳过路由渲染、超时结构化返回 |
| `devtools/probe_gaps.py`       | 探测现有规则集的覆盖盲区                                     |

## 生态

- [HaE](https://github.com/gh0stkey/HaE) — 规则格式来源
- [Tree-sitter](https://tree-sitter.github.io/tree-sitter/) — JavaScript AST 解析
- [MCP](https://modelcontextprotocol.io) — Model Context Protocol
- [jsowl](https://github.com/Spade-sec/jsowl) — 同类方向的前端信息收集工具

## License

MIT
