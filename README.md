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

​	用下来最大的感受是：不管换哪个大模型去分析前端 JS，都会漏东西，而且各家漏的还不太一样。原因也很简单——让 AI 硬啃几百 KB 的压缩 bundle，本来就容易看走眼，懒加载的路由、清单里的 chunk、WebSocket 这些更是经常直接跳过。

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
| `jsfind_scan`         | 扫描一个目标，返回 `scan_id`；可用 `js_dir` 指定脚本落盘目录、`save_js=false` 完全不落盘、`proxy` 指定出站代理 |
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

## 三个扩展阶段是怎么工作的

常规静态分析有三种确定的盲区，本项目用三个阶段分别补上，外加一个协议层通道。

### 1. 资源清单：唯一不靠猜的 chunk 发现

chunk 引用绝大多数是**间接**的——写在 webpack runtime 的映射表里、或者只出现在
某个从未被加载的 chunk 中。但构建产物通常会自己声明文件清单：

```text
/asset-manifest.json   /build-manifest.json   /mix-manifest.json   ...
navigator.serviceWorker.register('/service-worker.js')
self.__precacheManifest = (self.__precacheManifest || []).concat([...])
```

本工具**先读页面自己引用到的位置，再退回约定列表**（上限 12 个），解析后把清单里
**每一个脚本文件全部入队**。这是全流程唯一确定性的发现路径——其余 chunk 发现都是
概率性的。

### 2. 路由渲染：懒加载的代码只有渲染才看得见

一个懒加载视图的代码**存在于构建产物里，但没有任何已加载的脚本提到它**，
所以读 bundle 永远找不到它。只有访问它的路径才能拿到。

本工具解析路由配置（`{path, component|name|children|redirect}` 对象字面量，
压缩后作为函数参数出现也能命中），逐条 `GET` 渲染，并记录**这条路由单独拉进来的
脚本与接口**：

```json
{
  "route": "https://target/reports",
  "params": [], "parameterized": false,
  "rendered": true, "status_code": 200,
  "scripts": ["https://target/static/ChunkReports.js"],
  "endpoints": ["/api/v1/report/export"],
  "note": ""
}
```

前端路由守卫经常**不是权限控制**，直接访问往往能渲染出来并触发它自己的请求——
这也是本阶段只发 `GET`、不提交任何表单、不携带任何凭据的原因。

`parameterized: true` 表示动态段（`/user/:id`）被替换成探测值 `1` 渲染了一次：
**路径形状被确认了，但取值空间没有被遍历**。这一点会如实标注，不会假装覆盖了。

### 3. 接口规范：目标自己声明的接口清单

别处发现的接口都是从字符串字面量**推断**出来的，可能根本不存在。已发布的
OpenAPI / Swagger 文档是目标**自己写下的接口清单**，包含任何响应里都没出现过的字段：

```text
/v3/api-docs   /v2/api-docs   /swagger.json   /swagger-resources
/api-docs   /openapi.json   /openapi.yaml   /api/v3/api-docs   /doc.json  ...
```

解析出的操作带 `evidence="spec"`，`authorized` 反映的是**文档中声明的鉴权方案**
（空 `security` 数组 = 文档声称该操作是公开的），而不是服务端真实行为。
这些操作**刻意不进入 GET 探测队列**——一份规范可能声明数百个路径，
确认目标自己写下的接口不是「收集」该做的事。

> YAML 规范会被识别并明确报告「疑似 YAML，未解析」，而不是静默返回空。

### 4. 非 HTTP 协议：WebSocket / SSE / GraphQL

本项目其余部分都围绕 `fetch` / `axios` / XHR 的调用形态展开，但有三块真实的
攻击面完全在这个词汇表之外：

| 协议          | 为什么重要                                                   |
| ------------- | ------------------------------------------------------------ |
| **WebSocket** | 推送 / 通知通道的鉴权方式经常与 REST 接口不同，未授权 socket 是常见问题 |
| **SSE**       | 只读数据流常在无人察觉的情况下泄露实时记录                   |
| **GraphQL**   | 内嵌的**操作文档**比接口地址更有价值——它点名了服务端会返回的每一个字段，包括界面从不渲染的那些 |

WebSocket 地址以 `kind="socket"` 单独成行，**不混进 REST 接口**、也不生成 HTTP
请求模板、**绝不进入探测队列**：一个 `GET wss://...` 确认不了任何事，却会让模型把
无意义的返回读成「接口存在」或「404 不存在」。它们恒为 `signal="unprobed"`，
`jsfind_surface` 给出 `socket` 切入点并说明「本工具只发 HTTP GET，请自行用
WebSocket 客户端验证握手是否需要凭据」，`coverage.caveats` 里也写明这一点。

GraphQL 字段集会被单独标记敏感字段。字段名是 camelCase，所以除了精确匹配，
还会做高信号片段匹配（`password` / `token` / `secret` / `isAdmin` / `apikey` …），
否则 `rawPassword`、`accessToken`、`isAdminOverride` 这些最值得测的名字会被漏掉：

```json
{
  "kind": "query",
  "name": "GetUserDetail",
  "sensitive_fields": ["email", "isAdmin", "rawPassword", "internalToken", "balance"],
  "fields": ["user", "id", "username", "email", "isAdmin", "rawPassword", "internalToken", "balance"]
}
```

## 推荐工作流

```text
jsfind_diagnostics          # 先确认能力边界
jsfind_scan                 # 采集
jsfind_surface              # 从哪开始测 + 本次没看到什么
   ├─ jsfind_specs          # 目标自己声明的接口清单（最权威）
   ├─ jsfind_endpoints      # with_request=true 取写接口请求包
   ├─ jsfind_routes         # 哪些路由渲染过、各自加载了什么
   ├─ jsfind_sensitive      # 逐条看凭据的上下文
   ├─ jsfind_js_search      # 抽取器没建模的东西（签名算法、厂商字段名）
   └─ jsfind_banners        # 核对中间件版本
```

扫描结果只存在内存里，Server 重启即失效（`scan_id` 报错会提示重新扫描）。
收集到的 JavaScript 会写到 `js_dir` 供 `jsfind_js_search` 读取。

### 离线结果也能查也能概览

`jsfind_analyze_file` 的产物和在线扫描**存在同一张可查询表里**，`jsfind_endpoints` /
`jsfind_surface` / `jsfind_sensitive` 全部可用。两条曾经出错的地方已修：

- `jsfind_surface` 曾对**任何**离线结果抛 `AttributeError`（`Result.mode` 传的是证据
  等级常量而不是 `Mode` 枚举）。现在离线返回 `mode="local"`，概览完整。
- 概览现在**降级而非抛异常**：某个来源不适用时（离线没有响应头、没有清单），
  该段被跳过并记在 `degraded` 字段里，其余内容照常返回。

### 授权范围：离线也能标

| 情况                                                    | `authorized`                         |
| ------------------------------------------------------- | ------------------------------------ |
| 在线扫描                                                | 该接口是否在扫描根的授权范围内       |
| 离线，**给了** `base_url`                               | 同一 host（且同端口）的接口为 `true` |
| 离线，**没给** `base_url`                               | 全部 `false`                         |
| 离线，`base_url` 是 `https://local.invalid/` 这类占位源 | 全部 `false`（占位源不构成授权）     |

`jsfind_endpoints` 新增 `authorized` 过滤参数（`"true"` / `"false"` / 空=不筛）。
取值无法识别时**按不筛选处理**并照常返回全量——拼错参数不该返回一个看起来像
「范围内没有东西」的空表。

### diff 模式：本次比清单多了什么

```jsonc
// 手里的接口清单
{ "scan_id": "scan-1", "known": ["/order/submit", "GET /user/{userId}/detail"] }

// 清单很长？给文件
{ "scan_id": "scan-1", "known_file": "known-endpoints.txt" }
```

输出两个方向：

- `new_endpoints` —— 扫描发现、清单里没有的接口
- `stale_known` —— 清单里有、但本次代码里没找到的条目（清单该更新了）

匹配按**路径形状**而不是完整 URL：`/user/42` 和 `/user/{userId}` 是同一个接口，
清单里的 query string 会被忽略。默认还做**后缀匹配**，所以清单里的 `/order/submit`
能匹配代码里的 `/api/v2/order/submit`——否则带版本前缀的路径会让每一行都变成
「假新增」，把真正的新接口淹掉。`suffix=false` 可退回严格比较。

### 参数噪音过滤

`jsfind_parameters` 默认过滤压缩器留下的碎名（`t`、`a`、`e`），规则是**证据强度**
而不是文件名长度猜测：**短名只出现在普通代码位置（局部变量、对象属性）才算噪音**，
同样短的，一旦出现在请求位置（`endpoint` / `url_query` / `body`）就是真参数，保留。

被过滤掉的数量会写在 `dropped_minified` 里，`drop_minified=false` 可全部取回——
过滤不该静默丢东西。结果也改成**按可信度排序**（进过请求的在前），不再按字母序。

### 业务码语义

很多接口用 200 + 业务码表达失败。`request.business_codes` 让你自己说清楚：

```yaml
request:
  business_codes:
    biz_success: ['"code":0']
    biz_auth_fail: ['"code":477']
    biz_param_missing: ['"code":10001']
```

命中后该接口的 `signal` 变成对应分类，`200 + code:477` 不再被读成「成功」。
匹配是响应体里的**子串**——你写 `"code":477` 就是在说你们自己的 API 里 477 是什么，
比这里猜任何数字的含义都准。

### 出站代理

`jsfind_scan` 带 `proxy` / `no_proxy` / `trust_env` 三个参数：

```jsonc
// 走本地 Burp / mitmproxy
{ "url": "https://target.example", "proxy": "http://127.0.0.1:8080" }

// 带凭据（凭据不会出现在返回值里）
{ "url": "https://target.example", "proxy": "http://user:pass@proxy.corp:3128" }

// SOCKS5，注意 DNS 也在代理侧解析
{ "url": "https://target.example", "proxy": "socks5://127.0.0.1:1080" }

// 内网直连、其余走代理
{ "url": "https://target.example", "proxy": "http://p:3128",
  "no_proxy": "localhost,.corp.internal" }

// 忽略环境变量，证明这次是直连
{ "url": "https://target.example", "trust_env": false }
```

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

> `mcp.json` 与 `MCP-CONFIG.md` 里是**你这台机器的绝对路径**（这正是它们的价值：
> 粘进客户端就能用）。它们每次启动都会重新生成，已在 `.gitignore` 中，
> **不要提交或转发**。要分享配置请用 `examples/mcp.json` 里的 PATH 形式。

```text
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
  target_timeout: 5m
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

**关掉扩展阶段**（只想做纯静态分析、把请求数压到最低）：

```yaml
scope:
  probe_asset_manifests: false
  crawl_routes: false
  probe_api_specs: false
  probe_endpoints: false
```

首次运行会在 `~/.jsfind-mcp/rules.yml` 播种一份可编辑的敏感信息规则，
版本号规则在 `~/.jsfind-mcp/banners.yml`。

### 敏感信息规则（HaE 兼容）

```yaml
rules:
  - group: 内网
    rule:
      - name: 内网 IP
        loaded: true
        f_regex: "(?<![0-9.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![0-9.])"
        format: '{0}'
        severity: medium
```

内置的 61 条规则分 8 组，其中与授权测试直接相关的几组：

| 组           | 覆盖内容                                                     |
| ------------ | ------------------------------------------------------------ |
| `OA协同办公` | 泛微 e-cology、致远 Seeyon、蓝凌的部署路径与自报版本，钉钉 / 企业微信入口 |
| `身份标识`   | 员工工号、用户名字段、疑似真实姓名、邮箱域名线索、**用户枚举接口** |
| `可利用凭据` | 短信 / 推送令牌、Base64 编码凭据、硬编码 Bearer、OAuth 客户端密钥、加密密钥与盐值、银行账户、身份证号、国际手机号 |

### 版本号规则

```yaml
banners:
  - id: nginx
    product: Nginx
    category: web_server
    pattern: '(?i)\bnginx/(\d+(?:\.\d+)+)'
    headers: [server, x-powered-by, via]
    severity: info
```

---

## 打包为可执行文件

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
```

产物：`dist/jsfind-mcp.exe`（单文件，34 MB 左右），目标机不需要安装 Python。

打包时的三个坑已在 spec 中处理：

1. **内置 YAML** —— `config.yml` / `rules.yml` / `banners.yml` 是数据不是代码，
   通过 `datas` 打包，运行时由 `jsfind_mcp/resources.py` 定位
   （按 `importlib.resources` → `sys._MEIPASS` → `__file__` 依次尝试）。
2. **tree-sitter 原生语法** —— `.pyd` 必须原样拷贝。
3. **httpx 运行时解析的传输后端** —— 需要显式 hidden import。

验证：`python devtools/verify_frozen.py`——真实启动 `dist/` 里的二进制，
对本地靶场跑一次扫描，并检查内置数据、原生语法、chunk 发现、版本识别。

---

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
| `devtools/probe_gaps.py`       | 探测现有规则集的覆盖盲区                                     |

## 生态

- [HaE](https://github.com/gh0stkey/HaE) — 规则格式来源
- [Tree-sitter](https://tree-sitter.github.io/tree-sitter/) — JavaScript AST 解析
- [MCP](https://modelcontextprotocol.io) — Model Context Protocol
- [jsowl](https://github.com/Spade-sec/jsowl) — 同类方向的前端信息收集工具

## License

MIT
