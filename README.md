# DNSlog Everywhere

> 把自建 **DNSlog-GO** 变成 Burp Suite 版的 “Collaborator Everywhere” —— 自动给经过 Burp 的请求注入带唯一 ID 的回连域名，再把 DNS 解析记录匹配回「哪个请求的哪个 Header」，用来发现**不回显**的盲 SSRF / XXE / RCE / SQLi / XSS、Host 头注入、缓存投毒等问题。

![java](https://img.shields.io/badge/Java-17%2B-blue)
![burp](https://img.shields.io/badge/Burp%20Suite-2023.x%2B-orange)
![api](https://img.shields.io/badge/API-Montoya-brightgreen)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

> 截图/录屏可以放在 `docs/` 下，然后在上面这里插入 `![](docs/xxx.png)`。

---

## TL;DR (English)

A Burp Suite extension (Montoya API, pure Java, zero dependencies) that turns a self-hosted
[DNSlog-GO](https://github.com/lanyi1998/DNSlog-GO) into a Burp Collaborator replacement.
It injects a unique DNS-only domain into common HTTP headers of every proxied request, polls the
DNSlog API, and maps each DNS hit back to the exact request + header that triggered it — so you can
spot blind SSRF / XXE / RCE / SQLi and header-injection issues that never produce a visible response.
No Burp Pro required. See [配置](#配置) and [使用](#使用).

---

## 为什么需要它

Burp 官方的 **Collaborator Everywhere** 只能配合 Pro 版的 Collaborator 使用。如果你已经自建了
DNSlog-GO（或任何兼容其 API 的 DNSlog 服务），这个扩展让你在没有 Collaborator 的情况下获得同样的
「批量盲打 + 回连关联」能力：

- 每个请求的每个 Header 都带**独立的 ID**，命中后能精确知道是哪个头触发的，而不是只知道「这个请求有问题」
- 结果直接以表格形式呈现在 Burp 里，可右键复制域名 / 复现请求
- 内置降噪开关：仅 Scope、跳过静态资源、可暂停注入

## 工作原理

```
                      ①  每个请求注入独立 ID
  Browser ──► Burp Proxy ──────────────────────────────► Target
                 │      X-Forwarded-For: 1e7a3e96e301.dnslog.example.com
                 │      Referer:         http://1e7a3e96e305.dnslog.example.com/
                 │      User-Agent:      Mozilla/5.0 ... DNSlogEverywhere/1e7a3e96e307...
                 │
                 │  ② target 若真的解析了域名
                 ▼
        DNSlog-GO  DNS server  ◄──── DNS query ──── Target / WAF / 邮件网关 / 沙箱
                 │
                 │  ③ 扩展轮询 GET /api/getDnsData（带 token）
                 ▼
        Burp 「DNSlog」标签页：ID 前 12 位 → 反查内存表 → 表格出行
```

ID 结构：`<10 位随机 hex><2 位头序号>`，例如 `1e7a3e96e3` + `01`。同一请求的 7 个头共享前缀、
序号互不相同，因此一次请求命中多个头也能各自归位。

## 特性

- **零依赖**：纯 JDK + Montoya API，产出单个 jar，不需要 Gradle / Maven
- **7 个默认注入头**：`X-Forwarded-For`、`X-Real-IP`、`X-Client-IP`、`X-Forwarded-Host`、`Referer`、`Origin`、`User-Agent`，可自定义
- **可选参数注入**：把 URL / POST / JSON 等参数值也换成回连域名（默认关，噪声大）
- **独立 Tab**：工具栏 + 命中表格 + 状态栏，支持排序、右键复制域名 / 复制 URL / 删除行
- **诊断友好**：状态栏实时显示「收到请求 / 注入 / 待回连 / 命中 / 轮询时间 / 当前跳过原因」，注入没生效时直接告诉你为什么
- **兼容性好**：DNSlog-GO 的多种返回结构都能解析（字段名大小写、`data` 数组或 `data.list`、数字时间戳等），不会因为少一个字段就整轮失败
- **可选 Basic Auth**：DNSlog 前面套了 Nginx `auth_basic` 也能用
- **配置即时生效 + 持久化**：改完立即写入，重启 Burp 仍在

## 安装

1. 下载 [`dist/dnslog-everywhere.jar`](dist/dnslog-everywhere.jar)（或自己[构建](#从源码构建)）
2. Burp → **Extensions → Installed → Add**
3. Extension type 选 **Java**，选择 jar → **Next**
4. 顶部出现 **DNSlog** 标签页即成功；`Extensions → Output` 里会打印 `DNSlog Everywhere v1.4 loaded. file=...`

> 无需重启 Burp。卸载：在 Installed 列表里取消勾选即可。

## 配置

切到 **DNSlog** 标签页：

| 字段 | 说明 | 示例 |
|---|---|---|
| 服务器地址 | DNSlog-GO 根地址，末尾不要带 `/` | `https://dnslog.example.com` |
| Token | DNSlog-GO 中的 token | `abc123...` |
| 子域后缀 | 该 token 绑定的子域，点「测试连接」可自动回填 | `dnslog.example.com` |
| 账号 / 密码 | **可选**，仅当服务器前置 Basic Auth 时填 | `user` / `******` |
| 注入头 | 逗号分隔，默认 7 个 | 见下 |

```
X-Forwarded-For, X-Real-IP, X-Client-IP, X-Forwarded-Host, Referer, Origin, User-Agent
```

其它选项：

| 选项 | 默认 | 说明 |
|---|---|---|
| 轮询间隔 | 8 秒 | 3–120 秒。别设太小，避免给 DNSlog 服务器压力 |
| 仅 Scope 内 | 开 | 建议先把目标加进 Target → Scope，能大幅降噪 |
| 跳过静态资源 | 开 | 跳过 `.js/.css/.png/.jpg/.gif/.svg/.ico/.woff/.map/.mp4/.pdf/.zip` 等 |
| 注入参数 | 关 | 开启后替换参数值（每请求最多 5 个），只在怀疑参数型盲打时开 |

> 配置**边改边生效**，不需要点保存也能测；点「保存配置」才会持久化到 Burp 偏好里。

### 服务器启用了 Basic Auth

DNSlog-GO 前面套一层 `auth_basic`（Nginx）后，所有 `/api/*` 会先返回 `401 + WWW-Authenticate`。
扩展不会弹认证框，需要显式填写账号密码：

1. 填 **账号** / **密码** → 保存
2. 扩展会给 API 请求加 `Authorization: Basic base64(user:pass)`
3. 也可以把凭据写进地址（`https://user:pass@host`），保存时会自动拆分到两个输入框，URL 里不留明文

注意：这只影响**扩展访问 DNSlog 服务端**这一条路，注入到目标请求里的 Header 不会带你的 Basic Auth。

## 使用

1. 配置完成后**正常浏览/测试目标**即可。注入发生在 `HttpHandler` 层，不会回写 Burp 界面，Repeater 里看到的仍是原始请求
2. 表格里出现行 = 目标**真的发起了解析**：

| 列 | 含义 |
|---|---|
| 时间 | 注入时间 → 回连时间 |
| 方法 / URL | 是哪个请求 |
| 触发头 | 具体哪个 Header 被解析（或 `参数:xxx`） |
| 回连域名 | 带唯一 ID 的完整域名 |
| 来源 IP | DNSlog 记录到的解析来源 IP |

3. 右键：**复制回连域名** / **复制请求 URL** / **删除该行**
4. 工具栏：**暂停注入**（保留轮询，已注入的仍会继续匹配）、**清空记录**（只清本地表格，不动服务器）

**命中之后怎么用**：把那一行的 URL 拿到 Repeater，只保留被命中的那个 Header 再发一次，确认确实是它触发的；
确认后即可把它当作 SSRF / XXE / RCE 的入口继续利用。

> 注意：表格是**回连命中表**，不是注入日志。浏览普通页面（没有回连行为）时表格为空是正常的，
> 此时请看状态栏的「注入」计数与「当前跳过」原因。

## 与 Collaborator Everywhere 对比

|  | Collaborator Everywhere | DNSlog Everywhere |
|---|---|---|
| 需要的 Burp 版本 | Pro（Collaborator） | Community / Pro 均可 |
| 回连后端 | Burp Collaborator | 自建 DNSlog-GO（或兼容 API） |
| 数据出境 | 走 PortSwigger 服务器 | 只走你自己的服务器 |
| 关联粒度 | 请求 + 注入点 | 请求 + Header（ID 精确到单个头） |
| 参数注入 | 支持 | 支持（可选开关） |
| 独立 UI | 无（写进 issue / 日志） | 有独立 Tab + 表格 |

## 自测（不依赖任何靶场）

`tools/loopback-test.ps1` 会在本机起一个回环 HTTP 服务器：接收 Burp 转发来的请求、打印注入的头、
并**真实解析**注入的域名（从而让 DNSlog 面板立刻收到记录）。

```powershell
powershell -ExecutionPolicy Bypass -File tools\loopback-test.ps1 -DnsSuffix dnslog.example.com
```

1. 浏览器代理指向 Burp
2. 访问 `http://127.0.0.1:8888/anything`
3. 脚本窗口会打印 `注入域名: xxxx.dnslog.example.com` 与解析结果
4. 等一个轮询周期，扩展表格应出现对应行

需要 PowerShell 5.1+，脚本请以 **UTF-8 with BOM** 保存（否则 5.1 会按 ANSI 读取中文注释而报错）。

## 从源码构建

只需要 JDK 17+ 和一个 Burp / Montoya API jar（**不需要**完整 Burp 安装，独立的 `montoya-api.jar` 也行）：

```powershell
# Windows
.\build.ps1 -BurpJar 'C:\path\to\burpsuite_pro.jar' -JavaHome 'C:\Program Files\Java\jdk-21'
```

```bash
# Linux / macOS
BURP_JAR=/path/to/burpsuite_pro.jar ./build.sh
```

也可以把 jar 放进 `lib/`，或设置环境变量 `BURP_JAR`，脚本会自动寻找。
产物输出到 `dist/dnslog-everywhere.jar`。

> 独立 API jar 可从 Maven Central 获取：
> `https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/`

## 目录结构

```
.
├── build.ps1                  # Windows 构建脚本
├── build.sh                   # Linux / macOS 构建脚本
├── dist/
│   └── dnslog-everywhere.jar  # 构建产物（可直接安装）
├── docs/                      # 截图 / 演示（可选）
├── src/main/java/dnslogeverywhere/
│   ├── DnslogEverywhereExtension.java  # 入口：注册 Tab 与 HttpHandler
│   ├── InjectionHandler.java           # 注入逻辑（Header / 参数）
│   ├── DnslogClient.java               # DNSlog-GO API 客户端（含 Basic Auth）
│   ├── MiniJson.java                   # 自带 JSON 解析器（零依赖、容错）
│   ├── Store.java                      # ID → 命中 的内存关联表
│   ├── Hit.java                        # 单条注入记录
│   ├── Config.java                     # 配置 + 持久化
│   └── DnslogTab.java                  # Swing UI
└── tools/
    └── loopback-test.ps1      # 回环自测服务器
```

## 常见问题

**Q：装好了，浏览网页但表格一直是空的？**
表格只显示**回连命中**。先看状态栏：`注入` 是否在涨、`当前跳过：` 是否给出原因（未填 Token / 不在 Scope / 静态资源 / 已暂停）。
确认注入正常后，用 `tools/loopback-test.ps1` 做闭环验证。

**Q：手填到靶场里的域名在 DNSlog 面板有记录，但扩展表格没有？**
扩展只认**自己生成**的 ID（10 位 hex + 2 位序号）。手工填的域名不会出现在表格里，这是设计如此。

**Q：轮询失败 / 401？**
- `401` + 提示 token 无效 → 核对 token；若服务器有 Basic Auth，需填写账号密码
- `返回不是 JSON（可能是登录页或错误页）` → 地址填错，或反代返回了 HTML 登录页
- `PKIX path building failed` → HTTPS 证书不被 JDK 信任（自签证书），换受信任证书或给 Burp 的 JVM 指定 truststore

**Q：注入的域名解析到 `127.0.0.1`？**
这是 DNSlog-GO 的默认 A 记录，正常现象。能否被目标解析与 A 记录指向哪里无关，只与目标能否出网 DNS 有关。

**Q：会不会把 DNSlog 服务器自己也注入了？**
不会。扩展会跳过 URL 以配置的服务器地址开头的请求。

## 已知限制

- 目标**不出网**（内网隔离、DNS 不递归）时不会有任何记录
- 回连 ≠ 漏洞：WAF、CDN、邮件安全网关、杀软沙箱会主动抓取链接，需结合来源 IP 与行为判断
- 只对「服务端会消费该 Header」的场景有效（如 `X-Forwarded-Host` 被用于拼 URL、`Referer` 被用于抓取）
- 依赖 DNSlog-GO 的 API 结构；换成其它 DNSlog 服务需要小幅改动 `DnslogClient`

## 免责声明

本项目仅用于**已获授权的安全测试**、教学与研究。使用者应确保对被测目标拥有合法授权，
并遵守当地法律法规。因滥用造成的任何后果由使用者自行承担。

## 致谢

- [DNSlog-GO](https://github.com/lanyi1998/DNSlog-GO) —— 优秀的自建 DNSlog 服务
- PortSwigger 的 Collaborator Everywhere —— 本项目的灵感来源

## License

[MIT](LICENSE)
