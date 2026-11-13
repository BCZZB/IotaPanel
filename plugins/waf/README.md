# 微盾 WAF —— IotaPanel 的雷池式轻量 WAF 插件

对标雷池（SafeLine）社区版防护能力的轻量 WAF，核心哲学与 IotaPanel 微内核一脉相承：
**平时只留一个低占用探针，检测到威胁再开启全量防护，威胁平息自动降级。**

纯 Go 标准库实现，零第三方依赖，单二进制约 7 MB，探针模式常驻内存约 13 MB。

## 架构：双态引擎

```text
┌────────────── 探针模式（平时，低占用）──────────────┐
│ 纯 TCP 直通：偷看首个数据块（≤8KB），不解析 HTTP    │
│ · Host 字节扫描路由（通配域名匹配）                 │
│ · IP 黑名单（一次查表，黑名单探针态同样生效）       │
│ · 每 IP 令牌桶计数（O(1)，CC 阈值判定）             │
│ · 字面量特征集（大小写折叠 + 一层 URL 解码）        │
│ 干净流量 → io.Copy 双向直通，零 HTTP 解析零正则     │
└──────────────────────┬─────────────────────────────┘
    特征命中 / 频率超限 / 全局连接速率异常
┌──────────────────────▼─────────────────────────────┐
│ 防护模式（攻击期，全量检测）                         │
│ 完整 HTTP 解析 + 3 层深度解码变体（URL/HTML/\u）    │
│ 15 组内置规则（79 条，RE2 线性时间）+ 自定义规则     │
│ CC 防护 + PoW 人机验证（浏览器毫秒级，爬虫卡死）    │
│ URL 频率限制 / 404 封禁 / HTTP 方法白名单            │
│ 威胁情报信誉黑名单 + 拦截 / 观察 + 事件日志 + 自动拉黑 │
└──────────────────────┬─────────────────────────────┘
    无威胁持续 calm_secs 秒 → 自动降级回探针
```

## 防护能力（对标雷池社区版能力面）

| 能力 | 说明 |
|---|---|
| SQL 注入 | UNION/布尔/延时/报错注入、堆叠查询、注释绕过（12 条） |
| XSS | 脚本标签、事件属性、伪协议、敏感 DOM、data URI（10 条） |
| 命令注入 | 命令拼接、`$()`/反引号替换、反弹 Shell、破坏性命令（7 条） |
| 路径穿越 | `../` 序列、系统敏感文件、编码绕过（5 条） |
| 文件包含 | PHP 伪协议、`php://filter` 源码读取（2 条） |
| WebShell | 一句话木马、加密 Shell、已知家族特征（6 条，检测请求体） |
| 扫描器识别 | sqlmap/nikto/nuclei 等 20+ 工具 UA 特征（2 条） |
| 敏感文件 | `.env`/`.git`/私钥/备份文件/管理入口探测（8 条） |
| XXE | 外部实体定义与引用（2 条，检测请求体） |
| 反序列化 | Java `rO0AB`/PHP 序列化/利用链（3 条） |
| SSRF | 云元数据接口、内网回环地址（2 条） |
| CRLF | 响应拆分/头注入（1 条） |
| 协议异常 | Content-Length 非数字、请求走私、NUL 空字节（CRS 920160,5 条） |
| 文件上传限制 | 危险脚本/敏感配置扩展名上传拦截（2 条） |
| LDAP 注入 | 过滤器通配/布尔拼接、编码绕过（3 条） |
| CC 防护 | 令牌桶滑动限速 + PoW 人机验证 + 可选直接拦截 |
| URL 频率限制 | 每「IP+URL」令牌桶限速，超限 429 或临时封禁（1Panel「URL 模式」） |
| 404 封禁 | 反复访问不存在资源 → 达标封 IP（1Panel「404 频率限制」） |
| HTTP 方法白名单 | 仅放行给定方法集（1Panel「HTTP 规则」） |
| 威胁情报 | 定时拉取 CrowdSec 社区块表 / 恶意 IP 组，信誉命中直接拦截 |
| IP 名单 | 黑白名单（单 IP + CIDR），支持自动拉黑（按阈值与时长） |

深度解码：对每个检测字段生成「原始 / 多层解码 / SQL 归一化」变体，
`union/**/select`、`%3Cscript%3E`、`&#x6a;avascript` 等混淆全部现形。

## 融合来源（择优整合的开源/主流方案）

| 来源 | 吸收的能力 |
|---|---|
| [OWASP ModSecurity CRS](https://github.com/coreruleset/coreruleset) | 协议异常/请求走私规则、LDAP 注入、SQL/XSS/命令注入深度扩充（920160 等） |
| [CrowdSec](https://github.com/crowdsec/crowdsec) | 社区威胁情报信誉源（FireHOL 等文本块表，按 IP 信誉实时拉黑） |
| [1Panel](https://github.com/1Panel-dev/1Panel) 防火墙 | 「URL 模式」访问频率、404 频率封禁、HTTP 方法白名单、恶意 IP 组、文件上传扩展名限制 |
| [雷池 SafeLine](https://github.com/chaitin/safeline) | 探针-防护双态引擎、保护站点、人机验证的总体设计哲学 |

## 安装

### 方式一：放入 IotaPanel 插件目录

```bash
# 1. 构建（需 Go 1.22+）
cd waf && go build -trimpath -ldflags="-s -w" -o bin/waf .

# 2. 复制到面板插件目录
cp -r waf/ <PANEL_HOME>/plugins/waf/   # manifest.yaml + bin/waf

# 3. 面板「插件管理」中安装/启动；或重新构建面板将其内嵌：
#    编辑 IotaPanel/build.sh 的 PLUGINS 列表加入 waf
```

面板通过侧边栏「微盾 WAF」进入管理页（`/p/waf/`）。

### 方式二：独立运行（脱离面板调试）

```bash
PANEL_HOME=/data/panel PLUGIN_PORT=19006 ./bin/waf
# 流量入口默认 :8080（config.json 可改），管理页 http://127.0.0.1:19006/
```

## 配置

配置文件：`$PANEL_HOME/etc/waf/config.json`（管理页保存后自动写回并热更新）。

```jsonc
{
  "http_entry": ":8080",        // 对外 HTTP 入口
  "https_entry": "",            // 对外 HTTPS 入口（可留空；站点可配证书，未配则自签兜底）
  "calm_secs": 300,             // 防护模式无威胁多久后降级回探针
  "body_max": 1048576,          // 请求体检测上限（字节）
  "escalate_conns_per_min": 600,// 全局连接速率升级阈值（DoS 信号）
  "sites": [{
    "id": "site_default",
    "domains": ["example.com", "*.example.com"],  // 支持通配与 * 兜底
    "backends": ["127.0.0.1:8081"],               // 多上游自动轮询
    "mode": "block"              // off | monitor | block
  }],
  "cc": {
    "enabled": true, "capacity": 120, "window": 60,
    "action": "challenge",       // challenge 人机验证 | block 直接拦截
    "pow_bits": 16, "verify_secs": 1800
  },
  "auto_ban": { "enabled": false, "threshold": 5, "window": 120, "minutes": 10 },
  "url_rate": { "enabled": true, "capacity": 300, "window": 60, "ban_secs": 0 },
  "not_found": { "enabled": true, "capacity": 100, "window": 60, "ban_secs": 300 },
  "http_methods": ["GET", "POST", "HEAD", "PUT", "OPTIONS"], // 空=不限
  "threat_feeds": [
    { "name": "firehol_level1", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "interval_min": 60 }
  ]
}
```

## 管理 REST API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/health` | 存活探测 |
| GET | `/api/status` | 当前模式、防护剩余秒数、统计快照（QPS/拦截/RSS/Top 榜） |
| GET/POST | `/api/config` | 读取/保存配置（校验 + 落盘 + 热更新，无需重启） |
| GET | `/api/rules` | 15 组内置规则清单 |
| GET | `/api/events` | 事件流（`?n=100&kind=block&q=关键字`） |
| POST | `/api/mode` | 手动切换 `{"mode":"guard"|"probe"}` |
| POST | `/api/stats/reset` | 清零统计 |
| POST | `/api/ip` | 快捷增删 IP 名单 |

事件同时持久化到 `$PANEL_HOME/etc/waf/events.jsonl`（异步写入，超 5MB 自动轮转）。

## 人机验证（Anti-Bot Challenge）

超频客户端收到 429 挑战页，浏览器 JS 求解工作量证明：
找到 `n` 使 `fnv1a(nonce + ":" + n)` 的低 `pow_bits` 位全 0（16 位难度实测约 60ms），
随后写入 Cookie `nonce.n.expiry.HMAC(nonce|expiry|ip)`。
服务端无状态校验：PoW 位 + HMAC 签名 + 有效期 + IP 绑定——
不执行 JS 的爬虫/洪水工具被卡住，且每次求解都有真实 CPU 成本。

## 实测数据（本仓库沙箱）

- 攻击样本：SQLi（含 `+` 号编码/延时/报错/堆叠）、XSS（标签/事件/伪协议）、路径穿越、
  `.git`/`.env` 探测、sqlmap/nikto UA、WebShell 上传、XXE、SSRF 元数据、CRLF —— **16/16 全部拦截**
- 正常流量（页面/查询参数/登录表单）—— **零误拦，探针直通**
- CC：120 请求内放行，超限触发挑战；正确 PoW 放行，伪造签名持续拒绝
- 双态切换：特征命中自动升级，`calm_secs` 后自动降级（事件日志可追溯）
- 探针模式常驻 **13.2 MB RSS**，转发 P50 **0.2ms**

## 文件结构

```text
waf/
├── manifest.yaml   # IotaPanel 插件清单
├── main.go         # 入口：环境变量接线、管理服务、优雅退出
├── engine.go       # 双态引擎：探针快速路径 / 防护管线注入 / 状态机 / TLS
├── proxy.go        # 防护检测管线、反向代理、拦截页/挑战页
├── rules.go        # 15 组 79 条内置规则 + 自定义规则编译
├── decode.go       # 深度解码与归一化（变体生成）
├── defense.go      # 威胁情报拉取、蜘蛛识别、HTTP 方法校验
├── ratelimit.go    # 令牌桶 CC、URL 频率、404 封禁、IP 名单（CIDR）、自动拉黑、PoW 挑战
├── logs.go         # 事件环形缓冲 + 异步 JSONL 落盘 + 统计
├── store.go        # 配置原子持久化 + HMAC 密钥
├── api.go          # 管理 REST API
└── web/index.html  # 管理界面（单文件，无前端依赖）
```

## 与雷池的取舍

雷池是独立的反代 + 检测引擎集群（tengine + 语义分析 docker 栈），功能全面但资源占用高；
微盾把同一套防护思路压缩进 IotaPanel 的单进程插件模型：
以「探针 + 按需升级」换取常驻占用极低，以 RE2 规则 + 深度解码变体替代完整语义分析引擎。
适合小型服务器上「有总比没有强」的常态防护，不建议替代金融级 WAF。

## 许可证

Apache-2.0
