# 插件目录

本目录收录 IotaPanel 核心内置插件与已合并的独立插件仓库。每个子目录都是一个可独立构建的插件，详细说明见各自目录下的 `README.md` 与 `manifest.yaml`。

| 目录 | 名称 | 来源 |
|------|------|------|
| `file-manager` | 文件管理 | 核心内置 |
| `resource-monitor` | 资源监控 | 核心内置 |
| `hello` | Hello 演示 | 核心内置 |
| `terminal` | 终端 | 核心内置 |
| `https-front` | HTTPS 网关 | 核心内置 |
| `mcp-agent` | MCP Agent | 核心内置 |
| `app-store` | Docker 管理器 | 原 `iotapanel-appstore` |
| `web-manager` | 网站管理 | 原 `iotapanel-web-manager` |
| `cf-tunnel` | Cloudflare Tunnel | 原 `iotapanel-cf-tunnel` |
| `ai-guardian` | AI 守护 | 原 `iotapanel-ai-guardian` |
| `waf` | 微盾 WAF | 原 `iotapanel-waf` |
| `performance-test` | 性能测试 | 原 `iotapanel-performance-test` |
| `selfheal` | 自愈守护 | 原 `iotapanel-selfheal` |
| `disk-manager` | 磁盘管理 | 原 `disk-manager` |

单独构建某个插件：

```bash
cd plugins/<名称>
go build -o /tmp/<名称> .
```

或使用各插件自带的 `build.sh` 生成发布包。
