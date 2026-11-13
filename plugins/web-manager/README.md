# web-manager 网站管理插件

宝塔风格的网站管理插件，为 [IotaPanel](https://github.com/plainfate/IotaPanel) 打造。
纯 Go 标准库零依赖，单进程双角色（管理界面 + Web 服务器），常驻内存约 **10-15MB**。

## 功能

| 功能 | 说明 |
|---|---|
| 网站管理 | 添加 / 删除 / 启动 / 停止，中文站点名自动生成 ID |
| 多域名虚拟主机 | 按 Host 路由，支持 `*.example.com` 泛域名，域名全局唯一性校验 |
| 静态站点 | 默认文档、目录浏览开关、Range/断点续传、ETag |
| 反向代理 | 转发到任意 http/https 上游，透传 X-Forwarded-*，支持流式与 WebSocket |
| SSL 证书 | 粘贴 PEM 即启用，SNI 多证书、证书/私钥配对校验、到期天数提醒 |
| 强制 HTTPS | 一键 301 跳转 |
| IP 黑名单 | 按 IP / CIDR 拦截（只认直连地址，不信任可伪造头） |
| 访问统计 | 每站点请求数 / 流量，60 秒防抖落盘，重启不丢 |
| 端口热切换 | HTTP / HTTPS 监听端口在线修改，无需重启进程 |

## 安全设计

- **CSRF 三层防护**：面板网关注入的 `X-Panel-Plugin` 标记校验 / Origin 同源校验 / 回环放行
- **路径穿越防护**：URL 路径归一化折叠 `..`，双重编码无效
- **符号链接逃逸防护**：`EvalSymlinks` 解析后强制前缀校验，站点内软链无法逃出根目录
- **输入校验**：域名 / 端口 / 上游地址 / 站点目录 / 默认文档 / IP 黑名单全部白名单校验；JSON 严格解析（未知字段拒绝）
- **系统禁区**：`/proc` `/sys` `/dev` `/run` 禁止作为站点根目录
- **速率限制**：管理接口按 IP 令牌桶（5 req/s，突发 30）
- **审计日志**：所有管理操作记录来源 IP，输出到面板插件日志
- **证书私钥**：0600 权限独立目录存放，上传时先验证配对再落盘
- **删除安全**：仅清理沙箱内站点目录，绝不递归删除用户自定义路径

## 安装

```bash
# 方式一：面板「插件」页粘贴安装包 URL（推荐，可填 SHA256 校验）
# 方式二：手动拷贝
scp -r web-manager root@server:/data/panel/plugins/
# 然后在面板重启插件目录或重启面板，侧边栏出现「网站管理」菜单
```

安装包内含 `manifest.yaml` 与 `bin/web-manager`（入口二进制），顶层目录名必须为 `web-manager`。

## 使用

1. 面板侧边栏点击「网站管理」（首次由面板冷启动，约 1 秒）。
2. 点「添加网站」：填写域名（每行一个）、选择静态站点或反向代理。
3. 静态站点默认目录：`<面板目录>/data/web-manager/sites/<站点ID>/htdocs/`，可改为任意绝对路径。
4. 需要公网 80/443 之外的端口（如服务器已有 Nginx 占用 80），点「端口设置」修改。
5. SSL：站点设置 → SSL 证书 → 粘贴证书与私钥 PEM → 保存即启用（SNI）。

## 数据位置

```text
<PANEL_HOME>/etc/web-manager/
├── config.json          # 端口配置（原子写盘）
├── sites.json           # 站点定义 + 统计快照（.bak 自动回退）
├── fallback-cert.pem    # 兜底自签证书（无 SNI 匹配时使用）
├── fallback-key.pem
└── certs/<站点ID>/      # 各站点 SSL 证书（0600）
<PANEL_HOME>/data/web-manager/sites/<站点ID>/htdocs/   # 默认站点根目录
```

## 开发调试（不经面板独立运行）

```bash
cd web-manager
PLUGIN_PORT=19100 PANEL_HOME=/tmp/wm-dev ./bin/web-manager
# 管理界面 http://127.0.0.1:19100/ ，站点服务默认 0.0.0.0:80 + :443
```

源码构建（Go 1.25+）：

```bash
go build -trimpath -ldflags="-s -w" -o bin/web-manager .
```

## 注意事项

- 插件 `keepalive: true` 常驻（它本身就是 Web 服务器，站点需要 7x24 在线）。
- 站点服务监听 `0.0.0.0`，请确保防火墙/安全组放行对应端口。
- 与已有 Nginx 共存时：改用 8080/8443 等端口，或在 Nginx 反代到本插件端口。
- 面板以 root 运行，插件拥有同等权限：只部署可信配置。

## License

Apache-2.0
