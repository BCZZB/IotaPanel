# IotaPanel 软件商店 (app-store)

参考 [XMP 星梦面板](https://github.com/defeatedperson/xmp-v1-v2) 软件商店设计、适配 [IotaPanel](https://github.com/plainfate/IotaPanel) 插件规范的 Docker 应用商店插件。

## 特性

- **低占用**:纯 Go 标准库单二进制(约 7MB),零第三方依赖,常驻内存约 5MB,空闲自动退出(随面板 `IDLE_TIMEOUT`)
- **分类浏览**:建站工具 / 运行环境 / 网盘存储 / 运维管理 / 多媒体 / 实用工具 / AI 助手
- **一键部署**:选择版本 → 自定义实例名、端口映射、数据卷、环境变量 → `docker run` 拉起
- **容器管理**:启动 / 停止 / 重启 / 删除、实时日志查看
- **商店源自定义**:支持从任意 URL 拉取 `store.json`(兼容 XMP 格式),内置 19 个常用应用
- **安全默认**:容器加 `io.iotapanel.appstore=1` 标签隔离管理范围;`--restart unless-stopped` 崩溃自愈;相对路径数据卷存放在 `<PANEL_HOME>/data/volumes/` 下

## 安装

### 方式一:面板内安装(推荐)

IotaPanel → 插件页 → 从 URL 安装,粘贴 Release 包直链(可附 SHA256)。

### 方式二:拷贝即安装

```bash
# 下载发布包后
tar xzf app-store-<version>-linux-amd64.tar.gz
cp -r app-store /data/panel/plugins/
# 重启面板后在侧边栏出现「软件商店 🛍️」
```

### 方式三:源码构建

```bash
./build.sh   # 需要 Go 1.25+
```

## 使用前提

插件通过 Docker CLI 部署应用,宿主机需安装并运行 Docker:

```bash
# Alpine
apk add docker && rc-update add docker boot && service docker start
# Debian / Ubuntu
curl -fsSL https://get.docker.com | sh
```

## store.json 格式

```json
{
  "version": "1.0",
  "types": [{ "id": "1", "name": "建站工具" }],
  "apps": [{
    "id": "wordpress",
    "name": "WordPress",
    "icon": "📝",
    "description": "全球最流行的开源博客和内容管理系统",
    "typeId": "1",
    "versions": [{
      "version": "6.9.0",
      "image": "wordpress:6.9.0-php8.3-apache",
      "network": "bridge",
      "ports": [{ "host": "8080", "container": "80" }],
      "volumes": [{ "host": "/srv/wordpress/html", "container": "/var/www/html" }],
      "env": [{ "name": "TZ", "value": "Asia/Shanghai" }]
    }]
  }]
}
```

在商店页面「刷新源」传入自定义 `store.json` 的 URL 即可扩展应用目录(缓存在 `<PANEL_HOME>/data/store-remote.json`)。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | Docker 状态与商店统计 |
| GET | `/api/store` | 商店目录(含安装状态) |
| GET | `/api/meta` | 商店源信息 |
| GET | `/api/refresh?url=` | 更新/恢复商店源 |
| POST | `/api/crawl` | 一键爬取全网镜像仓库(Docker 官方镜像库/LinuxServer/Hotio/Quay) |
| GET | `/api/installed` | 已部署容器列表 |
| POST | `/api/deploy` | 一键部署 |
| POST | `/api/action` | start / stop / restart / remove |
| GET | `/api/logs?name=` | 容器日志 |

## 一键爬取全网镜像

点击「🌐 爬取全网镜像」按钮,后端并发从四个仓库抓取并自动合并(去重):

| 源 | 内容 | 规模 |
|---|---|---|
| docker-library/official-images | Docker 官方镜像库(含版本标签) | ~140 |
| GitHub org linuxserver | LinuxServer 自托管全家桶 | ~290 |
| GitHub org hotio | Hotio 热门自托管应用 | ~30 |
| quay.io 热门 API | Quay.io 公共仓库 | ~30 |

由于 Docker Hub 主站 API 在国内被 DNS 污染 + IP 阻断,爬取全部走 GitHub/Quay 可达通道,结果缓存于 `<PANEL_HOME>/data/store-crawled.json`。爬取到的镜像会智能归类(数据库/媒体/监控等 7 类 + 热门镜像),自动猜测默认端口,知名应用自动配 Logo(加载失败回退 emoji)。

## 致谢

- [IotaPanel](https://github.com/plainfate/IotaPanel) — 微内核面板框架(Apache-2.0)
- [XMP 星梦面板 v1/v2](https://github.com/defeatedperson/xmp-v1-v2) — 软件商店交互与 `store.json` 数据格式参考(Apache-2.0)

## License

Apache-2.0
