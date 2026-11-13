# disk-manager — IotaPanel 磁盘管理插件

极省内存的磁盘运维插件。以「常驻探针 + 按需唤醒主进程」双模式运行：探针空闲仅约 **5MB** 内存，只负责服务页面与转发；磁盘扫描、大文件检测、访问日志解析等重活在请求到来时由主进程执行，**空闲约 90 秒自动退出释放内存**。

## 功能

- 📊 **磁盘总览**：各挂载点 total / used / free / 使用率（自动排除 proc、sys 等伪文件系统）
- 📁 **目录占用排行**：并发扫描指定根目录，按占用大小降序 Top N
- 🗂️ **大文件检测**：全盘（或指定目录）体积最大的前 N 个文件
- 🕒 **文件访问统计**：自动探测 nginx / apache / 面板访问日志，按请求路径聚合「每个文件被访问了多少次」，支持路径过滤，条形图展示

## 架构：探针 + 主进程

```
面板网关 /p/disk-manager/*
        │
        ▼
  探针（常驻，≈5MB）    ◀── 只做页面 + 按需转发，不扫描
        │  收到 /api/* 请求时 exec 拉起主进程
        ▼
  主进程（同一二进制，IS_WORKER=1）
        │  执行磁盘扫描 / 日志解析
        └── 空闲 90s 自动退出，内存释放
```

核心机制（`main.go` `main()`）：

```go
func main() {
	if os.Getenv("IS_WORKER") == "1" {
		runWorker() // 主进程：重活 + 空闲自退
		return
	}
	runProbe() // 探针：极省内存，按需拉起主进程
}
```

- 探针与主进程为同一二进制，由环境变量 `IS_WORKER=1` 切换，兼容面板 `build.sh` 的一次性内嵌。
- 探针用 `net.Listen("127.0.0.1:0")` 取得空闲端口传给主进程，主进程监听成功后打印 `_READY_<port>` 就绪协议；探针据此确认转发可用后才反代。
- 空闲退出时长默认 90s，可用环境变量 `WORKER_IDLE` 覆盖（如 `30s` / `5m`）。

## 构建

```bash
./build.sh
# 产物: dist/disk-manager-<v>.tar.gz + .sha256
```

## 安装

方式一（URL / GitHub Release）：在面板「插件」页粘贴
`https://github.com/BCZZB/disk-manager/releases/latest/download/disk-manager-0.1.0.tar.gz`，并按需填写 SHA256。

方式二（拷贝即安装）：

```bash
tar xzf disk-manager-0.1.0.tar.gz
cp -r disk-manager /data/panel/plugins/
systemctl restart iotapanel   # 或 panel restart
```

安装后侧边栏出现「💾 磁盘管理」菜单。

## 独立调试

```bash
# 探针模式
PLUGIN_PORT=19004 ./disk-manager

# 主进程模式（模拟被唤醒）
IS_WORKER=1 WORKER_ADDR=127.0.0.1 WORKER_PORT=19200 ./disk-manager
```

## manifest

```yaml
name: disk-manager
title: 磁盘管理
version: 0.1.0
author: IotaPanel 社区
description: 磁盘容量总览、占用排行、大文件检测与文件访问次数统计
language: go
command: bin/disk-manager
bind: 127.0.0.1
keepalive: true
menus:
  - title: 磁盘管理
    icon: 💾
    path: /
    section: system
```

## 许可证

Apache License 2.0

Copyright © 2026 [BCZZB](https://github.com/BCZZB)。See [LICENSE](LICENSE).