# IotaPanel 自愈守护插件 (selfheal)

攻击熔断与自动拉起 + WAF 内存自愈守护插件，适用于 IotaPanel 面板。

## 功能

- **攻击熔断 + 自动拉起**：当 WAF 检测到被攻击（攻击速度 / 攻击量达到阈值，或处于 guard/block 防护态）并持续超过设定秒数后，自动关闭内网穿透 (`cf-tunnel`) 与网站 (`web-manager`)；再经过指定秒数后自动拉起恢复。
- **WAF 内存自愈**：当 WAF 进程内存占用超过阈值（默认 20MB）且当前无攻击时，自动重启 WAF 释放内存。
- **可视化设置页**：面板内一键开启/关闭，所有阈值与秒数均可调，实时展示 WAF QPS / 拦截量 / 内存与当前熔断状态。

## 技术特点

- 纯 Go 编写，零第三方依赖，常驻约 5MB。
- 通过面板管理 API (`/api/plugins/<name>/start|stop|restart`) 控制插件，可适配不同面板环境。
- 配置持久化到 `$PANEL_HOME/data/selfheal/config.json`。

## 本地构建

```bash
# 需安装 Go 1.22+
./build.sh    # 交叉编译 amd64 / arm64，产物输出到 bin/
```

## 目录结构

```
.
├── main.go       # 入口：HTTP 服务、配置加载/保存、接口
├── heal.go       # 核心巡检逻辑：攻击判定、熔断、内存自愈
├── manifest.yaml # IotaPanel 插件清单
├── build.sh      # 交叉编译脚本
└── web/
    └── index.html # 设置页界面
```

## 许可证

Apache-2.0