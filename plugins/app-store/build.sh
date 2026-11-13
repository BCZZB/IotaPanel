#!/usr/bin/env bash
# 构建 IotaPanel 软件商店插件
# 产物: bin/app-store (linux/amd64) + dist/iotapanel-appstore-<ver>-linux-amd64.tar.gz
set -euo pipefail
VERSION="$(grep '^version:' manifest.yaml | awk '{print $2}')"
OUT=bin/app-store
echo "==> 构建 app-store v${VERSION} (linux/amd64)"
mkdir -p bin dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$OUT" .
ls -lh "$OUT"
echo "==> 打包发布包"
tar -czf "dist/app-store-${VERSION}-linux-amd64.tar.gz" \
    --transform "s,^,app-store/," manifest.yaml bin/app-store
sha256sum "dist/app-store-${VERSION}-linux-amd64.tar.gz" > "dist/app-store-${VERSION}-linux-amd64.tar.gz.sha256"
ls -lh dist/
echo "✅ 构建完成。安装方式:"
echo "   1) 拷贝安装: 解压 app-store 目录到 <PANEL_HOME>/plugins/ 后重启面板"
echo "   2) 面板内安装: 插件页粘贴 tar.gz 直链(可选填 SHA256)"
