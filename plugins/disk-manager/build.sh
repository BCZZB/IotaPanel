#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# IotaPanel 磁盘管理插件构建脚本
# 产出:
#   dist/disk-manager-<ver>-linux-amd64.tar.gz   x86_64 分发包
#   dist/disk-manager-<ver>-linux-arm64.tar.gz   aarch64 分发包
#   dist/disk-manager-<ver>-linux-<arch>.tar.gz.sha256
# 说明:
#   CGO_ENABLED=0 强制静态链接，musl/精简系统可直接运行；
#   单二进制内嵌前端（go:embed），包内仅 manifest.yaml + bin/ + web/。
set -euo pipefail
cd "$(dirname "$0")"
GO="${GO:-go}"
VERSION="${VERSION:-0.2.0}"
OUT=dist
ARCHS="${ARCHS:-amd64 arm64}"

rm -rf "$OUT"
mkdir -p "$OUT"

for ARCH in $ARCHS; do
  PKG="$OUT/pkg-$ARCH/disk-manager"
  echo "[$ARCH] 编译插件二进制…"
  mkdir -p "$PKG/bin"
  CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" "$GO" build \
    -trimpath -ldflags="-s -w" -o "$PKG/bin/disk-manager" .
  cp manifest.yaml "$PKG/manifest.yaml"
  cp -r web "$PKG/web"
  TARBALL="$OUT/disk-manager-$VERSION-linux-$ARCH.tar.gz"
  echo "[$ARCH] 打包 $TARBALL…"
  tar czf "$TARBALL" -C "$OUT/pkg-$ARCH" disk-manager
  (cd "$OUT" && sha256sum "disk-manager-$VERSION-linux-$ARCH.tar.gz" > "disk-manager-$VERSION-linux-$ARCH.tar.gz.sha256")
  rm -rf "$OUT/pkg-$ARCH"
  echo "[$ARCH] SHA256: $(cut -d' ' -f1 "$TARBALL.sha256")"
done

echo "完成。产物列表:"
ls -la "$OUT"
