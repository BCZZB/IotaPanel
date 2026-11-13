#!/bin/sh
# 构建 AI 守护插件 (Linux amd64, 静态单二进制)
set -e
cd "$(dirname "$0")"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/ai-guardian .
echo "OK: bin/ai-guardian"
