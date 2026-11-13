#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
mkdir -p bin
for T in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$T go build -trimpath -ldflags "-s -w" -o "bin/selfheal.$T" .
  echo "built: bin/selfheal.$T"
done