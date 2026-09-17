#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=========================================="
echo "  go-responder test suite"
echo "=========================================="
echo

echo "[*] Building..."
go build ./...
echo "[+] Build OK"
echo

echo "[*] Running tests with verbose output..."
echo "------------------------------------------"
go test -count=1 -v -timeout 60s ./... 2>&1
echo "------------------------------------------"
echo

echo "[*] Coverage report..."
go test -count=1 -timeout 60s -coverprofile=/tmp/go-responder-coverage.out ./... 2>/dev/null
go tool cover -func=/tmp/go-responder-coverage.out
echo
echo "[*] Total:"
go tool cover -func=/tmp/go-responder-coverage.out | tail -1
