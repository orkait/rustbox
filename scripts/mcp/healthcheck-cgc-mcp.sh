#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CGC_BIN_DEFAULT="$REPO_ROOT/tools/codegraphcontext/.venv/bin/cgc"
CGC_BIN="${CGC_BIN:-$CGC_BIN_DEFAULT}"

if [[ ! -x "$CGC_BIN" ]]; then
  echo "[cgc-mcp] missing executable: $CGC_BIN" >&2
  echo "[cgc-mcp] run: ./scripts/bootstrap-mcp.sh" >&2
  exit 1
fi

echo "[cgc-mcp] version check..."
"$CGC_BIN" --version >/dev/null

echo "[cgc-mcp] mcp smoke starting..."
timeout 8s bash -lc "cd '$REPO_ROOT' && '$CGC_BIN' mcp start >/dev/null 2> >(grep -m1 -E 'mcp|server|listening|ready' >&2 || true)"
echo "[cgc-mcp] smoke ok"

