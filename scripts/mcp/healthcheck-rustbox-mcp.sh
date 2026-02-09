#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SERVER_DIR="$REPO_ROOT/tools/rustbox-mcp"

if [[ ! -f "$SERVER_DIR/dist/server.js" ]]; then
  echo "[rustbox-mcp] missing build artifact: $SERVER_DIR/dist/server.js" >&2
  echo "[rustbox-mcp] run: cd tools/rustbox-mcp && npm install && npm run build" >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "[rustbox-mcp] node not found in PATH" >&2
  exit 1
fi

echo "[rustbox-mcp] smoke starting..."
timeout 8s bash -lc "cd '$SERVER_DIR' && RUSTBOX_ROOT='$REPO_ROOT' node dist/server.js >/dev/null 2> >(grep -m1 'ready:' >&2)"
echo "[rustbox-mcp] smoke ok"

