#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUSTBOX_ROOT_DEFAULT="$REPO_ROOT"
export RUSTBOX_ROOT="${RUSTBOX_ROOT:-$RUSTBOX_ROOT_DEFAULT}"

CGC_BIN_DEFAULT="$RUSTBOX_ROOT/tools/codegraphcontext/.venv/bin/cgc"
CGC_BIN="${CGC_BIN:-$CGC_BIN_DEFAULT}"
DEFAULT_DATABASE="${DEFAULT_DATABASE:-falkordb}"
FALKORDB_SOCKET_PATH_DEFAULT="${HOME}/.codegraphcontext/falkordb.sock"
FALKORDB_SOCKET_PATH="${FALKORDB_SOCKET_PATH:-$FALKORDB_SOCKET_PATH_DEFAULT}"

if [[ ! -x "$CGC_BIN" ]]; then
  echo "[cgc-mcp] missing executable: $CGC_BIN" >&2
  echo "[cgc-mcp] run ./scripts/bootstrap-mcp.sh to provision tools/codegraphcontext/.venv" >&2
  exit 1
fi

# Recover from stale FalkorDB sockets left after interrupted sessions.
if [[ -S "$FALKORDB_SOCKET_PATH" ]] && ! pgrep -f "codegraphcontext.core.falkor_worker" >/dev/null 2>&1; then
  echo "[cgc-mcp] removing stale FalkorDB socket: $FALKORDB_SOCKET_PATH" >&2
  rm -f "$FALKORDB_SOCKET_PATH"
fi

cd "$RUSTBOX_ROOT"
export DEFAULT_DATABASE
export FALKORDB_SOCKET_PATH
exec "$CGC_BIN" mcp start
