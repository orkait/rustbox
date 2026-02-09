#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CGC_VENV="${CGC_VENV:-$REPO_ROOT/tools/codegraphcontext/.venv}"

require_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required command: ${cmd}" >&2
    exit 1
  fi
}

require_cmd git
require_cmd python3
require_cmd node
require_cmd npm

echo "[1/4] Initializing CodeGraphContext submodule..."
git -C "${REPO_ROOT}" submodule sync --recursive
git -C "${REPO_ROOT}" submodule update --init --recursive tools/codegraphcontext

echo "[2/4] Installing submodule-backed CGC runtime in ${CGC_VENV}..."
python3 -m venv "${CGC_VENV}"
source "${CGC_VENV}/bin/activate"
python -m pip install --upgrade pip
python -m pip install -e "${REPO_ROOT}/tools/codegraphcontext"

echo "[3/4] Installing and building rustbox-mcp..."
pushd "${REPO_ROOT}/tools/rustbox-mcp" >/dev/null
npm install
npm run build
popd >/dev/null

echo "[4/4] Running quick checks..."
"${CGC_VENV}/bin/cgc" version >/dev/null 2>&1
CGC_SOCKET_PATH="${FALKORDB_SOCKET_PATH:-$HOME/.codegraphcontext/falkordb.sock}"
if [[ -S "$CGC_SOCKET_PATH" ]] && ! pgrep -f "codegraphcontext.core.falkor_worker" >/dev/null 2>&1; then
  rm -f "$CGC_SOCKET_PATH"
fi
timeout 90 env DEFAULT_DATABASE=falkordb "${CGC_VENV}/bin/cgc" mcp tools >/dev/null 2>&1
pushd "${REPO_ROOT}/tools/rustbox-mcp" >/dev/null
RUSTBOX_ROOT="${REPO_ROOT}" npm run smoke >/dev/null 2>&1
popd >/dev/null

echo
echo "MCP bootstrap complete."
echo "CGC venv: ${CGC_VENV}"
echo "Submodule commit: $(git -C "${REPO_ROOT}/tools/codegraphcontext" rev-parse --short HEAD)"
echo "Restart Kiro/Codex to reload MCP servers."
