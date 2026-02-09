#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUSTBOX_ROOT_DEFAULT="$REPO_ROOT"
export RUSTBOX_ROOT="${RUSTBOX_ROOT:-$RUSTBOX_ROOT_DEFAULT}"

cd "$REPO_ROOT/tools/rustbox-mcp"
exec node dist/server.js
