#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/lib.sh"

bootstrap_cgroups
start_service 12

# Warmup
curl -sf --max-time 30 -X POST "${SUBMIT}?wait=true" \
    -H 'Content-Type: application/json' \
    -d '{"language":"python","code":"print(1)"}' >/dev/null

PAYLOAD_FILE="$TESTS_DIR/payloads/correctness/sieve_500k.py" \
HOST="http://127.0.0.1:${PORT}" \
    python3 "$SCRIPT_DIR/stress.py"

stop_service
