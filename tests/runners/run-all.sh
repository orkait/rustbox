#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/lib.sh"
PAYLOAD_DIR="$TESTS_DIR/payloads"

bootstrap_cgroups
start_service 4

# Warmup
curl -sf --max-time 30 -X POST "${SUBMIT}?wait=true" \
    -H 'Content-Type: application/json' \
    -d '{"language":"python","code":"print(1)"}' >/dev/null

# Run all manifests
for manifest in "$TESTS_DIR"/manifests/*.json; do
    run_manifest "$manifest"
done

stop_service
print_summary
exit $_FAIL
