#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/lib.sh"
PAYLOAD_DIR="$TESTS_DIR/payloads"

bootstrap_cgroups
start_service 4

run_manifest "$TESTS_DIR/manifests/correctness.json"

stop_service
print_summary
exit $_FAIL
