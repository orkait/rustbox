#!/usr/bin/env bash
# Shared test infrastructure for rustbox test runners.

PORT=4096
HOST="http://127.0.0.1:${PORT}"
SUBMIT="${HOST}/api/submit"
PAYLOAD_DIR=""
SVC_PID=""

# ── Colors ────────────────────────────────────────────────────────────────

red()    { printf "\033[1;31m%s\033[0m" "$*"; }
green()  { printf "\033[1;32m%s\033[0m" "$*"; }
yellow() { printf "\033[1;33m%s\033[0m" "$*"; }
dim()    { printf "\033[2m%s\033[0m" "$*"; }
bold()   { printf "\033[1m%s\033[0m" "$*"; }

# ── Counters ──────────────────────────────────────────────────────────────

_PASS=0
_FAIL=0
_SKIP=0
_TOTAL=0

# ── Cgroup bootstrap ─────────────────────────────────────────────────────

bootstrap_cgroups() {
    if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
        echo "FATAL: cgroup v2 not available"; exit 1
    fi
    mkdir -p /sys/fs/cgroup/init
    for pid in $(cat /sys/fs/cgroup/cgroup.procs 2>/dev/null); do
        echo "$pid" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true
    done
    echo "+memory +pids +cpu" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
    mkdir -p /sys/fs/cgroup/rustbox
    echo "+memory +pids +cpu" > /sys/fs/cgroup/rustbox/cgroup.subtree_control 2>/dev/null || true
}

# ── Service lifecycle ─────────────────────────────────────────────────────

start_service() {
    local workers=${1:-4}
    RUSTBOX_PORT=${PORT} \
    RUSTBOX_WORKERS=${workers} \
    RUSTBOX_DATABASE_URL="sqlite:///tmp/rustbox-test-$$.db" \
    RUST_LOG=error \
    judge-service >/dev/null 2>&1 &
    SVC_PID=$!

    for i in $(seq 1 30); do
        curl -sf "${HOST}/api/health/ready" >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    red "FATAL: judge-service not ready after 15s"; echo
    exit 1
}

stop_service() {
    [ -n "$SVC_PID" ] && kill $SVC_PID 2>/dev/null
    wait $SVC_PID 2>/dev/null || true
}

# Trap for clean shutdown on Ctrl+C
_cleanup() {
    echo
    yellow "Interrupted. Cleaning up..."; echo
    stop_service
    print_summary
    exit 1
}
trap _cleanup SIGINT SIGTERM

# ── Manifest loading ─────────────────────────────────────────────────────

load_manifest() {
    local manifest_file=$1

    if [ ! -f "$manifest_file" ]; then
        red "FATAL: manifest not found: $manifest_file"; echo
        exit 1
    fi

    # Validate JSON
    if ! python3 -c "import json; json.load(open('$manifest_file'))" 2>/dev/null; then
        red "FATAL: invalid JSON in $manifest_file"; echo
        exit 1
    fi

    # Validate required fields
    local errors
    errors=$(python3 -c "
import json, sys
m = json.load(open('$manifest_file'))
if 'tests' not in m:
    print('missing \"tests\" array')
    sys.exit(1)
for i, t in enumerate(m['tests']):
    for f in ['name', 'file', 'language', 'expect']:
        if f not in t:
            print(f'test[{i}] missing \"{f}\"')
" 2>&1)

    if [ -n "$errors" ]; then
        red "FATAL: manifest validation failed:"; echo
        echo "$errors"
        exit 1
    fi
}

get_test_count() {
    python3 -c "import json; print(len(json.load(open('$1'))['tests']))"
}

get_test_field() {
    local manifest=$1 index=$2 field=$3
    python3 -c "import json; t=json.load(open('$manifest'))['tests'][$index]; print(t.get('$field',''))"
}

get_test_expect() {
    local manifest=$1 index=$2
    python3 -c "import json; print(json.dumps(json.load(open('$manifest'))['tests'][$index]['expect']))"
}

# ── Submit and assert ─────────────────────────────────────────────────────

submit_code() {
    local language=$1 code_file=$2 timeout_sec=${3:-10} stdin_data=${4:-}

    if [ ! -f "$code_file" ]; then
        echo "PAYLOAD_MISSING"
        return
    fi

    if [ ! -s "$code_file" ]; then
        echo "PAYLOAD_EMPTY"
        return
    fi

    local code
    code=$(cat "$code_file")

    local payload
    payload=$(python3 -c "
import json, sys
code = open('$code_file').read()
d = {'language': '$language', 'code': code}
stdin = '''$stdin_data'''
if stdin:
    d['stdin'] = stdin
print(json.dumps(d))
")

    timeout "$timeout_sec" curl -sf --max-time "$timeout_sec" \
        -X POST "${SUBMIT}?wait=true" \
        -H 'Content-Type: application/json' \
        -d "$payload" 2>/dev/null || echo '{"status":"timeout","verdict":null}'
}

parse_field() {
    echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$2','') or '')" 2>/dev/null
}

assert_result() {
    local resp=$1 expect_json=$2 test_name=$3

    if [ -z "$resp" ] || [ "$resp" = "PAYLOAD_MISSING" ]; then
        red "  FAIL"; printf " [%s] payload file not found\n" "$test_name"
        return 1
    fi
    if [ "$resp" = "PAYLOAD_EMPTY" ]; then
        red "  FAIL"; printf " [%s] payload file is empty\n" "$test_name"
        return 1
    fi

    local verdict exit_code stdout signal
    verdict=$(parse_field "$resp" "verdict")
    exit_code=$(parse_field "$resp" "exit_code")
    stdout=$(parse_field "$resp" "stdout")
    signal=$(parse_field "$resp" "signal")

    local passed=true
    local reason=""

    # Check verdict
    local expect_verdict expect_verdict_any expect_verdict_not expect_stdout expect_exit
    expect_verdict=$(echo "$expect_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('verdict',''))" 2>/dev/null)
    expect_verdict_any=$(echo "$expect_json" | python3 -c "import sys,json; v=json.load(sys.stdin).get('verdict_any',[]); print(','.join(v) if v else '')" 2>/dev/null)
    expect_verdict_not=$(echo "$expect_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('verdict_not',''))" 2>/dev/null)
    expect_stdout=$(echo "$expect_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('stdout_contains',''))" 2>/dev/null)
    expect_exit=$(echo "$expect_json" | python3 -c "import sys,json; v=json.load(sys.stdin).get('exit_code',''); print(v if v != '' else '')" 2>/dev/null)

    if [ -n "$expect_verdict" ] && [ "$verdict" != "$expect_verdict" ]; then
        passed=false
        reason="verdict=$verdict expected=$expect_verdict"
    fi

    if [ -n "$expect_verdict_any" ]; then
        local found=false
        IFS=',' read -ra VALID <<< "$expect_verdict_any"
        for v in "${VALID[@]}"; do
            [ "$verdict" = "$v" ] && found=true
        done
        if ! $found; then
            passed=false
            reason="verdict=$verdict expected_any=[$expect_verdict_any]"
        fi
    fi

    if [ -n "$expect_verdict_not" ] && [ "$verdict" = "$expect_verdict_not" ]; then
        passed=false
        reason="verdict=$verdict must_not_be=$expect_verdict_not"
    fi

    if [ -n "$expect_stdout" ] && ! echo "$stdout" | grep -qF "$expect_stdout"; then
        passed=false
        reason="stdout missing '$expect_stdout'"
    fi

    if [ -n "$expect_exit" ] && [ "$exit_code" != "$expect_exit" ]; then
        passed=false
        reason="exit_code=$exit_code expected=$expect_exit"
    fi

    if $passed; then
        green "  PASS"; printf " [%s]  verdict=%s exit=%s signal=%s\n" "$test_name" "$verdict" "$exit_code" "$signal"
        return 0
    else
        red "  FAIL"; printf " [%s]  %s\n" "$test_name" "$reason"
        dim "        response: "; echo "$resp" | python3 -c "import sys,json; json.dump(json.load(sys.stdin),sys.stdout,indent=2)" 2>/dev/null; echo
        return 1
    fi
}

# ── Run manifest ──────────────────────────────────────────────────────────

run_manifest() {
    local manifest=$1

    load_manifest "$manifest"

    local suite_name
    suite_name=$(python3 -c "import json; print(json.load(open('$manifest')).get('name','Tests'))")
    local count
    count=$(get_test_count "$manifest")

    echo
    bold "━━━ $suite_name ($count tests) ━━━"; echo
    echo

    for idx in $(seq 0 $((count - 1))); do
        local name file language timeout_sec expect_json description
        name=$(get_test_field "$manifest" "$idx" "name")
        file=$(get_test_field "$manifest" "$idx" "file")
        language=$(get_test_field "$manifest" "$idx" "language")
        timeout_sec=$(get_test_field "$manifest" "$idx" "timeout_sec")
        expect_json=$(get_test_expect "$manifest" "$idx")
        description=$(get_test_field "$manifest" "$idx" "description")
        [ -z "$timeout_sec" ] && timeout_sec=10

        _TOTAL=$((_TOTAL + 1))
        local progress="[$_TOTAL/$((count + _TOTAL - _TOTAL))]"

        dim "  $progress $name"; [ -n "$description" ] && dim " - $description"; echo

        local code_file="${PAYLOAD_DIR}/${file}"
        local resp
        resp=$(submit_code "$language" "$code_file" "$timeout_sec")

        if assert_result "$resp" "$expect_json" "$name"; then
            _PASS=$((_PASS + 1))
        else
            _FAIL=$((_FAIL + 1))
        fi
    done
}

# ── Summary ───────────────────────────────────────────────────────────────

print_summary() {
    echo
    bold "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo
    printf "  Total: %d  |  " "$_TOTAL"
    green "PASS: $_PASS"; printf "  |  "
    if [ "$_FAIL" -eq 0 ]; then
        green "FAIL: 0"; echo
    else
        red "FAIL: $_FAIL"; echo
    fi
    echo
    if [ "$_FAIL" -eq 0 ]; then
        bold "VERDICT: "; green "ALL TESTS PASSED"; echo
    else
        bold "VERDICT: "; red "$_FAIL TESTS FAILED"; echo
    fi
    echo
}
