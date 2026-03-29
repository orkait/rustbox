#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Rustbox concurrency stress test
# Submits N jobs async to judge-service, lets the queue drain, polls results.
# ============================================================================

PORT=4096
HOST="http://127.0.0.1:${PORT}"
SUBMIT="${HOST}/api/submit"
RESULT="${HOST}/api/result"
TIERS=(1 5 10 25 50)
PAYLOAD_FILE="${PAYLOAD_FILE:-/opt/rustbox-tests/payloads/correctness/sieve_500k.py}"
EXPECTED="41538"
POLL_INTERVAL=0.05
POLL_TIMEOUT=300

# ── helpers ──────────────────────────────────────────────────────────────────

red()   { printf "\033[1;31m%s\033[0m" "$*"; }
green() { printf "\033[1;32m%s\033[0m" "$*"; }
bold()  { printf "\033[1m%s\033[0m" "$*"; }
log()   { echo "$(date +%H:%M:%S) $*"; }

PAYLOAD=""
build_payload() {
    if [ ! -f "$PAYLOAD_FILE" ]; then
        echo "FATAL: payload file not found: $PAYLOAD_FILE"; exit 1
    fi
    PAYLOAD=$(python3 -c "
import json
code = open('$PAYLOAD_FILE').read()
print(json.dumps({'language':'python','code':code}))
")
}

submit_one() {
    curl -sf --max-time 10 -X POST "${SUBMIT}" \
        -H 'Content-Type: application/json' \
        -d "$PAYLOAD" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null
}

poll_result() {
    local id=$1
    curl -sf --max-time 5 "${RESULT}/${id}" 2>/dev/null
}

# ── cgroup v2 bootstrap ─────────────────────────────────────────────────────

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
    log "cgroup v2: controllers=$(cat /sys/fs/cgroup/rustbox/cgroup.subtree_control 2>/dev/null || echo none)"
}

# ── run one tier ─────────────────────────────────────────────────────────────

run_tier() {
    local n=$1
    local ids=()
    local t0 t1

    t0=$(date +%s%N)

    # Submit all N jobs
    for i in $(seq 1 "$n"); do
        local id
        id=$(submit_one) || true
        if [ -n "$id" ]; then
            ids+=("$id")
        fi
    done

    local submitted=${#ids[@]}
    local submit_elapsed=$(( ($(date +%s%N) - t0) / 1000000 ))

    # Poll until all done or timeout
    local ok=0 ac=0 re=0 tle=0 ie=0 pending=$submitted wrong=0 submit_fail=$((n - submitted))
    local wall_sum=0 wall_max=0
    local deadline=$(( $(date +%s) + POLL_TIMEOUT ))

    while [ "$pending" -gt 0 ] && [ "$(date +%s)" -lt "$deadline" ]; do
        sleep "$POLL_INTERVAL"
        local still_pending=0

        for idx in "${!ids[@]}"; do
            local id="${ids[$idx]}"
            [ -z "$id" ] && continue

            local resp status
            resp=$(poll_result "$id" 2>/dev/null) || continue
            status=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")

            if [ "$status" = "completed" ] || [ "$status" = "error" ]; then
                local verdict stdout wall_ms
                verdict=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('verdict','?'))" 2>/dev/null || echo "?")
                stdout=$(echo "$resp" | python3 -c "import sys,json; print((json.load(sys.stdin).get('stdout','') or '').strip())" 2>/dev/null || echo "")
                wall_ms=$(echo "$resp" | python3 -c "import sys,json; print(int(float(json.load(sys.stdin).get('wall_time',0))*1000))" 2>/dev/null || echo 0)

                wall_sum=$((wall_sum + wall_ms))
                [ "$wall_ms" -gt "$wall_max" ] && wall_max=$wall_ms

                case "$verdict" in
                    AC) ac=$((ac + 1))
                        [ "$stdout" = "$EXPECTED" ] && ok=$((ok + 1)) || wrong=$((wrong + 1)) ;;
                    RE)  re=$((re + 1)) ;;
                    TLE) tle=$((tle + 1)) ;;
                    *)   ie=$((ie + 1)) ;;
                esac

                ids[$idx]=""
            else
                still_pending=$((still_pending + 1))
            fi
        done
        pending=$still_pending
    done

    # Count anything still pending as IE
    for id in "${ids[@]}"; do
        [ -n "$id" ] && ie=$((ie + 1))
    done

    t1=$(date +%s%N)
    local elapsed_ms=$(( (t1 - t0) / 1000000 ))
    local completed=$((ac + re + tle + ie + wrong))
    local wall_avg=0
    [ "$completed" -gt 0 ] && wall_avg=$((wall_sum / completed))
    local tps=0
    [ "$elapsed_ms" -gt 0 ] && tps=$(python3 -c "print(f'{${completed}/(${elapsed_ms}/1000):.1f}')")

    local failures=$((n - ok))

    printf "  %-7s %-9s %-10s %-9s %-9s %-8s " \
        "${n}x" "$ok/$n" "${elapsed_ms}ms" "${wall_avg}ms" "${wall_max}ms" "${tps}/s"

    if [ "$failures" -eq 0 ]; then
        green "PASS"
    else
        red "FAIL"
        printf " ac=%d re=%d tle=%d ie=%d sfail=%d wrong=%d" \
            "$ac" "$re" "$tle" "$ie" "$submit_fail" "$wrong"
    fi
    echo

    return "$failures"
}

# ── main ─────────────────────────────────────────────────────────────────────

echo
bold "=== Rustbox Concurrency Stress Test ==="; echo
log "CPUs: $(nproc) (docker may limit via cgroup)"
log "Workload: Python sieve(500000) -> expect ${EXPECTED}"
echo

bootstrap_cgroups
build_payload

log "Starting judge-service..."
RUSTBOX_PORT=${PORT} \
RUSTBOX_WORKERS=$(nproc) \
RUSTBOX_DATABASE_URL="sqlite:///tmp/rustbox-stress.db" \
RUST_LOG=warn \
judge-service &
SVC_PID=$!

for i in $(seq 1 30); do
    curl -sf "${HOST}/api/health/ready" >/dev/null 2>&1 && break
    sleep 0.5
done

if ! curl -sf "${HOST}/api/health/ready" >/dev/null 2>&1; then
    red "FATAL: judge-service not ready after 15s"; echo
    kill $SVC_PID 2>/dev/null; exit 1
fi

HEALTH=$(curl -sf "${HOST}/api/health" 2>/dev/null)
log "$(echo "$HEALTH" | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(f'ready: workers={d.get(\"workers\",\"?\")} cgroup={d.get(\"cgroup_backend\",\"?\")} mode={d.get(\"enforcement_mode\",\"?\")}')" 2>/dev/null)"

# Warmup (synchronous)
log "Warmup..."
for i in 1 2 3; do
    resp=$(curl -sf --max-time 30 -X POST "${SUBMIT}?wait=true" \
        -H 'Content-Type: application/json' -d "$PAYLOAD" 2>/dev/null)
    verdict=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('verdict','?'))" 2>/dev/null)
    stdout=$(echo "$resp" | python3 -c "import sys,json; print((json.load(sys.stdin).get('stdout','') or '').strip())" 2>/dev/null)
    if [ "$verdict" != "AC" ] || [ "$stdout" != "$EXPECTED" ]; then
        red "FATAL: warmup failed: verdict=$verdict stdout=$stdout"; echo
        kill $SVC_PID 2>/dev/null; exit 1
    fi
done
log "Warmup OK"
echo

bold "  TIER    PASS      ELAPSED    AVG_WALL  MAX_WALL  TPS      RESULT"; echo
printf "  %-7s %-9s %-10s %-9s %-9s %-8s %s\n" \
    "-------" "---------" "----------" "---------" "---------" "--------" "------"

total_failures=0
for tier in "${TIERS[@]}"; do
    run_tier "$tier" || total_failures=$((total_failures + $?))
done

echo
kill $SVC_PID 2>/dev/null
wait $SVC_PID 2>/dev/null || true

if [ "$total_failures" -eq 0 ]; then
    bold "$(green "VERDICT: PASS") - zero failures across all tiers"; echo
    exit 0
else
    bold "$(red "VERDICT: FAIL") - ${total_failures} total failures"; echo
    exit 1
fi
