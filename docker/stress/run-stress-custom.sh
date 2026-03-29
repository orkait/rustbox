#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Rustbox stress test - verbose, per-request visibility
# ============================================================================

PORT=4096
HOST="http://127.0.0.1:${PORT}"
SUBMIT="${HOST}/api/submit"
RESULT="${HOST}/api/result"

# Allow override via env: TIERS="1 10 50" docker run ...
IFS=' ' read -ra TIERS <<< "${TIERS:-1 10 50}"

POLL_INTERVAL=0.05
POLL_TIMEOUT=600

# ── helpers ──────────────────────────────────────────────────────────────────

red()    { printf "\033[1;31m%s\033[0m" "$*"; }
green()  { printf "\033[1;32m%s\033[0m" "$*"; }
yellow() { printf "\033[1;33m%s\033[0m" "$*"; }
cyan()   { printf "\033[1;36m%s\033[0m" "$*"; }
dim()    { printf "\033[2m%s\033[0m" "$*"; }
bold()   { printf "\033[1m%s\033[0m" "$*"; }
log()    { echo "$(date +%H:%M:%S) $*"; }

build_random_payload() {
    local n=$((490000 + RANDOM % 20001))
    echo "$n"  # return N to caller via stdout line 1
    python3 -c "
import json
code = '''
def sieve(n):
    is_prime = bytearray(b\"\\x01\") * (n + 1)
    is_prime[0] = is_prime[1] = 0
    for i in range(2, int(n**0.5) + 1):
        if is_prime[i]:
            is_prime[i*i::i] = bytearray(len(is_prime[i*i::i]))
    return sum(is_prime)

N = ${n}
print(f\"{N}:{sieve(N)}\")
'''
print(json.dumps({'language': 'python', 'code': code}))
"
}

build_warmup_payload() {
    python3 -c "
import json
code = '''
def sieve(n):
    is_prime = bytearray(b\"\\x01\") * (n + 1)
    is_prime[0] = is_prime[1] = 0
    for i in range(2, int(n**0.5) + 1):
        if is_prime[i]:
            is_prime[i*i::i] = bytearray(len(is_prime[i*i::i]))
    return sum(is_prime)

print(sieve(500000))
'''
print(json.dumps({'language': 'python', 'code': code}))
"
}

submit_one() {
    local payload=$1
    curl -sf --max-time 10 -X POST "${SUBMIT}" \
        -H 'Content-Type: application/json' \
        -d "$payload" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null
}

poll_result() {
    local id=$1
    curl -sf --max-time 5 "${RESULT}/${id}" 2>/dev/null
}

parse_field() {
    printf '%s' "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$2','') or '')" 2>/dev/null || echo ""
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
    log "cgroup v2 ready: $(cat /sys/fs/cgroup/rustbox/cgroup.subtree_control 2>/dev/null || echo none)"
}

# ── run one tier (verbose) ──────────────────────────────────────────────────

run_tier() {
    local n=$1
    echo
    bold "━━━ TIER ${n}x ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo

    # Phase 1: Submit
    log "Submitting ${n} requests..."
    local ids=()
    local sieve_ns=()
    local t0 submit_t1

    t0=$(date +%s%N)

    for i in $(seq 1 "$n"); do
        local output sieve_n payload id
        output=$(build_random_payload)
        sieve_n=$(echo "$output" | head -1)
        payload=$(echo "$output" | tail -1)
        id=$(submit_one "$payload") || true

        if [ -n "$id" ]; then
            ids+=("$id")
            sieve_ns+=("$sieve_n")
            if [ "$n" -le 50 ]; then
                dim "  [${i}/${n}] submitted id=${id:0:8}.. sieve(${sieve_n})"; echo
            fi
        else
            red "  [${i}/${n}] SUBMIT FAILED"; echo
        fi
    done

    submit_t1=$(date +%s%N)
    local submitted=${#ids[@]}
    local submit_ms=$(( (submit_t1 - t0) / 1000000 ))
    log "Submitted: $(green "${submitted}/${n}") in ${submit_ms}ms ($(python3 -c "print(f'{${submitted}/(${submit_ms}/1000):.0f}')" 2>/dev/null) req/s submit rate)"

    if [ "$submitted" -eq 0 ]; then
        red "  ALL SUBMISSIONS FAILED - skipping tier"; echo
        return "$n"
    fi

    # Phase 2: Poll with live progress
    log "Polling results..."
    local ok=0 ac=0 re=0 tle=0 ie=0 wrong=0 submit_fail=$((n - submitted))
    local completed_count=0 pending=$submitted
    local wall_sum=0 wall_max=0 wall_min=999999 cpu_sum=0
    local deadline=$(( $(date +%s) + POLL_TIMEOUT ))
    local last_progress_at=$(date +%s)

    while [ "$pending" -gt 0 ] && [ "$(date +%s)" -lt "$deadline" ]; do
        sleep "$POLL_INTERVAL"
        local still_pending=0
        local batch_completed=0

        for idx in "${!ids[@]}"; do
            local id="${ids[$idx]}"
            [ -z "$id" ] && continue

            local resp status
            resp=$(poll_result "$id" 2>/dev/null) || { still_pending=$((still_pending + 1)); continue; }
            status=$(parse_field "$resp" "status")

            if [ "$status" = "completed" ] || [ "$status" = "error" ]; then
                local verdict stdout stderr_out wall_ms cpu_ms exit_code mem_kb err_msg
                verdict=$(parse_field "$resp" "verdict")
                stdout=$(printf '%s' "$resp" | python3 -c "import sys,json; print((json.load(sys.stdin).get('stdout','') or '').strip())" 2>/dev/null || echo "")
                stderr_out=$(printf '%s' "$resp" | python3 -c "import sys,json; s=json.load(sys.stdin).get('stderr','') or ''; print(s[:200].strip())" 2>/dev/null || echo "")
                wall_ms=$(printf '%s' "$resp" | python3 -c "import sys,json; print(int(float(json.load(sys.stdin).get('wall_time',0))*1000))" 2>/dev/null || echo 0)
                cpu_ms=$(printf '%s' "$resp" | python3 -c "import sys,json; print(int(float(json.load(sys.stdin).get('cpu_time',0))*1000))" 2>/dev/null || echo 0)
                exit_code=$(parse_field "$resp" "exit_code")
                mem_kb=$(printf '%s' "$resp" | python3 -c "import sys,json; v=json.load(sys.stdin).get('memory_peak',0) or 0; print(int(v/1024))" 2>/dev/null || echo 0)
                err_msg=$(parse_field "$resp" "error_message")

                wall_sum=$((wall_sum + wall_ms))
                cpu_sum=$((cpu_sum + cpu_ms))
                [ "$wall_ms" -gt "$wall_max" ] && wall_max=$wall_ms
                [ "$wall_ms" -lt "$wall_min" ] && wall_min=$wall_ms
                completed_count=$((completed_count + 1))
                batch_completed=$((batch_completed + 1))

                local short_id="${id:0:8}"
                local sieve_n="${sieve_ns[$idx]:-?}"

                case "$verdict" in
                    AC)
                        ac=$((ac + 1))
                        if echo "$stdout" | grep -qE '^[0-9]+:[0-9]+$'; then
                            ok=$((ok + 1))
                            if [ "$n" -le 50 ]; then
                                green "  OK"; printf " %s sieve(%s)=%s  wall=%dms cpu=%dms mem=%dKB\n" "$short_id" "$sieve_n" "$stdout" "$wall_ms" "$cpu_ms" "$mem_kb"
                            fi
                        else
                            wrong=$((wrong + 1))
                            yellow "  WRONG"; printf " %s expected N:count got '%s'\n" "$short_id" "$stdout"
                        fi
                        ;;
                    RE)
                        re=$((re + 1))
                        red "  RE"; printf " %s exit=%s wall=%dms stderr='%s'\n" "$short_id" "$exit_code" "$wall_ms" "$stderr_out"
                        ;;
                    TLE)
                        tle=$((tle + 1))
                        yellow "  TLE"; printf " %s wall=%dms cpu=%dms\n" "$short_id" "$wall_ms" "$cpu_ms"
                        ;;
                    *)
                        ie=$((ie + 1))
                        red "  IE"; printf " %s verdict=%s err='%s'\n" "$short_id" "$verdict" "$err_msg"
                        ;;
                esac

                ids[$idx]=""
            else
                still_pending=$((still_pending + 1))
            fi
        done

        pending=$still_pending

        # Progress line for large tiers (every 2s)
        if [ "$n" -gt 50 ] && [ "$batch_completed" -gt 0 ]; then
            local now=$(date +%s)
            if [ $((now - last_progress_at)) -ge 2 ] || [ "$pending" -eq 0 ]; then
                last_progress_at=$now
                dim "  progress: ${completed_count}/${submitted} done, ${pending} pending, ${ok} ok, ${re} RE, ${tle} TLE, ${ie} IE"; echo
            fi
        fi
    done

    # Count anything still pending as IE
    local timed_out=0
    for idx in "${!ids[@]}"; do
        local id="${ids[$idx]}"
        if [ -n "$id" ]; then
            ie=$((ie + 1))
            timed_out=$((timed_out + 1))
            red "  TIMEOUT"; printf " %s never completed\n" "${id:0:8}"
        fi
    done

    # Phase 3: Tier summary
    local t1=$(date +%s%N)
    local elapsed_ms=$(( (t1 - t0) / 1000000 ))
    local total_done=$((ac + re + tle + ie + wrong))
    local wall_avg=0 cpu_avg=0
    [ "$total_done" -gt 0 ] && wall_avg=$((wall_sum / total_done)) && cpu_avg=$((cpu_sum / total_done))
    local tps=0
    [ "$elapsed_ms" -gt 0 ] && tps=$(python3 -c "print(f'{${total_done}/(${elapsed_ms}/1000):.1f}')" 2>/dev/null)
    [ "$wall_min" -eq 999999 ] && wall_min=0

    local failures=$((n - ok))

    echo
    bold "  TIER ${n}x SUMMARY:"; echo
    printf "    Submitted : %d/%d (in %dms)\n" "$submitted" "$n" "$submit_ms"
    printf "    Completed : %d  |  " "$total_done"
    green "AC=$ac"; printf "  "; red "RE=$re"; printf "  "; yellow "TLE=$tle"; printf "  "; red "IE=$ie"; echo
    printf "    Correct   : %d/%d" "$ok" "$n"
    [ "$wrong" -gt 0 ] && printf "  (wrong output: %d)" "$wrong"
    [ "$timed_out" -gt 0 ] && printf "  (timed out: %d)" "$timed_out"
    echo
    printf "    Wall time : avg=%dms  min=%dms  max=%dms\n" "$wall_avg" "$wall_min" "$wall_max"
    printf "    CPU time  : avg=%dms\n" "$cpu_avg"
    printf "    Elapsed   : %dms  |  Throughput: %s req/s\n" "$elapsed_ms" "$tps"
    printf "    Verdict   : "
    if [ "$failures" -eq 0 ]; then
        green "PASS"; echo
    else
        red "FAIL ($failures failures)"; echo
    fi

    return "$failures"
}

# ── main ─────────────────────────────────────────────────────────────────────

echo
bold "╔══════════════════════════════════════════════════════════════╗"; echo
bold "║   Rustbox Stress Test - Randomized Sieve ~500K, Python     ║"; echo
bold "╚══════════════════════════════════════════════════════════════╝"; echo
echo
log "System : CPUs=$(nproc)  RAM=$(free -h | awk '/Mem:/{print $2}')"
log "Tiers  : ${TIERS[*]}"
log "Payload: sieve(N), N in [490000..510000] randomized per request"
echo

bootstrap_cgroups

log "Starting judge-service..."
RUSTBOX_PORT=${PORT} \
RUSTBOX_WORKERS=$(nproc) \
RUSTBOX_DATABASE_URL="sqlite:///tmp/rustbox-stress.db" \
RUST_LOG=error \
judge-service >/tmp/judge-service.log 2>&1 &
SVC_PID=$!
log "Service logs at /tmp/judge-service.log (RUST_LOG=error)"

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
print(f'Service ready: workers={d.get(\"workers\",\"?\")}  cgroup={d.get(\"cgroup_backend\",\"?\")}  mode={d.get(\"enforcement_mode\",\"?\")}')" 2>/dev/null)"

# Warmup
echo
log "Warmup: 3 synchronous requests with sieve(500000)..."
WARMUP_PAYLOAD=$(build_warmup_payload)
for i in 1 2 3; do
    local_t0=$(date +%s%N)
    resp=$(curl -sf --max-time 30 -X POST "${SUBMIT}?wait=true" \
        -H 'Content-Type: application/json' -d "$WARMUP_PAYLOAD" 2>/dev/null)
    local_t1=$(date +%s%N)
    local_ms=$(( (local_t1 - local_t0) / 1000000 ))

    verdict=$(parse_field "$resp" "verdict")
    stdout=$(printf '%s' "$resp" | python3 -c "import sys,json; print((json.load(sys.stdin).get('stdout','') or '').strip())" 2>/dev/null)
    wall_ms=$(printf '%s' "$resp" | python3 -c "import sys,json; print(int(float(json.load(sys.stdin).get('wall_time',0))*1000))" 2>/dev/null || echo 0)
    cpu_ms=$(printf '%s' "$resp" | python3 -c "import sys,json; print(int(float(json.load(sys.stdin).get('cpu_time',0))*1000))" 2>/dev/null || echo 0)

    if [ "$verdict" != "AC" ] || [ "$stdout" != "41538" ]; then
        red "  WARMUP ${i}/3 FAILED"; printf ": verdict=%s stdout=%s\n" "$verdict" "$stdout"
        printf '%s' "$resp" | python3 -m json.tool 2>/dev/null || echo "$resp"
        kill $SVC_PID 2>/dev/null; exit 1
    fi
    green "  WARMUP ${i}/3 OK"; printf "  sieve(500000)=41538  wall=%dms  cpu=%dms  roundtrip=%dms\n" "$wall_ms" "$cpu_ms" "$local_ms"
done
log "Warmup passed"

# Run tiers
total_failures=0
for tier in "${TIERS[@]}"; do
    run_tier "$tier" || total_failures=$((total_failures + $?))
done

# Final
echo
bold "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo
if [ "$total_failures" -eq 0 ]; then
    bold "FINAL VERDICT: "; green "ALL ${#TIERS[@]} TIERS PASSED"; printf " (tiers: %s)\n" "${TIERS[*]}"
else
    bold "FINAL VERDICT: "; red "FAIL"; printf " - %d total failures across tiers: %s\n" "$total_failures" "${TIERS[*]}"
fi
echo

kill $SVC_PID 2>/dev/null
wait $SVC_PID 2>/dev/null || true

# Dump service errors if any
if [ -s /tmp/judge-service.log ]; then
    local_errors=$(grep -ci 'error\|panic\|leaked' /tmp/judge-service.log 2>/dev/null || echo 0)
    if [ "$local_errors" -gt 0 ]; then
        echo
        bold "━━━ SERVICE LOG ERRORS (${local_errors} lines) ━━━"; echo
        grep -i 'error\|panic\|leaked' /tmp/judge-service.log | head -30
        [ "$local_errors" -gt 30 ] && dim "  ... and $((local_errors - 30)) more (see /tmp/judge-service.log)"; echo
    fi
fi

exit $( [ "$total_failures" -eq 0 ] && echo 0 || echo 1 )
