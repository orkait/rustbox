#!/usr/bin/env bash
set -euo pipefail

RUSTBOX="./target/release/rustbox"
EXPECTED_PRIMES="78498"

SIEVE_CODE='
def sieve(n):
    s = bytearray(b"\x01") * (n + 1)
    s[0] = s[1] = 0
    for i in range(2, int(n**0.5) + 1):
        if s[i]:
            s[i*i::i] = bytearray(len(s[i*i::i]))
    return sum(s)
print(sieve(1_000_000))
'

CONCURRENCY_LEVELS=(10 20 50 100)
RESULTS_DIR=$(mktemp -d /tmp/rustbox-stress-XXXXXX)
SUMMARY_FILE="$RESULTS_DIR/summary.txt"

echo "================================================================"
echo "  RUSTBOX STRESS TEST - Sieve of Eratosthenes (n=1,000,000)"
echo "================================================================"
echo ""
echo "  Resource constraints: 4 GB RAM, 2 CPU (per sandbox)"
echo "  Expected answer:      $EXPECTED_PRIMES primes"
echo "  Results dir:          $RESULTS_DIR"
echo ""

# System info
echo "--- System snapshot ---"
echo "  CPUs:   $(nproc)"
echo "  RAM:    $(free -h | awk '/^Mem:/{print $2}')"
echo "  Kernel: $(uname -r)"
echo "  Pool:   $(echo '12345k' | sudo -S $RUSTBOX status 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print('active={}/{}'.format(d['pool_active'],d['pool_capacity']))")"
echo ""

run_one() {
    local id=$1
    local out_file=$2
    local start_ns
    start_ns=$(date +%s%N)

    local raw
    raw=$(echo "12345k" | sudo -S $RUSTBOX execute-code \
        --language=python \
        --code="$SIEVE_CODE" \
        --mem=4096 \
        --cpu=10 \
        --wall-time=30 \
        --strict 2>/dev/null) || true

    local end_ns
    end_ns=$(date +%s%N)
    local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

    if [ -z "$raw" ]; then
        echo "$id CRASH 0 0 0 0 $elapsed_ms no_json_output" >> "$out_file"
        return
    fi

    echo "$raw" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    status = d.get('status','??')
    stdout = d.get('stdout','').strip()
    cpu = d.get('cpu_time', 0)
    wall = d.get('wall_time', 0)
    mem = d.get('memory_peak', 0)
    correct = '1' if stdout == '$EXPECTED_PRIMES' else '0'
    err = d.get('verdict_provenance', {})
    cause = ''
    if err:
        cause = err.get('verdict_cause', '')
    print(f'$id {status} {correct} {cpu:.4f} {wall:.4f} {mem} $elapsed_ms {cause}')
except Exception as e:
    print(f'$id PARSE_ERR 0 0 0 0 $elapsed_ms {e}')
" >> "$out_file"
}

run_level() {
    local n=$1
    local level_dir="$RESULTS_DIR/x${n}"
    mkdir -p "$level_dir"
    local out_file="$level_dir/results.txt"
    > "$out_file"

    echo "--- x${n} concurrency ---"
    local wall_start
    wall_start=$(date +%s%N)

    local pids=()
    for i in $(seq 1 "$n"); do
        run_one "$i" "$out_file" &
        pids+=($!)
    done

    local failed_joins=0
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || ((failed_joins++))
    done

    local wall_end
    wall_end=$(date +%s%N)
    local total_wall_ms=$(( (wall_end - wall_start) / 1000000 ))

    # Parse results
    local total ok_count correct_count crash_count timeout_count error_count
    total=$(wc -l < "$out_file")
    ok_count=$(awk '$2=="OK"' "$out_file" | wc -l)
    correct_count=$(awk '$3=="1"' "$out_file" | wc -l)
    crash_count=$(awk '$2=="CRASH" || $2=="PARSE_ERR"' "$out_file" | wc -l)
    timeout_count=$(awk '$2=="TLE"' "$out_file" | wc -l)
    error_count=$(awk '$2!="OK" && $2!="CRASH" && $2!="PARSE_ERR" && $2!="TLE"' "$out_file" | wc -l)

    # Timing stats from the sandbox-reported wall times (column 5)
    local timing_stats
    timing_stats=$(awk '$2=="OK" {print $5}' "$out_file" | sort -n | awk '
        BEGIN { sum=0; count=0 }
        { vals[NR]=$1; sum+=$1; count++ }
        END {
            if (count==0) { print "0 0 0 0"; exit }
            avg=sum/count
            p50=vals[int(count*0.5)+1]
            p95=vals[int(count*0.95)+1]
            p99=vals[int(count*0.99)+1]
            printf "%.3f %.3f %.3f %.3f", avg, p50, p95, p99
        }')
    local avg_wall p50_wall p95_wall p99_wall
    read -r avg_wall p50_wall p95_wall p99_wall <<< "$timing_stats"

    # Memory stats (column 6, bytes -> MB)
    local mem_stats
    mem_stats=$(awk '$2=="OK" {print $6}' "$out_file" | sort -n | awk '
        BEGIN { sum=0; count=0 }
        { vals[NR]=$1; sum+=$1; count++ }
        END {
            if (count==0) { print "0 0 0"; exit }
            avg=sum/count/(1024*1024)
            mx=vals[count]/(1024*1024)
            mn=vals[1]/(1024*1024)
            printf "%.1f %.1f %.1f", avg, mn, mx
        }')
    local avg_mem min_mem max_mem
    read -r avg_mem min_mem max_mem <<< "$mem_stats"

    # E2E latency (column 7, ms)
    local latency_stats
    latency_stats=$(awk '{print $7}' "$out_file" | sort -n | awk '
        BEGIN { sum=0; count=0 }
        { vals[NR]=$1; sum+=$1; count++ }
        END {
            if (count==0) { print "0 0 0 0"; exit }
            avg=sum/count
            p50=vals[int(count*0.5)+1]
            p95=vals[int(count*0.95)+1]
            p99=vals[int(count*0.99)+1]
            printf "%.0f %.0f %.0f %.0f", avg, p50, p95, p99
        }')
    local avg_lat p50_lat p95_lat p99_lat
    read -r avg_lat p50_lat p95_lat p99_lat <<< "$latency_stats"

    # Pool state after
    local pool_after
    pool_after=$(echo '12345k' | sudo -S $RUSTBOX status 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["pool_active"])' 2>/dev/null || echo "?")

    # Failure details
    local failure_causes=""
    if [ "$crash_count" -gt 0 ] || [ "$timeout_count" -gt 0 ] || [ "$error_count" -gt 0 ]; then
        failure_causes=$(awk '$2!="OK" {print $2, $8}' "$out_file" | sort | uniq -c | sort -rn | head -5 | tr '\n' '; ')
    fi

    {
        echo ""
        printf "  %-14s %s\n" "Concurrency:" "x${n}"
        printf "  %-14s %s\n" "Total wall:" "${total_wall_ms}ms"
        printf "  %-14s %d/%d (%.1f%%)\n" "Success:" "$ok_count" "$total" "$(echo "scale=1; $ok_count * 100 / $total" | bc)"
        printf "  %-14s %d/%d\n" "Correct:" "$correct_count" "$ok_count"
        printf "  %-14s crash=%d  TLE=%d  other=%d\n" "Failures:" "$crash_count" "$timeout_count" "$error_count"
        printf "  %-14s avg=%.3fs  p50=%.3fs  p95=%.3fs  p99=%.3fs\n" "Sandbox wall:" "$avg_wall" "$p50_wall" "$p95_wall" "$p99_wall"
        printf "  %-14s avg=%dms  p50=%dms  p95=%dms  p99=%dms\n" "E2E latency:" "$avg_lat" "$p50_lat" "$p95_lat" "$p99_lat"
        printf "  %-14s avg=%.1fMB  min=%.1fMB  max=%.1fMB\n" "Memory:" "$avg_mem" "$min_mem" "$max_mem"
        printf "  %-14s %s\n" "Pool after:" "$pool_after"
        if [ -n "$failure_causes" ]; then
            printf "  %-14s %s\n" "Fail reasons:" "$failure_causes"
        fi
        echo ""
    } | tee -a "$SUMMARY_FILE"

    # Return non-zero if any failed
    [ "$ok_count" -eq "$total" ]
}

echo "" | tee "$SUMMARY_FILE"
echo "================================================================" | tee -a "$SUMMARY_FILE"
echo "  RESULTS" | tee -a "$SUMMARY_FILE"
echo "================================================================" | tee -a "$SUMMARY_FILE"

exit_code=0
for level in "${CONCURRENCY_LEVELS[@]}"; do
    if ! run_level "$level"; then
        exit_code=1
    fi
done

echo "================================================================" | tee -a "$SUMMARY_FILE"
echo "" | tee -a "$SUMMARY_FILE"

# Final pool leak check
pool_final=$(echo '12345k' | sudo -S $RUSTBOX status 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["pool_active"])' 2>/dev/null || echo "?")
echo "  Pool leak check: active=$pool_final (expected: 0)" | tee -a "$SUMMARY_FILE"
if [ "$pool_final" != "0" ]; then
    echo "  *** UID POOL LEAK DETECTED ***" | tee -a "$SUMMARY_FILE"
    exit_code=1
fi

echo ""
echo "  Full results: $RESULTS_DIR"
echo "  Summary:      $SUMMARY_FILE"
echo ""

exit $exit_code
