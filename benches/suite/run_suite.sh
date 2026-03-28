#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
#  RUSTBOX BENCHMARK SUITE v2
#  13 problems x 3 languages = 33 test cases
#  Each test: code file + stdin input + expected stdout + expected verdict
# ============================================================================

CONCURRENCY=${1:-1}
SUITE_DIR="$(cd "$(dirname "$0")" && pwd)"
TMPDIR=$(mktemp -d /tmp/rustbox-bench-XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

# --- Test definitions: id|lang|expected_status|mem_mb|wall_sec ---
TESTS=(
    "sieve|python|OK|256|10"
    "sieve|cpp|OK|256|10"
    "sieve|java|OK|512|15"
    "kadane|python|OK|256|10"
    "kadane|cpp|OK|256|10"
    "kadane|java|OK|512|15"
    "mergesort|python|OK|512|30"
    "mergesort|cpp|OK|256|10"
    "mergesort|java|OK|512|15"
    "bfs|python|OK|256|10"
    "bfs|cpp|OK|256|10"
    "bfs|java|OK|512|15"
    "nqueens|python|OK|256|30"
    "nqueens|cpp|OK|256|10"
    "nqueens|java|OK|512|15"
    "lcs|python|OK|512|120"
    "lcs|cpp|OK|256|10"
    "lcs|java|OK|512|15"
    "binsearch|python|OK|256|10"
    "binsearch|cpp|OK|256|10"
    "binsearch|java|OK|512|15"
    "rabinkarp|python|OK|256|30"
    "rabinkarp|cpp|OK|256|10"
    "rabinkarp|java|OK|512|15"
    "rangesum|python|OK|256|30"
    "rangesum|cpp|OK|256|10"
    "rangesum|java|OK|512|15"
    "dijkstra|python|OK|256|30"
    "dijkstra|cpp|OK|256|10"
    "dijkstra|java|OK|512|15"
    "deliberate_tle|python|TLE|256|3"
    "deliberate_mle|python|MLE|64|30"
    "deliberate_re|python|RE|256|10"
)

TOTAL=${#TESTS[@]}

run_one() {
    local test_def=$1
    local test_idx=$2
    IFS='|' read -r id lang expected_status mem_mb wall_sec <<< "$test_def"

    local src_file
    case "$lang" in
        python) src_file="$SUITE_DIR/python/${id}.py" ;;
        cpp)    src_file="$SUITE_DIR/cpp/${id}.cpp" ;;
        java)   src_file="$SUITE_DIR/java/${id}.java" ;;
    esac
    local input_file="$SUITE_DIR/inputs/${id}_${lang}.txt"
    if [ ! -f "$input_file" ]; then
        input_file="$SUITE_DIR/inputs/${id}.txt"
    fi
    local expected_file="$SUITE_DIR/expected/${id}_${lang}.txt"
    if [ ! -f "$expected_file" ]; then
        expected_file="$SUITE_DIR/expected/${id}.txt"
    fi

    if [ ! -f "$src_file" ]; then
        echo "$test_idx|${id}|${lang}|SKIP|0|0|0|0|file_missing" > "$TMPDIR/r_${test_idx}.txt"
        return
    fi

    local code stdin_data
    code=$(cat "$src_file")
    stdin_data=""
    if [ -f "$input_file" ] && [ -s "$input_file" ]; then
        stdin_data=$(cat "$input_file")
    fi

    local start_ms=$(($(date +%s%N)/1000000))

    local raw
    if [ -n "$stdin_data" ]; then
        raw=$(rustbox execute-code \
            --language="$lang" \
            --code="$code" \
            --stdin="$stdin_data" \
            --strict \
            --mem="$mem_mb" \
            --wall-time="$wall_sec" 2>/dev/null) || true
    else
        raw=$(rustbox execute-code \
            --language="$lang" \
            --code="$code" \
            --strict \
            --mem="$mem_mb" \
            --wall-time="$wall_sec" 2>/dev/null) || true
    fi

    local end_ms=$(($(date +%s%N)/1000000))
    local elapsed=$((end_ms - start_ms))

    if [ -z "$raw" ]; then
        echo "$test_idx|${id}|${lang}|CRASH|0|0|0|${elapsed}|no_output" > "$TMPDIR/r_${test_idx}.txt"
        return
    fi

    python3 -c "
import sys, json, os
raw_json = sys.stdin.read()
try:
    d = json.loads(raw_json)
    status = d.get('status', '??')
    stdout = d.get('stdout', '').rstrip()
    cpu = d.get('cpu_time', 0)
    wall = d.get('wall_time', 0)
    mem = d.get('memory_peak', 0)

    status_ok = '1' if status == '$expected_status' else '0'

    expected_file = '$expected_file'
    expected_out = ''
    if os.path.isfile(expected_file) and os.path.getsize(expected_file) > 0:
        expected_out = open(expected_file).read().rstrip()

    output_ok = '1'
    if expected_out and status == 'OK':
        output_ok = '1' if stdout == expected_out else '0'
    elif '$expected_status' != 'OK':
        output_ok = '1'

    cause = ''
    vp = d.get('verdict_provenance')
    if vp:
        cause = vp.get('verdict_cause', '')

    print(f'$test_idx|$id|$lang|{status}|{status_ok}|{output_ok}|{cpu:.4f}|{wall:.4f}|{mem}|$elapsed|{cause}')
except Exception as e:
    print(f'$test_idx|$id|$lang|PARSE_ERR|0|0|0|0|0|$elapsed|{e}')
" <<< "$raw" > "$TMPDIR/r_${test_idx}.txt"
}

echo "================================================================"
echo "  RUSTBOX BENCHMARK SUITE v2"
echo "  $TOTAL test cases | concurrency: x${CONCURRENCY}"
echo "  Input: via --stdin from input files"
echo "  Output: validated against expected files"
echo "================================================================"
echo ""

WALL_START=$(($(date +%s%N)/1000000))

if [ "$CONCURRENCY" -le 1 ]; then
    for i in $(seq 0 $((TOTAL - 1))); do
        run_one "${TESTS[$i]}" "$i"
        printf "." >&2
    done
    echo "" >&2
else
    for copy in $(seq 1 "$CONCURRENCY"); do
        for i in $(seq 0 $((TOTAL - 1))); do
            idx=$(( (copy - 1) * TOTAL + i ))
            run_one "${TESTS[$i]}" "$idx" &
        done
    done
    wait
fi

WALL_END=$(($(date +%s%N)/1000000))
TOTAL_WALL=$((WALL_END - WALL_START))

cat "$TMPDIR"/r_*.txt 2>/dev/null | sort -t'|' -k1 -n > "$TMPDIR/all_results.txt"

ACTUAL_TOTAL=$(wc -l < "$TMPDIR/all_results.txt")
STATUS_OK=$(awk -F'|' '$5=="1"' "$TMPDIR/all_results.txt" | wc -l)
OUTPUT_OK=$(awk -F'|' '$6=="1"' "$TMPDIR/all_results.txt" | wc -l)
BOTH_OK=$(awk -F'|' '$5=="1" && $6=="1"' "$TMPDIR/all_results.txt" | wc -l)

echo ""
printf "  %-14s %-6s %-6s %-6s %-6s %-9s %-9s %-8s %s\n" \
    "Problem" "Lang" "Status" "StOK" "OutOK" "CPU(s)" "Wall(s)" "E2E(ms)" "Cause"
printf "  %-14s %-6s %-6s %-6s %-6s %-9s %-9s %-8s %s\n" \
    "--------------" "------" "------" "------" "------" "---------" "---------" "--------" "--------"

awk -F'|' '{
    printf "  %-14s %-6s %-6s %-6s %-6s %-9s %-9s %-8s %s\n", $2, $3, $4, ($5=="1"?"pass":"FAIL"), ($6=="1"?"pass":"FAIL"), $7, $8, $10, $11
}' "$TMPDIR/all_results.txt" | head -66

FAILURES=$(awk -F'|' '$5!="1" || $6!="1"' "$TMPDIR/all_results.txt")
FAIL_COUNT=$(echo "$FAILURES" | grep -c '.' || true)

echo ""
echo "================================================================"
echo "  RESULTS"
echo "================================================================"
printf "  Total:          %d tests (x%d = %d executions)\n" "$TOTAL" "$CONCURRENCY" "$ACTUAL_TOTAL"
printf "  Verdict OK:     %d/%d\n" "$STATUS_OK" "$ACTUAL_TOTAL"
printf "  Output OK:      %d/%d\n" "$OUTPUT_OK" "$ACTUAL_TOTAL"
printf "  Fully correct:  %d/%d\n" "$BOTH_OK" "$ACTUAL_TOTAL"
printf "  Wall time:      %dms\n" "$TOTAL_WALL"
if [ "$ACTUAL_TOTAL" -gt 0 ] && [ "$TOTAL_WALL" -gt 0 ]; then
    printf "  Throughput:     %.1f tests/sec\n" "$(echo "scale=1; $ACTUAL_TOTAL * 1000 / $TOTAL_WALL" | bc)"
fi

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo ""
    echo "  FAILURES:"
    echo "$FAILURES" | awk -F'|' '{printf "    %s/%s: got %s (verdict=%s output=%s) %s\n", $2, $3, $4, ($5=="1"?"ok":"WRONG"), ($6=="1"?"ok":"WRONG"), $11}'
fi

echo ""
pool=$(rustbox status 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin)['pool_active'])" 2>/dev/null || echo "?")
echo "  Pool leak: $pool"
echo "================================================================"

[ "$FAIL_COUNT" -eq 0 ] && exit 0 || exit 1
