#!/usr/bin/env bash
set -euo pipefail

N=${1:?usage: stress_inner.sh <concurrency>}
EXPECTED="78498"

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

TMPDIR=$(mktemp -d)

run_one() {
    local id=$1
    local start_ms=$(($(date +%s%N)/1000000))

    local raw
    raw=$(rustbox execute-code --language=python --code="$SIEVE_CODE" --strict 2>/dev/null) || true

    local end_ms=$(($(date +%s%N)/1000000))
    local elapsed=$((end_ms - start_ms))

    if [ -z "$raw" ]; then
        echo "$id CRASH 0 0 0 0 $elapsed no_output" > "$TMPDIR/r_${id}.txt"
        return
    fi

    echo "$raw" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    st = d.get('status','??')
    out = d.get('stdout','').strip()
    cpu = d.get('cpu_time', 0)
    wall = d.get('wall_time', 0)
    mem = d.get('memory_peak', 0)
    ok = '1' if out == '$EXPECTED' else '0'
    mode = d.get('capability_report',{}).get('mode','?')
    cause = ''
    vp = d.get('verdict_provenance')
    if vp:
        cause = vp.get('verdict_cause','')
    print(f'$id {st} {ok} {cpu:.4f} {wall:.4f} {mem} $elapsed {mode} {cause}')
except Exception as e:
    print(f'$id PARSE_ERR 0 0 0 0 $elapsed ? {e}')
" > "$TMPDIR/r_${id}.txt"
}

WALL_START=$(($(date +%s%N)/1000000))

pids=()
for i in $(seq 1 "$N"); do
    run_one "$i" &
    pids+=($!)
done
for pid in "${pids[@]}"; do
    wait "$pid" 2>/dev/null || true
done

WALL_END=$(($(date +%s%N)/1000000))
echo "TOTAL_WALL=$((WALL_END - WALL_START))"
cat "$TMPDIR"/r_*.txt 2>/dev/null
rm -rf "$TMPDIR"
