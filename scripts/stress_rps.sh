#!/usr/bin/env bash
set -euo pipefail

IMAGE="rustbox:stress-test"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINER="rustbox-rps-$$"

cleanup() { sg docker -c "docker rm -f $CONTAINER" 2>/dev/null || true; }
trap cleanup EXIT

echo "================================================================"
echo "  RPS CEILING TEST - Sieve(1M) - Finding max throughput"
echo "================================================================"
echo ""

# Use full host resources (no --memory/--cpus cap)
sg docker -c "docker run -d \
    --name $CONTAINER \
    --privileged \
    --cgroupns=host \
    --entrypoint sleep \
    $IMAGE infinity" >/dev/null

sg docker -c "docker cp $SCRIPT_DIR/stress_inner.sh $CONTAINER:/tmp/stress_inner.sh"
sg docker -c "docker exec $CONTAINER chmod +x /tmp/stress_inner.sh"

CPUS=$(sg docker -c "docker exec $CONTAINER nproc")
MEM=$(sg docker -c "docker exec $CONTAINER free -h" | awk '/^Mem:/{print $2}')
echo "  Container resources: ${CPUS} CPUs, ${MEM} RAM (full host)"
echo ""

run_level() {
    local n=$1
    local raw
    raw=$(sg docker -c "docker exec $CONTAINER bash /tmp/stress_inner.sh $n" 2>/dev/null)

    local wall_ms
    wall_ms=$(echo "$raw" | grep "^TOTAL_WALL=" | cut -d= -f2)
    local results
    results=$(echo "$raw" | grep -v "^TOTAL_WALL=")

    local total ok correct
    total=$(echo "$results" | wc -l)
    ok=$(echo "$results" | awk '$2=="OK"' | wc -l)
    correct=$(echo "$results" | awk '$3=="1"' | wc -l)
    local fail=$((total - ok))

    local rps="0"
    if [ "${wall_ms:-0}" -gt 0 ]; then
        rps=$(echo "scale=1; $ok * 1000 / $wall_ms" | bc)
    fi

    local p50_wall p95_wall
    p50_wall=$(echo "$results" | awk '$2=="OK" {print $5}' | sort -n | awk 'BEGIN{c=0}{v[NR]=$1;c++}END{print v[int(c*0.5)+1]+0}')
    p95_wall=$(echo "$results" | awk '$2=="OK" {print $5}' | sort -n | awk 'BEGIN{c=0}{v[NR]=$1;c++}END{print v[int(c*0.95)+1]+0}')

    local p50_e2e p95_e2e
    p50_e2e=$(echo "$results" | awk '$2=="OK" {print $7}' | sort -n | awk 'BEGIN{c=0}{v[NR]=$1;c++}END{print v[int(c*0.5)+1]+0}')
    p95_e2e=$(echo "$results" | awk '$2=="OK" {print $7}' | sort -n | awk 'BEGIN{c=0}{v[NR]=$1;c++}END{print v[int(c*0.95)+1]+0}')

    printf "  x%-5s  %3d/%3d OK  %3d correct  %2d fail  wall=%5sms  RPS=%-7s  p50=%sms/%ss  p95=%sms/%ss\n" \
        "$n" "$ok" "$total" "$correct" "$fail" "${wall_ms:-?}" "$rps" \
        "${p50_e2e}" "${p50_wall}" "${p95_e2e}" "${p95_wall}"
}

echo "  Conc   Success     Correct    Fail   Wall       RPS        p50(E2E/sandbox)    p95(E2E/sandbox)"
echo "  -----  ----------  ---------  -----  ---------  ---------  ------------------  ------------------"

for level in 10 50 100 200 300 500 700 900; do
    run_level "$level"
done

echo ""

# Pool leak check
pool_active=$(sg docker -c "docker exec $CONTAINER rustbox status" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['pool_active'])" 2>/dev/null || echo "?")
echo "  Pool leak check: active=$pool_active"
echo ""
echo "================================================================"
