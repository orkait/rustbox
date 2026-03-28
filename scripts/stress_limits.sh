#!/usr/bin/env bash
set -euo pipefail

IMAGE="rustbox:stress-test"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

run_config() {
    local cpus=$1 mem=$2 label=$3
    local container="rustbox-limit-${cpus}c-$$"

    sg docker -c "docker rm -f $container" 2>/dev/null || true
    sg docker -c "docker run -d \
        --name $container \
        --privileged \
        --cpus=$cpus --memory=$mem \
        --cgroupns=host \
        -e RUSTBOX_UID_POOL_SIZE=2000 \
        --entrypoint sleep \
        $IMAGE infinity" >/dev/null

    sg docker -c "docker cp $SCRIPT_DIR/stress_inner.sh $container:/tmp/stress_inner.sh"
    sg docker -c "docker exec $container chmod +x /tmp/stress_inner.sh"

    echo ""
    echo "============================================================"
    echo "  $label"
    echo "============================================================"
    echo ""
    printf "  %-6s  %7s  %5s  %7s  %9s  %9s  %9s  %9s\n" \
        "Conc" "OK/Tot" "Fail" "Wall" "RPS" "p50 E2E" "p95 E2E" "p50 sbox"
    printf "  %-6s  %7s  %5s  %7s  %9s  %9s  %9s  %9s\n" \
        "------" "-------" "-----" "-------" "---------" "---------" "---------" "---------"

    for N in 10 25 50 100 200 500 1000; do
        local raw
        raw=$(sg docker -c "docker exec -e RUSTBOX_UID_POOL_SIZE=2000 $container bash /tmp/stress_inner.sh $N" 2>/dev/null)

        local wall_ms ok total
        wall_ms=$(echo "$raw" | grep "^TOTAL_WALL=" | cut -d= -f2)
        local results
        results=$(echo "$raw" | grep -v "^TOTAL_WALL=")
        total=$(echo "$results" | wc -l)
        ok=$(echo "$results" | awk '$2=="OK"' | wc -l)
        local fail=$((total - ok))

        local rps="0"
        if [ "${wall_ms:-0}" -gt 0 ]; then
            rps=$(echo "scale=1; $ok * 1000 / $wall_ms" | bc)
        fi

        local e2e_p50 e2e_p95 sb_p50
        e2e_p50=$(echo "$results" | awk '$2=="OK"{print $7}' | sort -n | awk '{v[NR]=$1;c++}END{if(c==0)print "0";else print v[int(c*0.5)+1]}')
        e2e_p95=$(echo "$results" | awk '$2=="OK"{print $7}' | sort -n | awk '{v[NR]=$1;c++}END{if(c==0)print "0";else print v[int(c*0.95)+1]}')
        sb_p50=$(echo "$results" | awk '$2=="OK"{print $5}' | sort -n | awk '{v[NR]=$1;c++}END{if(c==0)print "0";else printf "%.0f",v[int(c*0.5)+1]*1000}')

        printf "  x%-5s  %4d/%-3d  %4d  %5sms  %6s    %6sms  %6sms  %6sms\n" \
            "$N" "$ok" "$total" "$fail" "${wall_ms:-?}" "$rps" "$e2e_p50" "$e2e_p95" "$sb_p50"
    done

    local pool
    pool=$(sg docker -c "docker exec -e RUSTBOX_UID_POOL_SIZE=2000 $container rustbox status" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin)['pool_active'])" 2>/dev/null || echo "?")
    echo ""
    echo "  Pool leak: $pool"

    sg docker -c "docker rm -f $container" >/dev/null 2>&1
}

run_config 2 4g "2 CORES / 4 GB RAM"
run_config 4 4g "4 CORES / 4 GB RAM"

echo ""
echo "============================================================"
