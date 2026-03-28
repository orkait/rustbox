#!/usr/bin/env bash
set -euo pipefail

IMAGE="rustbox:stress-test"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINER="rustbox-5k-$$"

cleanup() { sg docker -c "docker rm -f $CONTAINER" 2>/dev/null || true; }
trap cleanup EXIT

echo "================================================================"
echo "  5000 CONCURRENT EXECUTIONS - Queue Pressure Test"
echo "  Sieve(1M) | Privileged | Full host resources"
echo "================================================================"
echo ""

sg docker -c "docker run -d \
    --name $CONTAINER \
    --privileged \
    --cgroupns=host \
    -e RUSTBOX_UID_POOL_SIZE=5000 \
    --entrypoint sleep \
    $IMAGE infinity" >/dev/null

sg docker -c "docker cp $SCRIPT_DIR/stress_inner.sh $CONTAINER:/tmp/stress_inner.sh"
sg docker -c "docker exec $CONTAINER chmod +x /tmp/stress_inner.sh"

CPUS=$(sg docker -c "docker exec $CONTAINER nproc")
MEM=$(sg docker -c "docker exec $CONTAINER free -h" | awk '/^Mem:/{print $2}')
echo "  Container: ${CPUS} CPUs, ${MEM} RAM, pool=5000"
echo ""

for N in 1000 2000 3000 5000; do
    echo "--- x${N} ---"
    STARTED=$(date +%s%N)

    RAW=$(sg docker -c "docker exec -e RUSTBOX_UID_POOL_SIZE=5000 $CONTAINER bash /tmp/stress_inner.sh $N" 2>/dev/null)

    ENDED=$(date +%s%N)
    HOST_MS=$(( (ENDED - STARTED) / 1000000 ))

    WALL_MS=$(echo "$RAW" | grep "^TOTAL_WALL=" | cut -d= -f2)
    RESULTS=$(echo "$RAW" | grep -v "^TOTAL_WALL=")

    TOTAL=$(echo "$RESULTS" | wc -l)
    OK=$(echo "$RESULTS" | awk '$2=="OK"' | wc -l)
    CORRECT=$(echo "$RESULTS" | awk '$3=="1"' | wc -l)
    CRASH=$(echo "$RESULTS" | awk '$2=="CRASH"' | wc -l)
    TLE=$(echo "$RESULTS" | awk '$2=="TLE"' | wc -l)
    SIG=$(echo "$RESULTS" | awk '$2=="SIG"' | wc -l)
    IE=$(echo "$RESULTS" | awk '$2=="IE"' | wc -l)
    OTHER=$(echo "$RESULTS" | awk '$2!="OK" && $2!="CRASH" && $2!="TLE" && $2!="SIG" && $2!="IE" && $2!="PARSE_ERR"' | wc -l)
    PARSE_ERR=$(echo "$RESULTS" | awk '$2=="PARSE_ERR"' | wc -l)

    RPS="0"
    if [ "${WALL_MS:-0}" -gt 0 ]; then
        RPS=$(echo "scale=1; $OK * 1000 / $WALL_MS" | bc)
    fi

    # Latency distribution for successful runs
    E2E_STATS=$(echo "$RESULTS" | awk '$2=="OK" {print $7}' | sort -n | awk '
        BEGIN{s=0;c=0}
        {v[NR]=$1;s+=$1;c++}
        END{
            if(c==0){print "0 0 0 0 0 0";exit}
            printf "%.0f %.0f %.0f %.0f %.0f %.0f",
                v[1], v[int(c*0.5)+1], v[int(c*0.95)+1], v[int(c*0.99)+1], v[c], s/c
        }')
    read -r E2E_MIN E2E_P50 E2E_P95 E2E_P99 E2E_MAX E2E_AVG <<< "$E2E_STATS"

    SANDBOX_STATS=$(echo "$RESULTS" | awk '$2=="OK" {print $5}' | sort -n | awk '
        BEGIN{s=0;c=0}
        {v[NR]=$1;s+=$1;c++}
        END{
            if(c==0){print "0 0 0 0";exit}
            printf "%.3f %.3f %.3f %.3f", v[int(c*0.5)+1], v[int(c*0.95)+1], v[int(c*0.99)+1], s/c
        }')
    read -r SB_P50 SB_P95 SB_P99 SB_AVG <<< "$SANDBOX_STATS"

    MEM_TOTAL=$(echo "$RESULTS" | awk '$2=="OK" {s+=$6} END{printf "%.0f", s/(1024*1024)}')

    FAIL_REASONS=""
    if [ $((TOTAL - OK)) -gt 0 ]; then
        FAIL_REASONS=$(echo "$RESULTS" | awk '$2!="OK" {print $2}' | sort | uniq -c | sort -rn | head -5 | awk '{printf "%s=%s ", $2, $1}')
    fi

    echo ""
    printf "  %-18s %d\n" "Requested:" "$N"
    printf "  %-18s %d/%d (%.1f%%)\n" "Success:" "$OK" "$TOTAL" "$(echo "scale=1; $OK * 100 / $TOTAL" | bc)"
    printf "  %-18s %d/%d\n" "Correct answers:" "$CORRECT" "$OK"
    printf "  %-18s %sms\n" "Container wall:" "${WALL_MS:-?}"
    printf "  %-18s %s\n" "Throughput:" "${RPS} RPS"
    echo ""
    printf "  %-18s min=%sms  p50=%sms  p95=%sms  p99=%sms  max=%sms\n" \
        "E2E latency:" "$E2E_MIN" "$E2E_P50" "$E2E_P95" "$E2E_P99" "$E2E_MAX"
    printf "  %-18s p50=%ss  p95=%ss  p99=%ss  avg=%ss\n" \
        "Sandbox wall:" "$SB_P50" "$SB_P95" "$SB_P99" "$SB_AVG"
    printf "  %-18s ~%s MB total across %d sandboxes\n" "Memory:" "$MEM_TOTAL" "$OK"
    if [ -n "$FAIL_REASONS" ]; then
        printf "  %-18s %s\n" "Failures:" "$FAIL_REASONS"
    fi
    echo ""
done

POOL=$(sg docker -c "docker exec -e RUSTBOX_UID_POOL_SIZE=5000 $CONTAINER rustbox status" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'active={d[\"pool_active\"]}')" 2>/dev/null || echo "?")
echo "  Pool leak check: $POOL"
echo ""
echo "================================================================"
