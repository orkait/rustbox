#!/usr/bin/env bash
set -euo pipefail

IMAGE="rustbox:stress-test"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR=$(mktemp -d /tmp/rustbox-docker-stress-XXXXXX)
CONTAINER="rustbox-stress-$$"

cleanup_container() { sg docker -c "docker rm -f $CONTAINER" 2>/dev/null || true; }
trap cleanup_container EXIT

echo "================================================================"
echo "  DOCKER PRIVILEGED STRESS TEST"
echo "  Sieve of Eratosthenes (n=1,000,000)"
echo "  Single container: --memory=4g --cpus=2 --privileged"
echo "  Concurrent sandbox executions INSIDE the container"
echo "================================================================"
echo ""

sg docker -c "docker run -d \
    --name $CONTAINER \
    --privileged \
    --memory=4g --cpus=2 \
    --cgroupns=host \
    --entrypoint sleep \
    $IMAGE infinity" >/dev/null

sg docker -c "docker cp $SCRIPT_DIR/stress_inner.sh $CONTAINER:/tmp/stress_inner.sh"
sg docker -c "docker exec $CONTAINER chmod +x /tmp/stress_inner.sh"

echo "Container $CONTAINER running (4GB RAM, 2 CPU)"
echo ""

run_level() {
    local n=$1
    local out_file="$RESULTS_DIR/x${n}.txt"

    echo "--- x${n} concurrency ---"

    local raw_output
    raw_output=$(sg docker -c "docker exec $CONTAINER bash /tmp/stress_inner.sh $n" 2>/dev/null)

    local container_wall
    container_wall=$(echo "$raw_output" | grep "^TOTAL_WALL=" | head -1 | cut -d= -f2)
    echo "$raw_output" | grep -v "^TOTAL_WALL=" > "$out_file"

    local total ok correct crash timeout other
    total=$(wc -l < "$out_file")
    ok=$(awk '$2=="OK"' "$out_file" | wc -l)
    correct=$(awk '$3=="1"' "$out_file" | wc -l)
    crash=$(awk '$2=="CRASH" || $2=="PARSE_ERR"' "$out_file" | wc -l)
    timeout=$(awk '$2=="TLE"' "$out_file" | wc -l)
    other=$(awk '$2!="OK" && $2!="CRASH" && $2!="PARSE_ERR" && $2!="TLE"' "$out_file" | wc -l)

    local timing
    timing=$(awk '$2=="OK" {print $5}' "$out_file" | sort -n | awk '
        BEGIN{s=0;c=0} {v[NR]=$1;s+=$1;c++}
        END{if(c==0){print "0 0 0 0";exit}
        printf "%.3f %.3f %.3f %.3f",s/c,v[int(c*0.5)+1],v[int(c*0.95)+1],v[int(c*0.99)+1]}')
    local avg p50 p95 p99
    read -r avg p50 p95 p99 <<< "$timing"

    local mem_stats
    mem_stats=$(awk '$2=="OK" {print $6}' "$out_file" | sort -n | awk '
        BEGIN{s=0;c=0} {v[NR]=$1;s+=$1;c++}
        END{if(c==0){print "0 0 0";exit}
        printf "%.1f %.1f %.1f",s/c/(1024*1024),v[1]/(1024*1024),v[c]/(1024*1024)}')
    local avg_mem min_mem max_mem
    read -r avg_mem min_mem max_mem <<< "$mem_stats"

    local lat_stats
    lat_stats=$(awk '{print $7}' "$out_file" | sort -n | awk '
        BEGIN{s=0;c=0} {v[NR]=$1;s+=$1;c++}
        END{if(c==0){print "0 0 0 0";exit}
        printf "%.0f %.0f %.0f %.0f",s/c,v[int(c*0.5)+1],v[int(c*0.95)+1],v[int(c*0.99)+1]}')
    local avg_lat p50_lat p95_lat p99_lat
    read -r avg_lat p50_lat p95_lat p99_lat <<< "$lat_stats"

    local modes
    modes=$(awk '$2=="OK" {print $8}' "$out_file" | sort | uniq -c | sort -rn | head -3 | tr '\n' ' ')

    local fails=""
    if [ "$crash" -gt 0 ] || [ "$timeout" -gt 0 ] || [ "$other" -gt 0 ]; then
        fails=$(awk '$2!="OK" {print $2, $9}' "$out_file" | sort | uniq -c | sort -rn | head -5 | tr '\n' '; ')
    fi

    echo ""
    printf "  %-16s %s\n" "Concurrency:" "x${n}"
    printf "  %-16s %sms\n" "Total wall:" "${container_wall:-?}"
    printf "  %-16s %d/%d (%.1f%%)\n" "Success:" "$ok" "$total" "$(echo "scale=1; $ok * 100 / $total" | bc)"
    printf "  %-16s %d/%d\n" "Correct:" "$correct" "$ok"
    printf "  %-16s crash=%d  TLE=%d  other=%d\n" "Failures:" "$crash" "$timeout" "$other"
    printf "  %-16s avg=%.3fs  p50=%.3fs  p95=%.3fs  p99=%.3fs\n" "Sandbox wall:" "$avg" "$p50" "$p95" "$p99"
    printf "  %-16s avg=%dms  p50=%dms  p95=%dms  p99=%dms\n" "E2E latency:" "$avg_lat" "$p50_lat" "$p95_lat" "$p99_lat"
    printf "  %-16s avg=%.1fMB  min=%.1fMB  max=%.1fMB\n" "Memory peak:" "$avg_mem" "$min_mem" "$max_mem"
    printf "  %-16s %s\n" "Security mode:" "$modes"
    if [ -n "$fails" ]; then
        printf "  %-16s %s\n" "Fail reasons:" "$fails"
    fi
    echo ""

    [ "$ok" -eq "$total" ]
}

exit_code=0
for level in 10 20 50 100; do
    if ! run_level "$level"; then
        exit_code=1
    fi
done

# Pool leak check
pool_status=$(sg docker -c "docker exec $CONTAINER rustbox status" 2>/dev/null)
pool_active=$(echo "$pool_status" | python3 -c "import sys,json; print(json.load(sys.stdin)['pool_active'])" 2>/dev/null || echo "?")
echo "  Pool leak check: active=$pool_active (expected: 0)"
if [ "$pool_active" != "0" ]; then
    echo "  *** UID POOL LEAK ***"
    exit_code=1
fi

echo ""
echo "================================================================"
echo "  Results: $RESULTS_DIR"
echo "================================================================"
exit $exit_code
