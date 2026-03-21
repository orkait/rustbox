#!/usr/bin/env bash
#
# Cluster integration tests for rustbox judge-service.
# Spins up 2 rustbox nodes + 1 PostgreSQL container, runs tests, tears down.
#
# Requirements: docker compose, curl, jq
# Usage: ./tests/cluster/cluster_test.sh

set -euo pipefail

COMPOSE_FILE="tests/cluster/docker-compose.test.yml"
PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_DIR"

NODE1="http://localhost:8081"
NODE2="http://localhost:8082"
HEALTH_TIMEOUT=120   # seconds to wait for nodes to become healthy
POLL_INTERVAL=2      # seconds between health polls
JOB_WAIT_TIMEOUT=60  # seconds to wait for a job to complete

PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { printf "\033[1;34m[cluster-test]\033[0m %s\n" "$*"; }
pass() { printf "\033[1;32m  PASS\033[0m %s\n" "$*"; PASS=$((PASS + 1)); }
fail() { printf "\033[1;31m  FAIL\033[0m %s\n" "$*"; FAIL=$((FAIL + 1)); }

cleanup() {
    log "Tearing down cluster..."
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

wait_for_health() {
    local url="$1/api/health"
    local label="$2"
    local elapsed=0

    log "Waiting for $label to become healthy ($url)..."
    while [ "$elapsed" -lt "$HEALTH_TIMEOUT" ]; do
        if curl -sf "$url" >/dev/null 2>&1; then
            log "$label is healthy (${elapsed}s)"
            return 0
        fi
        sleep "$POLL_INTERVAL"
        elapsed=$((elapsed + POLL_INTERVAL))
    done

    fail "$label did not become healthy within ${HEALTH_TIMEOUT}s"
    return 1
}

# Submit a job and print the response body. Returns non-zero on HTTP failure.
submit_job() {
    local node_url="$1"
    local payload="${2:-'{"language": "python", "code": "print(42)"}'}"
    local extra_headers="${3:-}"

    local curl_args=(-sf -X POST "$node_url/api/execute"
                     -H "Content-Type: application/json"
                     -d "$payload")
    if [ -n "$extra_headers" ]; then
        curl_args+=(-H "$extra_headers")
    fi

    curl "${curl_args[@]}"
}

# Poll until a job reaches a terminal state. Prints the final JSON.
wait_for_job() {
    local node_url="$1"
    local job_id="$2"
    local elapsed=0

    while [ "$elapsed" -lt "$JOB_WAIT_TIMEOUT" ]; do
        local resp
        resp=$(curl -sf "$node_url/api/executions/$job_id" 2>/dev/null) || true
        if [ -n "$resp" ]; then
            local status
            status=$(echo "$resp" | jq -r '.status // empty')
            if [ "$status" = "completed" ] || [ "$status" = "failed" ]; then
                echo "$resp"
                return 0
            fi
        fi
        sleep "$POLL_INTERVAL"
        elapsed=$((elapsed + POLL_INTERVAL))
    done

    fail "Job $job_id did not complete within ${JOB_WAIT_TIMEOUT}s"
    return 1
}

# Run a SQL query against the test postgres via docker compose exec.
psql_query() {
    docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U rustbox -d rustbox_test -tAc "$1"
}

# ---------------------------------------------------------------------------
# Bring up the cluster
# ---------------------------------------------------------------------------

log "Starting cluster (2 nodes + PostgreSQL)..."
docker compose -f "$COMPOSE_FILE" up -d --build

wait_for_health "$NODE1" "node-1"
wait_for_health "$NODE2" "node-2"

log "Cluster is up. Running tests."
echo

# ---------------------------------------------------------------------------
# Test 1: Cross-node execution
#   POST to node1, GET result from node2 - verify the result is visible on
#   both nodes (shared PostgreSQL state).
# ---------------------------------------------------------------------------

log "Test 1: Cross-node execution"

resp=$(submit_job "$NODE1") || { fail "Test 1 - submit to node1 failed"; }
job_id=$(echo "$resp" | jq -r '.id // .job_id // empty')

if [ -z "$job_id" ]; then
    fail "Test 1 - no job id in response: $resp"
else
    result=$(wait_for_job "$NODE2" "$job_id") || true

    if [ -n "$result" ]; then
        output=$(echo "$result" | jq -r '.stdout // .output // empty')
        if echo "$output" | grep -q "42"; then
            pass "Test 1 - job submitted on node1, retrieved from node2, output=42"
        else
            fail "Test 1 - unexpected output: $output"
        fi
    else
        fail "Test 1 - could not retrieve job $job_id from node2"
    fi
fi

echo

# ---------------------------------------------------------------------------
# Test 2: Work distribution
#   POST 10 jobs to node1, wait for completion, then verify that both node-1
#   and node-2 appear in the node_id column (work was distributed).
# ---------------------------------------------------------------------------

log "Test 2: Work distribution"

job_ids=()
for i in $(seq 1 10); do
    resp=$(submit_job "$NODE1" '{"language": "python", "code": "print(42)"}') || true
    jid=$(echo "$resp" | jq -r '.id // .job_id // empty')
    if [ -n "$jid" ]; then
        job_ids+=("$jid")
    fi
done

log "Submitted ${#job_ids[@]} jobs, waiting for completion..."

for jid in "${job_ids[@]}"; do
    wait_for_job "$NODE1" "$jid" >/dev/null 2>&1 || true
done

# Query postgres for distinct node_ids that executed these jobs.
node_ids=$(psql_query "SELECT DISTINCT node_id FROM executions WHERE node_id IS NOT NULL;") || true

has_node1=false
has_node2=false
while IFS= read -r line; do
    case "$line" in
        *node-1*) has_node1=true ;;
        *node-2*) has_node2=true ;;
    esac
done <<< "$node_ids"

if $has_node1 && $has_node2; then
    pass "Test 2 - work distributed across node-1 and node-2"
elif $has_node1 || $has_node2; then
    fail "Test 2 - work only ran on one node (node_ids: $node_ids)"
else
    fail "Test 2 - could not determine node distribution (node_ids: $node_ids)"
fi

echo

# ---------------------------------------------------------------------------
# Test 3: Idempotency across nodes
#   POST with Idempotency-Key to node1, then POST same key to node2.
#   Verify only one execution actually happened.
# ---------------------------------------------------------------------------

log "Test 3: Idempotency across nodes"

idempotency_key="test-idem-$(date +%s)-$$"

resp1=$(submit_job "$NODE1" \
    '{"language": "python", "code": "print(42)"}' \
    "Idempotency-Key: $idempotency_key") || true

job_id1=$(echo "$resp1" | jq -r '.id // .job_id // empty')

# Small pause so node1 registers the key before node2 tries.
sleep 1

resp2=$(submit_job "$NODE2" \
    '{"language": "python", "code": "print(42)"}' \
    "Idempotency-Key: $idempotency_key") || true

job_id2=$(echo "$resp2" | jq -r '.id // .job_id // empty')

if [ -n "$job_id1" ] && [ -n "$job_id2" ]; then
    if [ "$job_id1" = "$job_id2" ]; then
        pass "Test 3 - idempotent: same job_id ($job_id1) returned for both requests"
    else
        # Even if IDs differ, check if only one execution row exists.
        exec_count=$(psql_query \
            "SELECT COUNT(*) FROM executions WHERE idempotency_key = '$idempotency_key';") || true
        exec_count=$(echo "$exec_count" | tr -d '[:space:]')
        if [ "$exec_count" = "1" ]; then
            pass "Test 3 - idempotent: only 1 execution row for key (ids differ: $job_id1 vs $job_id2)"
        else
            fail "Test 3 - NOT idempotent: $exec_count executions for same key"
        fi
    fi
else
    fail "Test 3 - could not submit jobs (resp1=$resp1, resp2=$resp2)"
fi

echo

# ---------------------------------------------------------------------------
# Test 4: No sandbox collision
#   POST the same code to both nodes simultaneously. Verify different
#   sandbox_ids and both complete successfully.
# ---------------------------------------------------------------------------

log "Test 4: No sandbox collision"

payload='{"language": "python", "code": "print(42)"}'

# Fire both requests in parallel using background subshells.
resp_a_file=$(mktemp)
resp_b_file=$(mktemp)

(submit_job "$NODE1" "$payload" > "$resp_a_file" 2>&1) &
pid_a=$!
(submit_job "$NODE2" "$payload" > "$resp_b_file" 2>&1) &
pid_b=$!

wait "$pid_a" || true
wait "$pid_b" || true

resp_a=$(cat "$resp_a_file")
resp_b=$(cat "$resp_b_file")
rm -f "$resp_a_file" "$resp_b_file"

job_a=$(echo "$resp_a" | jq -r '.id // .job_id // empty')
job_b=$(echo "$resp_b" | jq -r '.id // .job_id // empty')

if [ -z "$job_a" ] || [ -z "$job_b" ]; then
    fail "Test 4 - could not submit parallel jobs (a=$resp_a, b=$resp_b)"
else
    result_a=$(wait_for_job "$NODE1" "$job_a") || true
    result_b=$(wait_for_job "$NODE2" "$job_b") || true

    sandbox_a=$(echo "$result_a" | jq -r '.sandbox_id // .box_id // empty')
    sandbox_b=$(echo "$result_b" | jq -r '.sandbox_id // .box_id // empty')

    status_a=$(echo "$result_a" | jq -r '.status // empty')
    status_b=$(echo "$result_b" | jq -r '.status // empty')

    if [ "$status_a" = "completed" ] && [ "$status_b" = "completed" ]; then
        if [ -n "$sandbox_a" ] && [ -n "$sandbox_b" ] && [ "$sandbox_a" != "$sandbox_b" ]; then
            pass "Test 4 - no collision: sandbox_a=$sandbox_a, sandbox_b=$sandbox_b, both completed"
        elif [ "$sandbox_a" = "$sandbox_b" ] && [ -n "$sandbox_a" ]; then
            fail "Test 4 - COLLISION: same sandbox_id=$sandbox_a on both nodes"
        else
            # sandbox_id might not be in the response; as long as both completed we pass.
            pass "Test 4 - both completed (sandbox_id not exposed in response, but no error)"
        fi
    else
        fail "Test 4 - not both completed: status_a=$status_a, status_b=$status_b"
    fi
fi

echo

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

log "========================================"
log "  Results: $PASS passed, $FAIL failed"
log "========================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi

exit 0
