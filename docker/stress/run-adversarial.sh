#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Rustbox adversarial regression tests
# Submits malicious code and asserts the sandbox contains it.
# ============================================================================

PORT=4096
HOST="http://127.0.0.1:${PORT}"
SUBMIT="${HOST}/api/submit?wait=true"

red()   { printf "\033[1;31m%s\033[0m" "$*"; }
green() { printf "\033[1;32m%s\033[0m" "$*"; }
bold()  { printf "\033[1m%s\033[0m" "$*"; }
log()   { echo "$(date +%H:%M:%S) $*"; }

PASS=0
FAIL=0
TOTAL=0

run_test() {
    local name=$1
    local code=$2
    local assert_fn=$3
    TOTAL=$((TOTAL + 1))

    local payload
    payload=$(python3 -c "import json; print(json.dumps({'language':'python','code':$(python3 -c "import sys,json; print(json.dumps('''$code'''))")}))")

    local resp
    resp=$(curl -sf --max-time 30 -X POST "$SUBMIT" \
        -H 'Content-Type: application/json' \
        -d "$payload" 2>/dev/null) || resp=""

    if [ -z "$resp" ]; then
        red "  FAIL"; printf " %s: no response\n" "$name"
        FAIL=$((FAIL + 1))
        return
    fi

    local verdict status exit_code signal stderr_out
    verdict=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('verdict','') or '')" 2>/dev/null)
    status=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
    exit_code=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('exit_code','') or '')" 2>/dev/null)
    signal=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('signal','') or '')" 2>/dev/null)
    stderr_out=$(echo "$resp" | python3 -c "import sys,json; print((json.load(sys.stdin).get('stderr','') or '')[:100])" 2>/dev/null)

    if $assert_fn "$verdict" "$status" "$exit_code" "$signal" "$stderr_out"; then
        green "  PASS"; printf " %s  verdict=%s exit=%s signal=%s\n" "$name" "$verdict" "$exit_code" "$signal"
        PASS=$((PASS + 1))
    else
        red "  FAIL"; printf " %s  verdict=%s exit=%s signal=%s stderr=%s\n" "$name" "$verdict" "$exit_code" "$signal" "$stderr_out"
        FAIL=$((FAIL + 1))
    fi
}

# ── Assertion functions ────────────────────────────────────────────────────

assert_killed() {
    local verdict=$1 status=$2 exit_code=$3 signal=$4 stderr=$5
    # Must not be AC. Must have nonzero exit or signal.
    [ "$verdict" != "AC" ] && [ "$status" = "completed" -o "$status" = "error" ]
}

assert_tle() {
    local verdict=$1 status=$2 exit_code=$3 signal=$4 stderr=$5
    [ "$verdict" = "TLE" ]
}

assert_mle_or_tle() {
    local verdict=$1 status=$2 exit_code=$3 signal=$4 stderr=$5
    [ "$verdict" = "MLE" ] || [ "$verdict" = "TLE" ]
}

assert_not_ac() {
    local verdict=$1 status=$2 exit_code=$3 signal=$4 stderr=$5
    [ "$verdict" != "AC" ]
}

assert_re_or_killed() {
    local verdict=$1 status=$2 exit_code=$3 signal=$4 stderr=$5
    [ "$verdict" = "RE" ] || [ "$verdict" = "SIG" ] || [ "$verdict" = "TLE" ] || [ "$verdict" = "MLE" ]
}

# ── Bootstrap ──────────────────────────────────────────────────────────────

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
}

bootstrap_cgroups

log "Starting judge-service..."
RUSTBOX_PORT=${PORT} \
RUSTBOX_WORKERS=4 \
RUSTBOX_DATABASE_URL="sqlite:///tmp/rustbox-adversarial.db" \
RUST_LOG=error \
judge-service >/dev/null 2>&1 &
SVC_PID=$!

for i in $(seq 1 30); do
    curl -sf "${HOST}/api/health/ready" >/dev/null 2>&1 && break
    sleep 0.5
done

if ! curl -sf "${HOST}/api/health/ready" >/dev/null 2>&1; then
    red "FATAL: judge-service not ready"; echo
    kill $SVC_PID 2>/dev/null; exit 1
fi

# Warmup
curl -sf --max-time 30 -X POST "$SUBMIT" \
    -H 'Content-Type: application/json' \
    -d '{"language":"python","code":"print(1)"}' >/dev/null

echo
bold "╔══════════════════════════════════════════════════════════════╗"; echo
bold "║   Rustbox Adversarial Regression Tests                     ║"; echo
bold "╚══════════════════════════════════════════════════════════════╝"; echo
echo

# ── 1. Fork bomb ──────────────────────────────────────────────────────────
bold "── Process containment ──"; echo

run_test "fork_bomb" \
    'import os
while True:
    os.fork()' \
    assert_re_or_killed

run_test "thread_bomb" \
    'import threading
def f():
    while True:
        threading.Thread(target=f).start()
f()' \
    assert_re_or_killed

# ── 2. Memory bomb ───────────────────────────────────────────────────────
bold "── Memory containment ──"; echo

run_test "memory_bomb" \
    'x = []
while True:
    x.append(b"A" * (1024 * 1024))' \
    assert_mle_or_tle

# ── 3. CPU / wall time ──────────────────────────────────────────────────
bold "── Time containment ──"; echo

run_test "cpu_spin" \
    'while True: pass' \
    assert_tle

run_test "sigxcpu_catch" \
    'import signal
signal.signal(signal.SIGXCPU, signal.SIG_IGN)
while True: pass' \
    assert_tle

# ── 4. Filesystem containment ────────────────────────────────────────────
bold "── Filesystem containment ──"; echo

run_test "read_etc_passwd" \
    'print(open("/etc/passwd").read())' \
    assert_not_ac

run_test "read_etc_shadow" \
    'print(open("/etc/shadow").read())' \
    assert_not_ac

run_test "write_to_bin" \
    'open("/bin/evil","w").write("pwned")' \
    assert_not_ac

run_test "escape_chroot" \
    'import os
for _ in range(20):
    try: os.chdir("..")
    except: pass
print(open("etc/passwd").read())' \
    assert_not_ac

# ── 5. /proc and /sys containment ────────────────────────────────────────
bold "── Proc/sys containment ──"; echo

run_test "read_proc_cpuinfo" \
    'print(open("/proc/cpuinfo").read())' \
    assert_not_ac

run_test "read_proc_meminfo" \
    'print(open("/proc/meminfo").read())' \
    assert_not_ac

run_test "read_sys_hardware" \
    'import os
found = []
for root, dirs, files in os.walk("/sys"):
    for f in files[:3]:
        try: found.append(open(os.path.join(root,f)).read()[:50])
        except: pass
if not found:
    raise RuntimeError("no /sys files readable - sandbox blocked access")
print("ESCAPED:", found)' \
    assert_not_ac

# ── 6. Syscall filtering (seccomp) ──────────────────────────────────────
bold "── Syscall filtering ──"; echo

run_test "clone_newuser" \
    'import ctypes
libc = ctypes.CDLL("libc.so.6", use_errno=True)
CLONE_NEWUSER = 0x10000000
ret = libc.unshare(CLONE_NEWUSER)
if ret != 0:
    import ctypes.util
    raise OSError(ctypes.get_errno(), "unshare blocked")
print("ESCAPED")' \
    assert_not_ac

run_test "mount_attempt" \
    'import ctypes
libc = ctypes.CDLL("libc.so.6", use_errno=True)
ret = libc.mount(b"/tmp", b"/mnt", b"tmpfs", 0, None)
if ret == 0: print("ESCAPED")
else: raise OSError("blocked")' \
    assert_not_ac

run_test "ptrace_attempt" \
    'import ctypes
libc = ctypes.CDLL("libc.so.6", use_errno=True)
PTRACE_TRACEME = 0
ret = libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
if ret == 0: print("ESCAPED")
else: raise OSError("blocked")' \
    assert_not_ac

# ── 7. Resource exhaustion ───────────────────────────────────────────────
bold "── Resource exhaustion ──"; echo

run_test "fd_exhaustion" \
    'fds = []
try:
    while True:
        fds.append(open("/dev/null"))
except OSError as e:
    print(f"blocked at {len(fds)} fds: {e}")
    raise' \
    assert_not_ac

run_test "file_size_bomb" \
    'f = open("/tmp/bomb", "wb")
try:
    while True:
        f.write(b"A" * (1024 * 1024))
        f.flush()
except OSError as e:
    print(f"blocked: {e}")
    raise' \
    assert_not_ac

run_test "inode_bomb" \
    'import os
try:
    for i in range(100000):
        open(f"/tmp/f{i}", "w").close()
except OSError as e:
    print(f"blocked at {i}: {e}")
    raise' \
    assert_not_ac

# ── 8. Network containment ───────────────────────────────────────────────
bold "── Network containment ──"; echo

run_test "tcp_connect" \
    'import socket
s = socket.socket()
s.settimeout(2)
s.connect(("8.8.8.8", 53))
print("ESCAPED")' \
    assert_not_ac

run_test "dns_lookup" \
    'import socket
addr = socket.getaddrinfo("google.com", 80)
print("ESCAPED:", addr)' \
    assert_not_ac

# ── 9. Privilege escalation ──────────────────────────────────────────────
bold "── Privilege escalation ──"; echo

run_test "setuid_root" \
    'import os
try:
    os.setuid(0)
    print("ESCAPED")
except OSError as e:
    raise' \
    assert_not_ac

run_test "setgid_root" \
    'import os
try:
    os.setgid(0)
    print("ESCAPED")
except OSError as e:
    raise' \
    assert_not_ac

# ── 10. Concurrent adversarial ───────────────────────────────────────────
bold "── Concurrent adversarial (4 malicious + 4 normal) ──"; echo

TMPDIR=$(mktemp -d)
GOOD='{"language":"python","code":"print(42)"}'
BAD='{"language":"python","code":"import os\nwhile True:\n    os.fork()"}'

for i in 1 2 3 4; do
    curl -sf --max-time 30 -X POST "$SUBMIT" -H 'Content-Type: application/json' -d "$BAD" -o "$TMPDIR/bad$i.json" &
done
for i in 1 2 3 4; do
    curl -sf --max-time 30 -X POST "$SUBMIT" -H 'Content-Type: application/json' -d "$GOOD" -o "$TMPDIR/good$i.json" &
done
wait

GOOD_OK=0
BAD_CONTAINED=0
for i in 1 2 3 4; do
    v=$(python3 -c "import json; print(json.load(open('$TMPDIR/good$i.json')).get('verdict',''))" 2>/dev/null || echo "")
    [ "$v" = "AC" ] && GOOD_OK=$((GOOD_OK + 1))
done
for i in 1 2 3 4; do
    v=$(python3 -c "import json; print(json.load(open('$TMPDIR/bad$i.json')).get('verdict',''))" 2>/dev/null || echo "")
    [ "$v" != "AC" ] && [ -n "$v" ] && BAD_CONTAINED=$((BAD_CONTAINED + 1))
done
rm -rf "$TMPDIR"

TOTAL=$((TOTAL + 1))
if [ "$GOOD_OK" -ge 3 ] && [ "$BAD_CONTAINED" -ge 3 ]; then
    green "  PASS"; printf " concurrent_mixed  good=%d/4_AC  bad=%d/4_contained\n" "$GOOD_OK" "$BAD_CONTAINED"
    PASS=$((PASS + 1))
else
    red "  FAIL"; printf " concurrent_mixed  good=%d/4_AC  bad=%d/4_contained\n" "$GOOD_OK" "$BAD_CONTAINED"
    FAIL=$((FAIL + 1))
fi

# ── Summary ──────────────────────────────────────────────────────────────

echo
bold "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo
printf "  Tests: %d  |  " "$TOTAL"
green "PASS: $PASS"; printf "  |  "
if [ "$FAIL" -eq 0 ]; then
    green "FAIL: 0"; echo
else
    red "FAIL: $FAIL"; echo
fi
echo

if [ "$FAIL" -eq 0 ]; then
    bold "VERDICT: "; green "ALL ADVERSARIAL TESTS PASSED"; echo
else
    bold "VERDICT: "; red "$FAIL TESTS FAILED"; echo
fi
echo

kill $SVC_PID 2>/dev/null
wait $SVC_PID 2>/dev/null || true
exit $FAIL
