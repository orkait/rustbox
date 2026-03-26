# Sandbox Setup Contention Issue

## Status: In Progress (branch: fix/sandbox-setup-contention)

## Problem

Under high concurrency (x100 in VM, strict mode, cgroup v1), ~1-3% of sandbox setups hang indefinitely in a kernel mount syscall. The proxy child never reaches `execvp()` - it gets stuck before producing any output (cpu_time=0, stderr empty).

## Failure Signature

```
verdict: TLE (should be IE)
wall_time: 22.4s (full kill_timeout)
cpu_time: 0.0006s (code never ran)
signal: 9 (SIGKILL from supervisor)
error: "failed to decode json on fd: EOF" (proxy killed before reporting)
stderr: (empty - child never wrote anything)
memory_peak: 160-220 KB (barely started)
```

## Root Cause Analysis

Each sandbox creates 18 mount syscalls and 7 namespace operations:

```
Supervisor clone(CLONE_NEWPID|CLONE_NEWIPC|CLONE_NEWUTS|CLONE_NEWNS|CLONE_NEWNET)
  -> Proxy fork() -> Payload child:
    1. unshare(CLONE_NEWNS|CLONE_NEWNET)     <- REDUNDANT (clone already did this)
    2. mount(MS_REC|MS_PRIVATE, "/")          <- Walks ALL 25 mounts (15 cgroup v1 controllers)
    3. mount(tmpfs) for chroot root           <- 1 mount
    4. bind mount + remount chroot            <- 2 mounts
    5. bind mount /bin, /lib, /usr, /lib64    <- 8 mounts (4 bind + 4 remount)
    6. mount(sysfs) on /sys                   <- 1 mount (not needed for code)
    7. mount(tmpfs) on /dev + 4x mknod        <- 1 mount
    8. mount(proc) with hidepid cascade       <- 1-4 mount ATTEMPTS (contention source)
    9. mount(tmpfs) on /dev/shm               <- 1 mount (not needed for code)
    10. mount(tmpfs) on /tmp                  <- 1 mount
    11. bind mount + remount workdir          <- 2 mounts
    12. chroot, setresgid, setresuid, caps, seccomp, execvp
```

On cgroup v1 hosts (15 controller mounts), step 2 (recursive MS_PRIVATE) and step 8 (procfs hidepid cascade) are the main contention sources. The kernel's `namespace_sem` lock serializes mount operations across concurrent sandboxes.

## Environment Where It Reproduces

- Multipass VM, 4 cores, 4GB RAM, kernel 5.15
- cgroup v1 enabled via `systemd.unified_cgroup_hierarchy=0`
- Docker container with `--privileged` or `--cap-add SYS_ADMIN`
- 100 concurrent HTTP submissions, 2 workers

## Does NOT Reproduce On

- Host machine (bare metal, 16 cores, 29GB, kernel 6.17, cgroup v2) - 100/100 at x100
- Lower concurrency (x50 in VM) - reliable after other fixes

## Fixes Already Applied (merged in PR #29)

1. Proxy wall timer starts after fork() (accurate payload execution time)
2. SETUP_BUDGET added to supervisor kill timeout (was wall_limit only)

## Fixes On Branch (fix/sandbox-setup-contention, NOT YET MERGED)

### Safe fixes (no security tradeoff):
1. **Remove redundant unshare()** - `runtime_exec.rs` passes `(false,false,false,false)` to `setup_namespaces` since supervisor's `clone()` already created all namespaces. Saves 2 namespace operations per sandbox.
2. **SETUP_BUDGET 15s -> 3s** - Normal setup takes <100ms. 15s was too generous. Now hung sandboxes are killed in 3s, freeing the worker.
3. **Fix fallback ProxyStatus timed_out bug** - When proxy never wrote status (EOF on pipe), the fallback was setting `timed_out` from the supervisor's flag, making it look like the proxy reported TLE. Fixed to `timed_out: false`.
4. **TLE vs IE classification** - Supervisor now distinguishes proxy-reported timeout (real TLE) from supervisor safety timeout (setup hung = InternalError).
5. **Proxy watchdog thread** - Spawns a thread that kills the payload after exactly `wall_time_limit_ms`. The proxy correctly reports `timed_out: true`. This is the authoritative wall timer.

### Risky fixes (need validation before merging):
6. **Non-recursive MS_PRIVATE on `/`** - Changed from `MS_REC|MS_PRIVATE` to just `MS_PRIVATE` on `/`, then `MS_REC|MS_PRIVATE` on `/tmp` only. **Risk:** Shared mounts other than `/` and `/tmp` could still propagate into the sandbox. The original recursive flag was a security measure.
7. **Remove sysfs mount** - Skipped mounting sysfs in chroot. **Risk:** Java's JVM reads `/sys/devices/system/cpu` for CPU topology. Go runtime might also probe sysfs. Could cause runtime failures.
8. **Remove /dev/shm mount** - Skipped shared memory mount. **Risk:** Java uses shared memory for internal IPC. Go's runtime might use it. Could cause runtime crashes.
9. **Replace procfs hidepid cascade with single mount** - Instead of trying `hidepid=invisible`, `hidepid=2`, etc. (1-4 mount attempts), does a single plain `mount(proc)`. **Risk:** Without `hidepid`, sandbox processes can see all PIDs in `/proc`. Mitigated by PID namespace (only own PID tree visible), but it's a defense-in-depth regression.

## Recommendation

**Merge safe fixes (1-5).** They reduce the impact of hangs without any security tradeoff.

**For risky fixes (6-9):** Test Java and Go with these changes. If they work, consider:
- Bring back `MS_REC|MS_PRIVATE` (fix #6 revert) since security > speed
- Keep sysfs/shm removal only if Java/Go tests pass
- Keep simplified procfs (without hidepid) since PID namespace already isolates

The fundamental issue (kernel mount lock contention on cgroup v1) cannot be fully solved in userspace. The 3s setup budget is the pragmatic fix - it limits blast radius when the kernel blocks.

## Benchmark Results

### Before any fixes (x100 in VM):
- 59/100 OK, failures show as TLE with 22s wall time

### After safe fixes only (x100 in VM):
- 97-100/100 OK, failures show as IE with 10s wall time, batch completes in 10-14s

### On bare metal (all fixes, x100):
- 100/100 OK, 38 rps

## Files Changed

```
src/kernel/runtime_exec.rs     - Remove redundant unshare (SAFE)
src/sandbox/proxy.rs           - Watchdog thread, timed_out from atomic (SAFE)
src/sandbox/supervisor.rs      - 3s budget, fallback timed_out fix, IE classification (SAFE)
src/kernel/namespace.rs        - Non-recursive MS_PRIVATE (RISKY - consider reverting)
src/kernel/mount/filesystem.rs - Skip sysfs/shm, simplify procfs (RISKY - test Java/Go first)
```

## Test Commands

```bash
# VM setup (see multipass.md for full instructions)
multipass exec judge-bench -- sudo docker build -t rustbox:bench .
multipass exec judge-bench -- sudo docker run -d --name rustbox-bench -p 4096:4096 \
    --cpus=4 --memory=2g \
    --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID \
    --cap-add NET_ADMIN --cap-add MKNOD --cap-add DAC_OVERRIDE \
    --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
    --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -e RUSTBOX_WORKERS=2 rustbox:bench

# x100 stress test
for i in $(seq 1 100); do
    curl -s --max-time 60 -X POST "http://localhost:4096/api/submit?wait=true" \
        -H "Content-Type: application/json" -d @payload.json > /tmp/r_$i.json &
done; wait
```
