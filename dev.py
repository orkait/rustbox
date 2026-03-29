#!/usr/bin/env python3
"""Rustbox development helper.

Usage:
    python dev.py build        # Build rustbox + judge-service
    python dev.py backend      # Start judge-service (needs sudo)
    python dev.py test         # Run all tests (cargo test + clippy + fmt)
    python dev.py curl         # Quick smoke test via curl
    python dev.py stress       # Build + run Docker stress test (serial curl)
    python dev.py bench        # Build + run hey load test (true throughput)
    python dev.py adversarial  # Build + run Docker adversarial tests
    python dev.py status       # Show backend health
"""

import subprocess
import sys
import os
import time
import signal
import shutil
import json
from pathlib import Path

ROOT = Path(__file__).parent.resolve()

RUSTBOX_PORT = 4096

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def log(msg, color=GREEN):
    print(f"{color}{BOLD}>>> {msg}{RESET}")

def err(msg):
    print(f"{RED}{BOLD}!!! {msg}{RESET}")

def run(cmd, cwd=None, check=True, capture=False, env=None):
    cwd = cwd or ROOT
    merged_env = {**os.environ, **(env or {})}
    if not capture:
        print(f"  {CYAN}$ {cmd}{RESET}")
    return subprocess.run(
        cmd, shell=True, cwd=str(cwd), check=check,
        capture_output=capture, text=True, env=merged_env,
    )

def check_tool(name):
    if not shutil.which(name):
        err(f"'{name}' not found in PATH.")
        sys.exit(1)


def cmd_build():
    log("Building rustbox + judge-service...")
    run("cargo build -p rustbox -p judge-service")
    log("Build complete.")


def cmd_backend():
    binary = ROOT / "target" / "debug" / "judge-service"
    if not binary.exists():
        log("Not built, building...", YELLOW)
        run("cargo build -p judge-service")

    be_env = {
        "RUSTBOX_DATABASE_URL": f"sqlite:///tmp/rustbox-dev.db",
        "RUSTBOX_PORT": str(RUSTBOX_PORT),
        "RUSTBOX_WORKERS": os.environ.get("RUSTBOX_WORKERS", "4"),
        "RUST_LOG": os.environ.get("RUST_LOG", "info"),
    }

    log(f"Starting judge-service on :{RUSTBOX_PORT} ...")
    log("  (Ctrl+C to stop)", YELLOW)

    euid = os.geteuid() if hasattr(os, "geteuid") else 1
    if euid != 0:
        log("Not root - running with sudo (sandbox needs root)", YELLOW)
        env_args = " ".join(f"{k}={v}" for k, v in be_env.items())
        cmd = f"sudo {env_args} {binary}"
    else:
        cmd = str(binary)

    try:
        run(cmd, env={**os.environ, **be_env})
    except KeyboardInterrupt:
        log("judge-service stopped.")


def cmd_test():
    log("Format check...")
    run("cargo fmt --all -- --check")
    log("Clippy...")
    run("cargo clippy --workspace -- -D warnings -A clippy::too_many_arguments -A clippy::type_complexity")
    log("Unit tests...")
    run("cargo test --workspace")
    log("All tests passed!", GREEN)


def cmd_curl():
    api_key = os.environ.get("RUSTBOX_API_KEY", "")
    key_header = f"-H 'x-api-key: {api_key}'" if api_key else ""
    base = f"http://localhost:{RUSTBOX_PORT}"

    log("Submitting Python hello world...")
    result = run(
        f"""curl -s -X POST {base}/api/submit?wait=true \
           -H 'Content-Type: application/json' \
           {key_header} \
           -d '{{"language":"python","code":"print(42)","stdin":""}}'""",
        capture=True, check=False,
    )
    if result.returncode != 0 or not result.stdout:
        err(f"Failed. Is the backend running on :{RUSTBOX_PORT}?")
        return

    try:
        r = json.loads(result.stdout)
        verdict = r.get("verdict", "?")
        stdout = (r.get("stdout") or "").strip()
        print(f"  {json.dumps(r, indent=2)}")
        if verdict == "AC" and stdout == "42":
            log("Smoke test PASSED!")
        else:
            log(f"Smoke test: verdict={verdict}, stdout='{stdout}'", YELLOW)
    except json.JSONDecodeError:
        err(f"Bad response: {result.stdout}")


def cmd_stress():
    log("Building stress test image...")
    run("docker build -t rustbox-stress -f docker/stress/Dockerfile .")
    log("Running throughput stress test (4 CPU, 4 GB)...")
    run("docker run --privileged --cpus=4 --memory=4g --rm rustbox-stress")


def cmd_bench():
    log("Building stress test image...")
    run("docker build -t rustbox-stress -f docker/stress/Dockerfile .")
    log("Running hey load test (50 requests, 12 concurrent, full roundtrip)...")
    run("""docker run --privileged --cpus=12 --memory=24g --rm --entrypoint bash rustbox-stress -c '
mkdir -p /sys/fs/cgroup/init
for pid in $(cat /sys/fs/cgroup/cgroup.procs 2>/dev/null); do echo "$pid" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true; done
echo "+memory +pids +cpu" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
mkdir -p /sys/fs/cgroup/rustbox
echo "+memory +pids +cpu" > /sys/fs/cgroup/rustbox/cgroup.subtree_control 2>/dev/null || true
RUSTBOX_PORT=4096 RUSTBOX_WORKERS=12 RUSTBOX_DATABASE_URL="sqlite:///tmp/b.db" RUST_LOG=error judge-service >/dev/null 2>&1 &
for i in $(seq 1 30); do curl -sf http://127.0.0.1:4096/api/health/ready >/dev/null 2>&1 && break; sleep 0.5; done
for i in 1 2 3; do curl -sf --max-time 30 -X POST "http://127.0.0.1:4096/api/submit?wait=true" -H "Content-Type: application/json" -d "{\\\"language\\\":\\\"python\\\",\\\"code\\\":\\\"print(1)\\\"}" >/dev/null; done
echo "=== hey: 50 requests, 12 concurrent, full sandbox roundtrip ==="
hey -n 50 -c 12 -m POST -H "Content-Type: application/json" -d "{\\\"language\\\":\\\"python\\\",\\\"code\\\":\\\"print(1)\\\"}" "http://127.0.0.1:4096/api/submit?wait=true"
kill %1 2>/dev/null; wait 2>/dev/null
'""")


def cmd_adversarial():
    log("Building stress test image...")
    run("docker build -t rustbox-stress -f docker/stress/Dockerfile .")
    log("Running adversarial + correctness + recovery tests...")
    run("docker run --privileged --cpus=4 --memory=4g --rm --entrypoint /opt/rustbox-tests/runners/run-all.sh rustbox-stress")


def cmd_status():
    base = f"http://localhost:{RUSTBOX_PORT}"
    result = run(f"curl -s {base}/api/health 2>/dev/null", capture=True, check=False)
    if result.returncode == 0 and result.stdout:
        try:
            h = json.loads(result.stdout)
            log(f"Backend: UP  workers={h.get('workers')} queue={h.get('queue_depth')} mode={h.get('enforcement_mode')}")
        except json.JSONDecodeError:
            log("Backend: UP (non-JSON response)", YELLOW)
    else:
        log("Backend: DOWN", RED)


COMMANDS = {
    "build": cmd_build,
    "backend": cmd_backend,
    "test": cmd_test,
    "curl": cmd_curl,
    "stress": cmd_stress,
    "bench": cmd_bench,
    "adversarial": cmd_adversarial,
    "status": cmd_status,
}

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "build"

    if cmd in ("-h", "--help", "help"):
        print(__doc__)
        sys.exit(0)

    if cmd not in COMMANDS:
        err(f"Unknown command: {cmd}")
        print(f"Available: {', '.join(COMMANDS.keys())}")
        sys.exit(1)

    check_tool("cargo")
    if cmd in ("stress", "adversarial"):
        check_tool("docker")

    try:
        COMMANDS[cmd]()
    except subprocess.CalledProcessError as e:
        err(f"Command failed with exit code {e.returncode}")
        sys.exit(e.returncode)
    except KeyboardInterrupt:
        print()
        log("Interrupted.")

if __name__ == "__main__":
    main()
