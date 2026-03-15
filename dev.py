#!/usr/bin/env python3
"""Rustbox development environment launcher.

Usage:
    python dev.py              # Start everything (infra + backend + frontend)
    python dev.py up           # Same as above
    python dev.py infra        # Start only Postgres + Redis
    python dev.py backend      # Start only judge-service (assumes infra running)
    python dev.py frontend     # Start only web dev server
    python dev.py build        # Build everything (cargo + npm)
    python dev.py down         # Stop all Docker containers
    python dev.py status       # Show status of all components
    python dev.py test         # Run all tests
    python dev.py curl         # Quick smoke test via curl
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
WEB_DIR = ROOT / "web"

# Colors
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
    """Run a command, printing it first."""
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
        err(f"'{name}' not found in PATH. Please install it.")
        sys.exit(1)

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_infra():
    """Start Postgres + Redis via docker compose."""
    log("Starting Postgres + Redis...")
    run("docker compose up -d postgres redis")
    log("Waiting for services to be healthy...")
    for _ in range(30):
        result = run(
            "docker compose ps --format json",
            capture=True, check=False,
        )
        if result.returncode != 0:
            time.sleep(1)
            continue
        lines = result.stdout.strip().split("\n")
        all_healthy = True
        for line in lines:
            if not line.strip():
                continue
            try:
                svc = json.loads(line)
                name = svc.get("Service", svc.get("Name", ""))
                status = svc.get("Health", svc.get("Status", ""))
                if name in ("postgres", "redis") and "healthy" not in status.lower():
                    all_healthy = False
            except json.JSONDecodeError:
                all_healthy = False
        if all_healthy and lines:
            break
        time.sleep(1)
    else:
        err("Timed out waiting for infra. Check: docker compose ps")
        return False
    log("Postgres + Redis ready.")
    return True


def cmd_build():
    """Build backend + frontend."""
    log("Building judge-service...")
    run("cargo build -p judge-service")
    log("Building rustbox...")
    run("cargo build -p rustbox")
    if (WEB_DIR / "package.json").exists():
        log("Installing web dependencies...")
        run("npm install --legacy-peer-deps", cwd=WEB_DIR)
        log("Building web frontend...")
        run("npx vite build", cwd=WEB_DIR)
    log("Build complete.", GREEN)


def cmd_backend():
    """Start judge-service (needs sudo for sandbox)."""
    binary = ROOT / "target" / "debug" / "judge-service"
    if not binary.exists():
        log("judge-service not built, building...", YELLOW)
        run("cargo build -p judge-service")

    log("Starting judge-service on :8080 ...")
    log("  (Ctrl+C to stop)", YELLOW)

    env = {
        "RUSTBOX_DATABASE_URL": "postgres://rustbox:rustbox@localhost:5433/rustbox",
        "RUSTBOX_REDIS_URL": "redis://127.0.0.1:6379",
        "RUSTBOX_PORT": "8080",
        "RUSTBOX_WORKERS": os.environ.get("RUSTBOX_WORKERS", "2"),
        "RUST_LOG": os.environ.get("RUST_LOG", "info"),
    }

    euid = os.geteuid() if hasattr(os, "geteuid") else 1
    cmd = str(binary)
    if euid != 0:
        log("Not root — running with sudo (sandbox needs root)", YELLOW)
        env_args = " ".join(f"{k}={v}" for k, v in env.items())
        cmd = f"sudo {env_args} {binary}"
        env = None  # sudo handles env

    try:
        run(cmd, env=env)
    except KeyboardInterrupt:
        log("judge-service stopped.")


def cmd_frontend():
    """Start Vite dev server."""
    if not (WEB_DIR / "node_modules").exists():
        log("Installing web dependencies...", YELLOW)
        run("npm install --legacy-peer-deps", cwd=WEB_DIR)

    log("Starting web dev server on :3000 ...")
    log("  (Ctrl+C to stop)", YELLOW)
    try:
        run("npx vite", cwd=WEB_DIR)
    except KeyboardInterrupt:
        log("Web server stopped.")


def cmd_up():
    """Start everything: infra, then backend + frontend in parallel."""
    if not cmd_infra():
        return

    log("Starting backend + frontend...")
    log("  Backend:  http://localhost:8080/api/health")
    log("  Frontend: http://localhost:3000")
    log("  (Ctrl+C to stop all)", YELLOW)

    procs = []
    try:
        # Backend
        binary = ROOT / "target" / "debug" / "judge-service"
        if not binary.exists():
            log("Building judge-service...", YELLOW)
            run("cargo build -p judge-service")

        backend_env = {
            **os.environ,
            "RUSTBOX_DATABASE_URL": "postgres://rustbox:rustbox@localhost:5433/rustbox",
            "RUSTBOX_REDIS_URL": "redis://127.0.0.1:6379",
            "RUSTBOX_PORT": "8080",
            "RUSTBOX_WORKERS": os.environ.get("RUSTBOX_WORKERS", "2"),
            "RUST_LOG": os.environ.get("RUST_LOG", "info"),
        }

        euid = os.geteuid() if hasattr(os, "geteuid") else 1
        if euid != 0:
            env_args = " ".join(
                f"{k}={v}" for k, v in {
                    "RUSTBOX_DATABASE_URL": "postgres://rustbox:rustbox@localhost:5433/rustbox",
                    "RUSTBOX_REDIS_URL": "redis://127.0.0.1:6379",
                    "RUSTBOX_PORT": "8080",
                    "RUSTBOX_WORKERS": os.environ.get("RUSTBOX_WORKERS", "2"),
                    "RUST_LOG": os.environ.get("RUST_LOG", "info"),
                }.items()
            )
            backend_cmd = f"sudo {env_args} {binary}"
            backend_proc = subprocess.Popen(
                backend_cmd, shell=True, cwd=str(ROOT),
            )
        else:
            backend_proc = subprocess.Popen(
                [str(binary)], cwd=str(ROOT), env=backend_env,
            )
        procs.append(("backend", backend_proc))

        # Frontend
        if not (WEB_DIR / "node_modules").exists():
            run("npm install --legacy-peer-deps", cwd=WEB_DIR)

        frontend_proc = subprocess.Popen(
            "npx vite", shell=True, cwd=str(WEB_DIR), env=os.environ,
        )
        procs.append(("frontend", frontend_proc))

        # Wait for any to exit
        while True:
            for name, proc in procs:
                ret = proc.poll()
                if ret is not None:
                    log(f"{name} exited with code {ret}", RED if ret else GREEN)
                    raise KeyboardInterrupt
            time.sleep(0.5)

    except KeyboardInterrupt:
        log("Shutting down...")
        for name, proc in procs:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                log(f"  {name} stopped")


def cmd_down():
    """Stop all Docker containers."""
    log("Stopping Docker containers...")
    run("docker compose down")
    log("Done.")


def cmd_status():
    """Show status of all components."""
    log("Docker containers:")
    run("docker compose ps", check=False)
    print()

    # Check backend
    result = run(
        "curl -s http://localhost:8080/api/health 2>/dev/null",
        capture=True, check=False,
    )
    if result.returncode == 0 and result.stdout:
        try:
            health = json.loads(result.stdout)
            log(f"Backend:  UP (workers={health.get('workers')}, queue={health.get('queue_depth')})")
        except json.JSONDecodeError:
            log("Backend:  UP (response not JSON)", YELLOW)
    else:
        log("Backend:  DOWN", RED)

    # Check frontend
    result = run(
        "curl -s -o /dev/null -w '%{http_code}' http://localhost:3000 2>/dev/null",
        capture=True, check=False,
    )
    if result.returncode == 0 and result.stdout.strip() == "200":
        log("Frontend: UP (http://localhost:3000)")
    else:
        log("Frontend: DOWN", RED)


def cmd_test():
    """Run all tests."""
    log("Running rustbox unit + integration tests...")
    run("cargo test -p rustbox --all")
    log("Running judge-service check...")
    run("cargo check -p judge-service")
    if (WEB_DIR / "package.json").exists():
        log("Type-checking frontend...")
        run("npx tsc --noEmit", cwd=WEB_DIR)
    log("All tests passed!", GREEN)


def cmd_curl():
    """Quick smoke test via curl."""
    log("Submitting Python hello world...")
    result = run(
        """curl -s -X POST http://localhost:8080/api/submit \
           -H 'Content-Type: application/json' \
           -d '{"language":"python","code":"print(42)","stdin":""}'""",
        capture=True, check=False,
    )
    if result.returncode != 0 or not result.stdout:
        err(f"Submit failed. Is the backend running? ({result.stderr})")
        return

    print(f"  Response: {result.stdout}")
    try:
        resp = json.loads(result.stdout)
        job_id = resp["id"]
    except (json.JSONDecodeError, KeyError):
        err("Unexpected response format")
        return

    log(f"Polling result for {job_id}...")
    for i in range(30):
        time.sleep(0.5)
        result = run(
            f"curl -s http://localhost:8080/api/result/{job_id}",
            capture=True, check=False,
        )
        if result.returncode != 0:
            continue
        try:
            r = json.loads(result.stdout)
            status = r.get("status", "")
            if status in ("completed", "error"):
                print(f"  {json.dumps(r, indent=2)}")
                verdict = r.get("verdict", "?")
                stdout = (r.get("stdout") or "").strip()
                if verdict == "Ok" and stdout == "42":
                    log("Smoke test PASSED!", GREEN)
                else:
                    log(f"Smoke test: verdict={verdict}, stdout='{stdout}'", YELLOW)
                return
        except json.JSONDecodeError:
            pass

    err("Timed out waiting for result")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

COMMANDS = {
    "up": cmd_up,
    "infra": cmd_infra,
    "backend": cmd_backend,
    "frontend": cmd_frontend,
    "build": cmd_build,
    "down": cmd_down,
    "status": cmd_status,
    "test": cmd_test,
    "curl": cmd_curl,
}

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "up"

    if cmd in ("-h", "--help", "help"):
        print(__doc__)
        sys.exit(0)

    if cmd not in COMMANDS:
        err(f"Unknown command: {cmd}")
        print(f"Available: {', '.join(COMMANDS.keys())}")
        sys.exit(1)

    # Check prerequisites
    check_tool("docker")
    if cmd in ("backend", "up"):
        check_tool("cargo")
    if cmd in ("frontend", "up", "build"):
        check_tool("npm")

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
