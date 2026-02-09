#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[phase2-smoke] this smoke test must run on Linux/WSL" >&2
  exit 2
fi

ensure_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    exec sudo -n "$0" "$@"
  fi
  echo "[phase2-smoke] root required (strict runtime path); run as root or configure passwordless sudo" >&2
  exit 2
}

ensure_root "$@"

RUNNER=(cargo run -q --bin rustbox -- execute-code --strict)

run_case() {
  local name="$1"
  local box_id="$2"
  local cpu_s="$3"
  local wall_s="$4"
  local processes="$5"
  local marker="$6"
  local code="$7"

  local out_file
  out_file="$(mktemp)"

  echo "[phase2-smoke] case=${name} box_id=${box_id} marker=${marker}"

  set +e
  "${RUNNER[@]}" \
    --box-id "${box_id}" \
    --language python \
    --cpu "${cpu_s}" \
    --wall-time "${wall_s}" \
    --processes "${processes}" \
    --code "${code}" >"${out_file}" 2>&1
  local rc=$?
  set -e

  echo "[phase2-smoke] case=${name} rc=${rc}"

  if pgrep -fa "${marker}" >/tmp/phase2-smoke-pgrep.txt 2>/dev/null; then
    echo "[phase2-smoke] FAIL: leftover processes matched marker ${marker}" >&2
    cat /tmp/phase2-smoke-pgrep.txt >&2
    cat "${out_file}" >&2
    rm -f "${out_file}"
    return 1
  fi

  if rustbox status 2>/dev/null | rg -q "rustbox/${box_id}"; then
    echo "[phase2-smoke] FAIL: sandbox rustbox/${box_id} still present after run" >&2
    cat "${out_file}" >&2
    rm -f "${out_file}"
    return 1
  fi

  if ! rg -q '"status"[[:space:]]*:[[:space:]]*"(TLE|SIG|IE|RE|SV|MLE|OK)"' "${out_file}"; then
    echo "[phase2-smoke] WARN: output did not include expected JSON status token" >&2
    cat "${out_file}" >&2
  fi

  rm -f "${out_file}"
}

BOX1=9201
MARK1="rbx_phase2_timeout_$$"
CODE1=$'import subprocess,time\nmarker="'"${MARK1}"$'"\nfor _ in range(6):\n    subprocess.Popen(["/usr/bin/python3","-c","import time; time.sleep(600)", marker])\nwhile True:\n    time.sleep(1)'

BOX2=9202
MARK2="rbx_phase2_desc_$$"
CODE2=$'import os,time,subprocess\nmarker="'"${MARK2}"$'"\nfor _ in range(32):\n    try:\n        if os.fork() == 0:\n            subprocess.Popen(["/usr/bin/python3","-c","import time; time.sleep(600)", marker])\n            while True:\n                time.sleep(1)\n    except OSError:\n        break\nwhile True:\n    time.sleep(1)'

run_case "timeout_descendants" "${BOX1}" 1 3 32 "${MARK1}" "${CODE1}"
run_case "fork_descendants" "${BOX2}" 1 3 64 "${MARK2}" "${CODE2}"

echo "[phase2-smoke] PASS"
