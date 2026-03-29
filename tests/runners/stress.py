#!/usr/bin/env python3
"""Parallel stress test with correctness verification.

Submits N requests concurrently, verifies every result.
Uses stdlib only (urllib + ThreadPoolExecutor).
"""

import json
import os
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HOST = os.environ.get("HOST", "http://127.0.0.1:4096")
SUBMIT = f"{HOST}/api/submit?wait=true"
TIERS = [int(x) for x in os.environ.get("TIERS", "1 5 10 25 50").split()]
CONCURRENCY = int(os.environ.get("CONCURRENCY", "12"))
EXPECTED_STDOUT = "41538"

PAYLOAD_FILE = os.environ.get(
    "PAYLOAD_FILE",
    str(Path(__file__).parent.parent / "payloads" / "correctness" / "sieve_500k.py"),
)

RED = "\033[1;31m"
GREEN = "\033[1;32m"
BOLD = "\033[1m"
RESET = "\033[0m"


def load_payload():
    with open(PAYLOAD_FILE) as f:
        code = f.read()
    return json.dumps({"language": "python", "code": code}).encode()


def submit_one(payload_bytes, idx):
    req = urllib.request.Request(
        SUBMIT,
        data=payload_bytes,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return idx, json.loads(r.read())
    except Exception as e:
        return idx, {"error": str(e), "verdict": None}


def run_tier(n, payload_bytes):
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=min(n, CONCURRENCY)) as pool:
        futures = [pool.submit(submit_one, payload_bytes, i) for i in range(n)]
        results = [f.result() for f in as_completed(futures)]

    elapsed = time.time() - t0
    tps = n / elapsed if elapsed > 0 else 0

    ok = 0
    ac = 0
    wrong = 0
    re = 0
    tle = 0
    ie = 0

    for idx, resp in results:
        verdict = resp.get("verdict", "")
        stdout = (resp.get("stdout") or "").strip()

        if verdict == "AC":
            ac += 1
            if stdout == EXPECTED_STDOUT:
                ok += 1
            else:
                wrong += 1
        elif verdict == "TLE":
            tle += 1
        elif verdict in ("RE", "SIG", "MLE"):
            re += 1
        else:
            ie += 1

    failures = n - ok
    status = f"{GREEN}PASS{RESET}" if failures == 0 else f"{RED}FAIL{RESET}"

    print(
        f"  {n:>5}x  {ok}/{n:<6}  {elapsed*1000:>8.0f}ms  {tps:>6.1f}/s  {status}",
        end="",
    )
    if failures > 0:
        print(f"  ac={ac} re={re} tle={tle} ie={ie} wrong={wrong}", end="")
    print()

    return failures


def main():
    print()
    print(f"{BOLD}=== Rustbox Parallel Stress Test ==={RESET}")
    print(f"  Payload:     {PAYLOAD_FILE}")
    print(f"  Expected:    stdout={EXPECTED_STDOUT}")
    print(f"  Concurrency: {CONCURRENCY}")
    print(f"  Tiers:       {TIERS}")
    print()
    print(f"  {'TIER':>5}   {'PASS':<7}  {'ELAPSED':>9}  {'TPS':>7}  RESULT")
    print(f"  {'-----':>5}   {'-------':<7}  {'---------':>9}  {'-------':>7}  ------")

    payload = load_payload()
    total_failures = 0

    for tier in TIERS:
        total_failures += run_tier(tier, payload)

    print()
    if total_failures == 0:
        print(f"{BOLD}VERDICT: {GREEN}ALL TIERS PASSED{RESET}")
    else:
        print(f"{BOLD}VERDICT: {RED}{total_failures} FAILURES{RESET}")

    sys.exit(0 if total_failures == 0 else 1)


if __name__ == "__main__":
    main()
