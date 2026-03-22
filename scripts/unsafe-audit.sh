#!/usr/bin/env bash
# unsafe-audit.sh — Tree visualization of unsafe code distribution
# Replaces cargo-geiger (which is broken on modern Rust toolchains)
# Exit code 1 if unsafe is found outside expected modules
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
DIM='\033[2m'
RESET='\033[0m'
BOLD='\033[1m'

SRC_DIR="${1:-src}"
FORBIDDEN_DIRS="verdict"

echo -e "${BOLD}rustbox unsafe audit${RESET}"
echo -e "${DIM}$(date -Iseconds)${RESET}"
echo ""

total=0
violations=0

echo -e "${BOLD}src/${RESET}"

dirs=$(find "$SRC_DIR" -mindepth 1 -maxdepth 1 -type d | sort)
dir_count=$(echo "$dirs" | wc -l)
i=0

for dir in $dirs; do
    i=$((i + 1))
    mod=$(basename "$dir")
    count=$(grep -rc "unsafe {" "$dir" --include="*.rs" 2>/dev/null | awk -F: '{s+=$2}END{print s+0}')
    total=$((total + count))

    connector="├──"
    sub_prefix="│  "
    if [ "$i" -eq "$dir_count" ]; then
        connector="└──"
        sub_prefix="   "
    fi

    if [ "$count" -eq 0 ]; then
        echo -e "  ${connector} ${GREEN}$mod/${RESET} ${DIM}(0 unsafe)${RESET}"
    elif echo "$FORBIDDEN_DIRS" | grep -qw "$mod"; then
        echo -e "  ${connector} ${RED}$mod/${RESET} $count unsafe ${RED}VIOLATION${RESET}"
        violations=$((violations + count))
        grep -rn "unsafe {" "$dir" --include="*.rs" 2>/dev/null | sed "s|^|  ${sub_prefix} |" | head -5
    else
        echo -e "  ${connector} ${YELLOW}$mod/${RESET} $count unsafe"
        grep -rn "unsafe {" "$dir" --include="*.rs" 2>/dev/null | while IFS= read -r line; do
            file=$(echo "$line" | cut -d: -f1 | sed "s|$SRC_DIR/||")
            lineno=$(echo "$line" | cut -d: -f2)
            src_file=$(echo "$line" | cut -d: -f1)
            has_safety=$(sed -n "$((lineno > 1 ? lineno - 1 : 1)),$((lineno))p" "$src_file" 2>/dev/null | grep -c "SAFETY:" || true)
            if [ "$has_safety" -gt 0 ]; then
                echo -e "  ${sub_prefix} ${DIM}$file:$lineno${RESET} ${GREEN}// SAFETY${RESET}"
            else
                echo -e "  ${sub_prefix} ${DIM}$file:$lineno${RESET} ${YELLOW}// no SAFETY comment${RESET}"
            fi
        done
    fi
done

echo ""
echo -e "${BOLD}Summary:${RESET} $total unsafe blocks total"
echo -e "  Forbidden: verdict/ (must be pure logic)"

if [ "$violations" -gt 0 ]; then
    echo -e "  ${RED}FAIL: $violations unsafe block(s) in forbidden modules${RESET}"
    exit 1
else
    echo -e "  ${GREEN}PASS: all unsafe in expected modules${RESET}"
    exit 0
fi
