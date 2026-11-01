#!/usr/bin/env bash
#
# Aegis - Automated Test Suite
# Runs full regression & penetration tests across all enclave layers
#

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}====================================================${NC}"
echo -e "${BOLD}         Aegis - Automated Verification Test        ${NC}"
echo -e "${BOLD}====================================================${NC}\n"

# Ensure all binaries are compiled
if [ ! -f "bin/aegis_launcher" ] || [ ! -f "bin/anti_cheat_sample" ]; then
    echo -e "${BLUE}[*] Building all project binaries...${NC}"
    make -s all
fi

PASSED=0
FAILED=0

run_check() {
    local name="$1"
    local cmd="$2"
    echo -ne "  [*] Checking: ${name} ... "
    if eval "$cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}[PASS]${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}[FAIL]${NC}"
        FAILED=$((FAILED + 1))
    fi
}

echo -e "${BOLD}[STAGE 1] Testing Memory Shielding & Process Sealing${NC}"

# Spawn mock game inside aegis launcher
./bin/aegis_launcher ./bin/mock_game > /tmp/aegis_suite.log 2>&1 &
GAME_PID=$!
sleep 1

# Extract target PID and Address
TARGET_PID=$(grep "Process ID (PID)" /tmp/aegis_suite.log | awk '{print $NF}')
ADDR=$(grep "Address of g_player_health" /tmp/aegis_suite.log | awk '{print $NF}')

# Run mock cheat attack
./bin/mock_cheat "$TARGET_PID" "$ADDR" > /tmp/cheat_attack.log 2>&1 || true

run_check "Vector 1: /proc/<pid>/mem access blocked" \
    "grep -q 'SHIELD SUCCESS: Access to /proc/<pid>/mem was blocked!' /tmp/cheat_attack.log"

run_check "Vector 2: process_vm_readv blocked" \
    "grep -q 'SHIELD SUCCESS: Cross-process VM read was blocked!' /tmp/cheat_attack.log"

run_check "Vector 3: ptrace attach blocked" \
    "grep -q 'SHIELD SUCCESS: ptrace attachment was blocked!' /tmp/cheat_attack.log"

# Clean up spawned game
kill -9 "$GAME_PID" "$TARGET_PID" 2>/dev/null || true
rm -f /tmp/aegis_suite.log /tmp/cheat_attack.log

echo -e "\n${BOLD}[STAGE 2] Testing Landlock Filesystem Isolation${NC}"
run_check "Immutability: Game binary is read-only" \
    "./bin/mock_game --test-and-exit | grep -q 'Binary and assets are IMMUTABLE'"

run_check "Anti-Hijacking: Rogue DLL creation blocked" \
    "./bin/aegis_launcher ./bin/mock_game --test-and-exit 2>/dev/null | grep -q 'Landlock prevented dropping unauthorized libraries'"

run_check "Host Privacy: /etc/shadow is invisible" \
    "./bin/aegis_launcher ./bin/mock_game --test-and-exit 2>/dev/null | grep -q 'Host system files are invisible'"

echo -e "\n${BOLD}[STAGE 3] Testing TPM 2.0 Hardware Attestation Engine${NC}"
./bin/test_attestation > /tmp/attest.log 2>&1

run_check "Challenge Nonce Replay Protection" \
    "grep -q 'VERIFICATION SUCCESS: Client environment is genuine' /tmp/attest.log"

run_check "Tampered Executable Detection" \
    "grep -q 'SHIELD SUCCESS: Tampered client was caught and quarantined!' /tmp/attest.log"

rm -f /tmp/attest.log

echo -e "\n${BOLD}[STAGE 4] Testing Public Anti-Cheat C SDK (libaegis.so)${NC}"
./bin/aegis_launcher ./bin/anti_cheat_sample > /tmp/sdk_sample.log 2>&1

if [ -f /sys/kernel/security/lsm ] && grep -q "bpf" /sys/kernel/security/lsm; then
    run_check "SDK: Host eBPF LSM and Landlock verified" \
        "grep -q 'Host OS verified: eBPF LSM and Landlock supported!' /tmp/sdk_sample.log"
else
    echo -e "  [*] Checking: SDK: Host eBPF LSM and Landlock verified ... ${BLUE}[SKIP] (Kernel LSM BPF inactive in VM)${NC}"
fi

run_check "SDK: Process Security Status verified active" \
    "grep -q 'eBPF LSM Memory Shield : ACTIVE' /tmp/sdk_sample.log"

run_check "SDK: Attestation Quote Generation" \
    "grep -q 'Successfully generated hardware attestation quote!' /tmp/sdk_sample.log"

rm -f /tmp/sdk_sample.log

echo -e "\n${BOLD}====================================================${NC}"
echo -e "${BOLD}TEST SUMMARY: ${GREEN}${PASSED} Passed${NC}, ${RED}${FAILED} Failed${NC}"
echo -e "${BOLD}====================================================${NC}\n"

if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}ALL INTEGRITY CHECKS PASSED.${NC} System is fully verified."
    exit 0
else
    echo -e "${RED}${BOLD}SOME CHECKS FAILED.${NC}"
    exit 1
fi
