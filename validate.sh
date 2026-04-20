#!/usr/bin/env bash
# validate.sh — eBPF EDR detection validation
#
# Runs all 7 attack test cases while the order-processor integration tests
# run concurrently in the background. This validates two things at once:
#   1. Attack detection: each threat rule fires correctly
#   2. No false positives: normal service traffic does not trigger alerts
#
# Run on the GCP VM as root while the EDR agent is running.
#
# Usage:
#   sudo ./validate.sh
#
# Watch alerts in a separate terminal:
#   tail -f alerts/alert.log

set -euo pipefail

TARGET="order-processor-auth_service"
INV="order-processor-inventory_service"
LOG="alerts/alert.log"
INTEGRATION_TESTS="/home/yifeng2019/workspace/cloud-native-order-processor/integration_tests/run_all_tests.sh"

# ── helpers ───────────────────────────────────────────────────────────────────

header() {
    local num=$1 total=$2 name=$3 expect=$4
    echo ""
    echo "══════════════════════════════════════════════════════"
    echo "  TEST ${num}/${total} — ${name}"
    echo "  EXPECT: ${expect}"
    echo "══════════════════════════════════════════════════════"
}

pass() { echo "  [OK] command sent — check alert.log"; }

# ── pre-flight ────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root — sudo ./validate.sh"
    exit 1
fi

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${TARGET}$"; then
    echo "ERROR: container ${TARGET} is not running"
    exit 1
fi

if ! pgrep -x ebpf-edr-demo > /dev/null 2>&1; then
    echo "WARN: ebpf-edr-demo process not detected — is the EDR agent running?"
fi

echo ""
echo "EDR Validation — 7 attack tests + concurrent integration traffic"
echo "Log: tail -f ${LOG}"

# ── Start integration tests in background ────────────────────────────────────
# Runs the full order-processor test suite concurrently while attack tests fire.
# Goal: EDR must catch the attacks without false-positiving on normal API traffic.

INTEG_PID=""
if [[ -f "${INTEGRATION_TESTS}" ]]; then
    echo ""
    echo "Starting integration tests in background (normal traffic simulation)..."
    bash "${INTEGRATION_TESTS}" all > /tmp/integ_tests.log 2>&1 &
    INTEG_PID=$!
    echo "  Integration tests PID: ${INTEG_PID}"
    echo "  Log: tail -f /tmp/integ_tests.log"
    sleep 5  # let services receive initial traffic before attacks begin
else
    echo ""
    echo "WARN: integration tests not found at ${INTEGRATION_TESTS} — skipping background traffic"
fi

echo ""
echo "Starting attack tests in 3 seconds..."
sleep 3

# ── T1: Shell spawn in container ─────────────────────────────────────────────

header 1 7 "Shell spawn in container" "CRITICAL shell_spawn_container"
docker exec "${TARGET}" bash -c "id" 2>/dev/null || true
pass
sleep 3

# ── T2: Network recon tool in container ──────────────────────────────────────

header 2 7 "Network tool in container" "HIGH network_tool_container"
# Try nc first (netcat-openbsd ships in many Debian-based images).
# Fall back to wget if nc is absent (requires apt-get install, which may fail
# due to missing /var/lib/apt/lists/partial perms in hardened containers).
if docker exec "${TARGET}" which nc > /dev/null 2>&1; then
    echo "  Using nc (already installed)"
    docker exec "${TARGET}" nc -w 2 1.1.1.1 80 2>/dev/null || true
elif docker exec "${TARGET}" which ncat > /dev/null 2>&1; then
    echo "  Using ncat (already installed)"
    docker exec "${TARGET}" ncat -w 2 1.1.1.1 80 2>/dev/null || true
else
    echo "  nc/ncat not found — attempting apt-get install wget (may fail in hardened containers)"
    docker exec "${TARGET}" apt-get update -qq 2>/dev/null || true
    docker exec "${TARGET}" apt-get install -y wget -q 2>/dev/null || true
    docker exec "${TARGET}" wget --timeout=2 -q http://1.1.1.1 2>/dev/null || true
fi
pass
sleep 3

# ── T3: Read /etc/shadow ──────────────────────────────────────────────────────

header 3 7 "Read /etc/shadow from container" "HIGH sensitive_file_access"
docker exec "${TARGET}" cat /etc/shadow 2>/dev/null || true
pass
sleep 3

# ── T4: Read SSH private key ──────────────────────────────────────────────────

header 4 7 "Read SSH private key from container" "CRITICAL sensitive_file_access"

# Create a test key so the file exists to be read
# Note: bash spawn here also triggers CRITICAL shell_spawn_container — expected
docker exec "${TARGET}" bash -c \
    "mkdir -p /root/.ssh && echo 'test-key-material' > /root/.ssh/id_rsa" \
    2>/dev/null || true
sleep 1

docker exec "${TARGET}" cat /root/.ssh/id_rsa 2>/dev/null || true
pass
sleep 3

# ── T5: Unauthorized external network connect ─────────────────────────────────

header 5 7 "Unauthorized external connect from container" "HIGH unauthorized_external_connect"
docker exec "${TARGET}" python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(('8.8.8.8', 80))
finally:
    s.close()
" 2>/dev/null || true
pass
sleep 3

# ── T6: Authorized external connect (inventory_service audit log) ─────────────

header 6 7 "Authorized external connect — inventory_service" "LOW external_connect_allowed"
echo "  Triggering inventory_service to call CoinGecko..."
echo "  Run manually in another terminal if needed:"
echo "    curl http://localhost:8080/api/v1/assets"
echo ""
# Attempt direct socket from inventory_service as a fallback trigger
docker exec "${INV}" python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(4)
try:
    s.connect(('209.97.132.148', 443))  # api.coingecko.com — verify IP before use
finally:
    s.close()
" 2>/dev/null || true
pass
sleep 3

# ── T7: Host reads container filesystem ──────────────────────────────────────

header 7 7 "Host process reads container filesystem" "CRITICAL host_reads_container_fs"

MERGED=$(docker inspect "${TARGET}" \
    --format '{{.GraphDriver.Data.MergedDir}}' 2>/dev/null || echo "")

if [[ -z "${MERGED}" ]]; then
    echo "  SKIP: could not resolve overlay2 MergedDir for ${TARGET}"
    echo "  Run manually: cat /var/lib/docker/overlay2/<id>/merged/etc/hostname"
else
    cat "${MERGED}/etc/hostname" 2>/dev/null || true
    pass
fi
sleep 3

# ── summary ───────────────────────────────────────────────────────────────────

# Wait for integration tests to finish (or report if still running)
if [[ -n "${INTEG_PID}" ]]; then
    echo ""
    if kill -0 "${INTEG_PID}" 2>/dev/null; then
        echo "  Integration tests still running (PID ${INTEG_PID})"
        echo "  Wait for them or kill: kill ${INTEG_PID}"
        echo "  Output: tail -f /tmp/integ_tests.log"
    else
        wait "${INTEG_PID}" && STATUS=0 || STATUS=$?
        if [[ ${STATUS} -eq 0 ]]; then
            echo "  Integration tests: PASSED (no service errors during attack window)"
        else
            echo "  Integration tests: exit ${STATUS} — check /tmp/integ_tests.log"
        fi
    fi
fi

echo ""
echo "══════════════════════════════════════════════════════"
echo "  All attack tests sent."
echo "  Verify results:"
echo "    tail -20 ${LOG}"
echo ""
echo "  Expected attack alerts:"
echo "    T1  CRITICAL shell_spawn_container"
echo "    T2  HIGH     network_tool_container      (nc / ncat / wget)"
echo "    T3  HIGH     sensitive_file_access  (/etc/shadow)"
echo "    T4  CRITICAL sensitive_file_access  (/root/.ssh/id_rsa)"
echo "    T5  HIGH     unauthorized_external_connect"
echo "    T6  LOW      external_connect_allowed"
echo "    T7  CRITICAL host_reads_container_fs"
echo ""
echo "  Normal service traffic (integration tests) should NOT"
echo "  produce any CRITICAL or HIGH alerts."
echo "══════════════════════════════════════════════════════"
