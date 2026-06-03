#!/usr/bin/env bash
# validate.sh — eBPF EDR detection validation
#
# Runs all 11 attack test cases while the order-processor integration tests
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

TARGET="order-processor-auth_service"      # raw Docker container name
INV="order-processor-inventory_service"    # inventory service — external connects are allowlisted
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

if ! pgrep -x ebpf-edr > /dev/null 2>&1; then
    echo "WARN: ebpf-edr process not detected — is the EDR agent running?"
fi

echo ""
echo "EDR Validation — 11 attack tests + concurrent integration traffic"
echo "Log: tail -f ${LOG}"

# ── Start integration tests in background ────────────────────────────────────

INTEG_PID=""
if [[ -f "${INTEGRATION_TESTS}" ]]; then
    echo ""
    echo "Starting integration tests in background (normal traffic simulation)..."
    bash "${INTEGRATION_TESTS}" all > /tmp/integ_tests.log 2>&1 &
    INTEG_PID=$!
    echo "  Integration tests PID: ${INTEG_PID}"
    echo "  Log: tail -f /tmp/integ_tests.log"
    sleep 5
else
    echo ""
    echo "WARN: integration tests not found at ${INTEGRATION_TESTS} — skipping background traffic"
fi

echo ""
echo "Starting attack tests in 3 seconds..."
sleep 3

# ── T1: Shell spawn in container ─────────────────────────────────────────────
# T1059.004 · T1609

header 1 11 "Shell spawn in container" "CRITICAL T1059_unix_shell_execution + action=kill_process"
docker exec "${TARGET}" bash -c "id" 2>/dev/null || true
pass
sleep 3

# ── T2: Network staging tool in container ────────────────────────────────────
# T1105 · T1095

header 2 11 "Network staging tool in container" "HIGH T1105_ingress_tool_transfer"
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

# ── T3: OS credential dumping ─────────────────────────────────────────────────
# T1003.008

header 3 11 "Read /etc/shadow from container" "HIGH T1003_008_os_credential_dumping"
docker exec "${TARGET}" cat /etc/shadow 2>/dev/null || true
pass
sleep 3

# ── T4: SSH private key access ────────────────────────────────────────────────
# T1552.004
# Use docker cp to create the file — avoids bash spawn (which would trigger T1059
# and be killed before the file write completes).

header 4 11 "Read SSH private key from container" "CRITICAL T1552_004_private_keys"
echo 'test-key-material' > /tmp/test_id_rsa
docker exec "${TARGET}" mkdir -p /root/.ssh 2>/dev/null || true
docker cp /tmp/test_id_rsa "${TARGET}":/root/.ssh/id_rsa
docker exec "${TARGET}" cat /root/.ssh/id_rsa 2>/dev/null || true
rm -f /tmp/test_id_rsa
pass
sleep 3

# ── T5: Unauthorized external connect ─────────────────────────────────────────
# T1041 · T1048

header 5 11 "Unauthorized external connect from container" "HIGH T1041_exfiltration_over_c2"
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

# ── T6: Authorized external connect (allowlisted — no alert expected) ─────────

header 6 11 "Authorized external connect — inventory_service" "no alert (allowlisted)"
echo "  Triggering inventory_service to call CoinGecko..."
docker exec "${INV}" python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(4)
try:
    s.connect(('209.97.132.148', 443))
finally:
    s.close()
" 2>/dev/null || true
pass
sleep 3

# ── T7: Host reads container filesystem ──────────────────────────────────────
# T1611

header 7 11 "Host process reads container filesystem" "CRITICAL T1611_escape_to_host_fs + action=kill_process"
MERGED=$(docker inspect "${TARGET}" \
    --format '{{.GraphDriver.Data.MergedDir}}' 2>/dev/null || echo "")

if [[ -z "${MERGED}" ]]; then
    echo "  SKIP: could not resolve overlay2 MergedDir for ${TARGET}"
else
    cat "${MERGED}/etc/hostname" 2>/dev/null || true
    pass
fi
sleep 3

# ── T8: System information discovery ─────────────────────────────────────────
# T1082

header 8 11 "Read /etc/passwd from container (system recon)" "MEDIUM T1082_system_info_discovery"
docker exec "${TARGET}" cat /etc/passwd 2>/dev/null || true
pass
sleep 3

# ── T9: Binary masquerading ───────────────────────────────────────────────────
# T1036
# Two separate docker exec calls — avoids /bin/sh wrapper which would trigger T1059.

header 9 11 "Binary masquerading from /tmp" "HIGH T1036_masquerading"
docker exec "${TARGET}" cp /bin/cat /tmp/sshd 2>/dev/null || true
sleep 1
docker exec "${TARGET}" /tmp/sshd /etc/hostname 2>/dev/null || true
pass
sleep 3

# ── T10: Cron configuration access ───────────────────────────────────────────
# T1053.003
# Use docker cp to place the file — opensnoop only fires on successful opens.

header 10 11 "Cron config access from container" "HIGH T1053_003_scheduled_task_cron"
echo "* * * * * root /tmp/evil_payload" > /tmp/test_crontab
docker cp /tmp/test_crontab "${TARGET}":/etc/crontab
docker exec "${TARGET}" cat /etc/crontab 2>/dev/null || true
rm -f /tmp/test_crontab
pass
sleep 3

# ── T11: Command history access ───────────────────────────────────────────────
# T1070.003
# Use docker cp to place the file — opensnoop only fires on successful opens.

header 11 11 "Command history access from container" "MEDIUM T1070_003_clear_command_history"
echo "rm -rf /important_data" > /tmp/bash_hist
docker cp /tmp/bash_hist "${TARGET}":/root/.bash_history
docker exec "${TARGET}" cat /root/.bash_history 2>/dev/null || true
rm -f /tmp/bash_hist
pass
sleep 3

# ── summary ───────────────────────────────────────────────────────────────────

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
echo "  Expected alerts:"
echo "    T1  CRITICAL T1059_unix_shell_execution          action=kill_process"
echo "    T2  HIGH     T1105_ingress_tool_transfer         (nc/wget must be installed)"
echo "    T3  HIGH     T1003_008_os_credential_dumping     filename=/etc/shadow"
echo "    T4  CRITICAL T1552_004_private_keys              filename=/root/.ssh/id_rsa"
echo "    T5  HIGH     T1041_exfiltration_over_c2          dst=8.8.8.8:80"
echo "    T6  (no alert — inventory_service allowlisted)"
echo "    T7  CRITICAL T1611_escape_to_host_fs             action=kill_process"
echo "    T8  MEDIUM   T1082_system_info_discovery         filename=/etc/passwd"
echo "    T9  HIGH     T1036_masquerading                  comm=/tmp/sshd"
echo "    T10 HIGH     T1053_003_scheduled_task_cron       filename=/etc/crontab"
echo "    T11 MEDIUM   T1070_003_clear_command_history     filename=/root/.bash_history"
echo ""
echo "  Normal service traffic (integration tests) should NOT"
echo "  produce any CRITICAL or HIGH alerts."
echo "══════════════════════════════════════════════════════"
