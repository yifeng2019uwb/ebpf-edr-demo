#!/usr/bin/env bash
# validate.sh — eBPF EDR detection validation
#
# Runs all 12 attack test cases while the order-processor integration tests
# run concurrently in the background. This validates two things at once:
#   1. Attack detection: each threat rule fires correctly
#   2. No false positives: normal service traffic does not trigger alerts
#
# Tests are distributed across services to confirm eBPF monitors the full stack:
#   auth_service      — T4 (ext-connect + block), T10 (container-mgmt), T11 (ingress-tool)
#   user_service      — T1 (shell-spawn), T3 (ssh-key), T7 (cron), T9 (credentials-env)
#   order_service     — T2 (shadow), T6 (masquerade)
#   insights_service  — T5 (passwd), T8 (history)
#   inventory_service — T12 (allowlisted external connect → NO alert)
#
# Run on the GCP VM as root while the EDR agent is running.
#
# Usage:
#   sudo ./validate.sh
#
# Watch alerts in a separate terminal:
#   tail -f alerts/alert.log

set -euo pipefail

AUTH_SVC="order-processor-auth_service"          # T4, T10, T11
USER_SVC="order-processor-user_service"          # T1, T3, T7, T9
ORDER_SVC="order-processor-order_service"        # T2, T6
INSIGHTS_SVC="order-processor-insights_service"  # T5, T8
INVENTORY_SVC="order-processor-inventory_service" # T12 (optional — skipped if not running)
# Alert log the agent writes. Resolved absolutely (script-relative) so it matches the
# agent's alerts/alert.log regardless of the caller's CWD. Override with ALERT_LOG_PATH
# if the agent writes elsewhere (e.g. its own ALERT_LOG_PATH env).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="${ALERT_LOG_PATH:-$SCRIPT_DIR/alerts/alert.log}"
INTEGRATION_TESTS="/home/yifeng2019/workspace/cloud-native-order-processor/integration_tests/run_all_tests.sh"

# Unique temp directory — avoids name collisions with stale files from previous runs.
TESTDIR=$(mktemp -d /tmp/edr_validate.XXXXXX)
trap "rm -rf ${TESTDIR}" EXIT

# ── helpers ───────────────────────────────────────────────────────────────────

header() {
    local num=$1 total=$2 name=$3 expect=$4
    echo ""
    echo "══════════════════════════════════════════════════════"
    echo "  TEST ${num}/${total} — ${name}"
    echo "  EXPECT: ${expect}"
    echo "══════════════════════════════════════════════════════"
}

PASS=0 FAIL=0 SKIP=0
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; ((PASS++)) || true; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; ((FAIL++)) || true; }
skip() { echo -e "${YELLOW}[SKIP]${NC} $*"; ((SKIP++)) || true; }

# Wait for alert matching pattern in log (poll every 2s, timeout 30s).
# Scans only the TAIL — the alert fires within ~2s of the attack, so it's at the very end;
# tailing also avoids matching stale alerts from earlier in a long-running log.
expect_alert() {
    local pattern=$1
    local timeout=${2:-30}

    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if tail -n 30 "${LOG}" 2>/dev/null | grep -qE "$pattern"; then
            return 0
        fi
        sleep 2
        ((elapsed += 2))
    done
    return 1
}

# Count matching alerts in log
count_alerts() {
    local pattern=$1
    tail -20 "${LOG}" 2>/dev/null | grep -c "$pattern" || echo 0
}

# Assert NO alert matching pattern appears within the window (inverse of expect_alert).
# Waits the full window first — alerts land within ~2s of the trigger, so a clean
# tail after the wait means the event was correctly suppressed.
expect_no_alert() {
    local pattern=$1
    local window=${2:-12}
    sleep "$window"
    if tail -n 30 "${LOG}" 2>/dev/null | grep -qE "$pattern"; then
        return 1
    fi
    return 0
}

# ── pre-flight ────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root — sudo ./validate.sh"
    exit 1
fi

for svc in "$AUTH_SVC" "$USER_SVC" "$ORDER_SVC" "$INSIGHTS_SVC"; do
    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${svc}$"; then
        echo "ERROR: container ${svc} is not running"
        exit 1
    fi
done

if ! pgrep -x ebpf-edr > /dev/null 2>&1; then
    echo "WARN: ebpf-edr process not detected — is the EDR agent running?"
fi

echo ""
echo "EDR Validation — 12 attack tests + concurrent integration traffic"
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

# ── T1: Shell spawn in container — user_service ───────────────────────────────
# T1059.004 · T1609

header 1 12 "Shell spawn in container (user_service)" "CRITICAL T1059_unix_shell_execution"
T1_SINCE=$(date +%s%N)
docker exec "${USER_SVC}" bash -c "id" 2>/dev/null || true
if expect_alert "CRITICAL.*T1059_unix_shell_execution.*user_service" 30; then
    pass "T1: CRITICAL T1059 detected"
else
    fail "T1: no CRITICAL T1059 alert within timeout"
fi
sleep 2

# ── T2: OS credential dumping — order_service ────────────────────────────────
# T1003.008

header 2 12 "Read /etc/shadow from container (order_service)" "CRITICAL T1003_008_os_credential_dumping"
T3_SINCE=$(date +%s%N)
docker exec "${ORDER_SVC}" cat /etc/shadow 2>/dev/null || true
if expect_alert "CRITICAL.*T1003_008_os_credential_dumping.*order_service" 30; then
    pass "T2: CRITICAL T1003_008 detected"
else
    fail "T2: no CRITICAL T1003_008 alert within timeout"
fi
sleep 2

# ── T3: SSH private key access — user_service ────────────────────────────────
# T1552.004
# Use docker cp to create the file — avoids bash spawn (which would trigger T1059
# and be killed before the file write completes).
# /tmp/id_rsa matches the id_rsa suffix → fires T1552_004 at HIGH.

header 3 12 "Read SSH private key from container (user_service)" "HIGH T1552_004_private_keys"
echo 'test-key-material' > "${TESTDIR}/id_rsa"
docker cp "${TESTDIR}/id_rsa" "${USER_SVC}":/tmp/id_rsa 2>/dev/null || true
docker exec "${USER_SVC}" cat /tmp/id_rsa 2>/dev/null || true
if expect_alert "HIGH.*T1552_004_private_keys.*user_service" 30; then
    pass "T3: HIGH T1552_004 detected"
else
    fail "T3: no HIGH T1552_004 alert within timeout"
fi
sleep 3

# ── T4: Unauthorized external connect + LPMTrie block verification — auth_service
# T1041 · T1048
# First connect: fires T1041 alert + writes 8.8.8.8 to blocked_ips BPF map.
# Second connect to same IP: must get EPERM (blocked at kernel before handshake).
# Third connect to private IP: must NOT get EPERM (private IPs never blocked).
# Map is flushed before the test so each validate.sh run is independent.

header 4 12 "Unauthorized external connect — block verification (auth_service)" "HIGH T1041_exfiltration_over_c2 + block_ip"

# Flush blocked_ips map so the test is repeatable across multiple validate.sh runs.
BLOCK_MAP_ID=$(sudo bpftool map show 2>/dev/null | awk '/blocked_ips/{print id} {id=$1}' | tr -d ':' | head -1)
if [[ -n "${BLOCK_MAP_ID}" ]]; then
    sudo bpftool map flush id "${BLOCK_MAP_ID}" 2>/dev/null && \
        echo "  Flushed blocked_ips map (id=${BLOCK_MAP_ID}) — clean slate for this run" || \
        echo "  WARN: could not flush blocked_ips map — step 1 may not fire if IP already blocked"
else
    echo "  WARN: blocked_ips map not found — is the agent running with LPMTrie support?"
fi

echo "  Step 1: first connect to 8.8.8.8 — fires alert + adds IP to blocked_ips map"
docker exec "${AUTH_SVC}" python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(('8.8.8.8', 80))
finally:
    s.close()
" 2>/dev/null || true
sleep 2

echo "  Step 2: second connect to 8.8.8.8 — expect EPERM (Operation not permitted)"
BLOCK_RESULT=$(docker exec "${AUTH_SVC}" python3 -c "
import socket, errno, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(('8.8.8.8', 80))
    print('FAIL: connection succeeded — IP not blocked')
    sys.exit(1)
except OSError as e:
    if e.errno == errno.EPERM:
        print('PASS: connection blocked (EPERM) — kernel enforcement working')
    else:
        print(f'WARN: unexpected error: {e}')
" 2>&1 || true)
echo "  ${BLOCK_RESULT}"

echo "  Step 3: connect to private IP (10.0.0.1) — expect no EPERM (private IPs never blocked)"
UNBLOCK_RESULT=$(docker exec "${AUTH_SVC}" python3 -c "
import socket, errno, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1)
try:
    s.connect(('10.0.0.1', 80))
    s.close()
    print('PASS: connection to private IP not blocked')
except OSError as e:
    if e.errno == errno.EPERM:
        print('FAIL: private IP was blocked — should never happen')
        sys.exit(1)
    else:
        print(f'PASS: private IP not blocked (got expected network error: {e.strerror})')
" 2>&1 || true)
echo "  ${UNBLOCK_RESULT}"

if expect_alert "HIGH.*T1041_exfiltration_over_c2.*auth_service.*8\.8\.8\.8" 30; then
    pass "T4: HIGH T1041 detected (block verification printed above)"
else
    fail "T4: no HIGH T1041 alert within timeout"
fi
sleep 3

# ── T5: System information discovery — insights_service ──────────────────────
# T1082

header 5 12 "Read /etc/passwd from container — system recon (insights_service)" "MEDIUM T1082_system_info_discovery"
docker exec "${INSIGHTS_SVC}" cat /etc/passwd 2>/dev/null || true
if expect_alert "MEDIUM.*T1082_system_info_discovery.*insights_service.*passwd" 30; then
    pass "T5: MEDIUM T1082 detected"
else
    fail "T5: no MEDIUM T1082 alert within timeout"
fi
sleep 3

# ── T6: Binary masquerading — order_service ───────────────────────────────────
# T1036
# Two separate docker exec calls — avoids /bin/sh wrapper which would trigger T1059.

header 6 12 "Binary masquerading from /tmp (order_service)" "HIGH T1036_masquerading"
docker exec "${ORDER_SVC}" cp /bin/cat /tmp/sshd 2>/dev/null || true
sleep 1
docker exec "${ORDER_SVC}" /tmp/sshd /etc/hostname 2>/dev/null || true
if expect_alert "HIGH.*T1036_masquerading.*order_service" 30; then
    pass "T6: HIGH T1036 detected"
else
    fail "T6: no HIGH T1036 alert within timeout"
fi
sleep 3

# ── T7: Cron configuration access — user_service ────────────────────────────
# T1053.003
# Use docker cp to place the file — lsm/file_open only fires on successful opens.

header 7 12 "Cron config access from container (user_service)" "HIGH T1053_003_scheduled_task_cron"
echo "* * * * * root /tmp/evil_payload" > "${TESTDIR}/crontab"
docker cp "${TESTDIR}/crontab" "${USER_SVC}":/etc/crontab
docker exec "${USER_SVC}" cat /etc/crontab 2>/dev/null || true
if expect_alert "HIGH.*T1053_003_scheduled_task_cron.*user_service" 30; then
    pass "T7: HIGH T1053_003 detected"
else
    fail "T7: no HIGH T1053_003 alert within timeout"
fi
sleep 3

# ── T8: Command history access — insights_service ───────────────────────────
# T1070.003
# Use docker cp to place the file — lsm/file_open only fires on successful opens.
# /tmp/.bash_history matches the .bash_history suffix → fires T1070 at MEDIUM.

header 8 12 "Command history access from container (insights_service)" "MEDIUM T1070_003_clear_command_history"
echo "rm -rf /important_data" > "${TESTDIR}/bash_history"
docker cp "${TESTDIR}/bash_history" "${INSIGHTS_SVC}":/tmp/.bash_history 2>/dev/null || true
docker exec "${INSIGHTS_SVC}" cat /tmp/.bash_history 2>/dev/null || true
if expect_alert "MEDIUM.*T1070_003_clear_command_history.*insights_service" 30; then
    pass "T8: MEDIUM T1070_003 detected"
else
    fail "T8: no MEDIUM T1070_003 alert within timeout"
fi
sleep 3

# ── T9: Credentials in .env file — user_service ─────────────────────────────
# T1552.001
# Use docker cp to place the .env file — lsm/file_open fires on successful opens.
# /tmp/app.env matches .env suffix → fires T1552_001_credentials_in_files at HIGH.

header 9 12 "Credentials in .env file from container (user_service)" "HIGH T1552_001_credentials_in_files"
echo "DB_PASSWORD=super_secret_password" > "${TESTDIR}/app.env"
docker cp "${TESTDIR}/app.env" "${USER_SVC}":/tmp/app.env 2>/dev/null || true
docker exec "${USER_SVC}" cat /tmp/app.env 2>/dev/null || true
if expect_alert "HIGH.*T1552_001_credentials_in_files.*user_service" 30; then
    pass "T9: HIGH T1552_001 detected"
else
    fail "T9: no HIGH T1552_001 alert within timeout"
fi
sleep 3

# ── T10: Container management tool execution — auth_service ──────────────────
# T1613
# Copy the docker binary from the host into the container and execute it.
# /usr/local/bin/docker matches the /docker suffix → fires T1613_container_resource_discovery.
# The command fails at runtime (no socket in container) but the execve fires the alert.

header 10 12 "Container management tool in container (auth_service)" "HIGH T1613_container_resource_discovery"
if which docker > /dev/null 2>&1; then
    docker cp "$(which docker)" "${AUTH_SVC}":/usr/local/bin/docker 2>/dev/null || true
    docker exec "${AUTH_SVC}" /usr/local/bin/docker ps 2>/dev/null || true
else
    echo "  SKIP: docker not on PATH — cannot copy binary to container"
fi
if expect_alert "HIGH.*T1613_container_resource_discovery.*auth_service" 30; then
    pass "T10: HIGH T1613 detected"
else
    fail "T10: no HIGH T1613 alert within timeout"
fi
sleep 3

# ── T11: Ingress tool transfer — auth_service ─────────────────────────────────
# T1105 · T1095
# The rule matches the exec path suffix (network_tools: nc, ncat, wget) — the exec
# event fires at sys_enter_execve, so the binary's behavior doesn't matter. Same
# trick as T6/T10: copy an in-container binary under the tool name and exec it
# (no static nc/wget needed in the image).

header 11 12 "Ingress tool transfer (auth_service)" "HIGH T1105_ingress_tool_transfer"
docker exec "${AUTH_SVC}" cp /bin/cat /usr/local/bin/wget 2>/dev/null || true
sleep 1
docker exec "${AUTH_SVC}" /usr/local/bin/wget /etc/hostname 2>/dev/null || true
if expect_alert "HIGH.*T1105_ingress_tool_transfer.*auth_service" 30; then
    pass "T11: HIGH T1105 detected"
else
    fail "T11: no HIGH T1105 alert within timeout"
fi
sleep 3

# ── T12: Allowlisted external connect — inventory_service — expect NO alert ──
# T1041 exception: inventory_service is in allowed_services (calls CoinGecko for
# live market data), so its external connects must be suppressed, not alerted.
# Uses 1.1.1.1 (not 8.8.8.8) so T4's block_ip on 8.8.8.8 can never mask this
# test once kernel-level blocking is active.

header 12 12 "Allowlisted external connect (inventory_service)" "NO T1041 alert (service allowlisted)"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${INVENTORY_SVC}$"; then
    docker exec "${INVENTORY_SVC}" python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(('1.1.1.1', 80))
finally:
    s.close()
" 2>/dev/null || true
    if expect_no_alert "T1041_exfiltration_over_c2.*inventory" 12; then
        pass "T12: no T1041 alert for allowlisted inventory_service (correct suppression)"
    else
        fail "T12: T1041 fired for allowlisted inventory_service — allowed_services exception broken"
    fi
else
    skip "T12: ${INVENTORY_SVC} not running"
fi

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
echo -e "  ${GREEN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}  ${YELLOW}${SKIP} skipped${NC}"
echo "══════════════════════════════════════════════════════"
echo ""
echo "  Log: tail -20 ${LOG}"
echo "══════════════════════════════════════════════════════"
