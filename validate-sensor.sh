#!/usr/bin/env bash
# validate-sensor.sh — eBPF EDR detection validation for sensor containers
#
# Tests 6 attack scenarios against the sensor containers running on this VM.
# With the debug logging enabled, also shows exactly where file events flow
# through the pipeline — useful for diagnosing why cat/file access alerts may
# not fire.
#
# Run on the sensor VM as root while the EDR agent is running.
#
# Usage:
#   sudo ./validate-sensor.sh
#
# Watch alerts + debug log in separate terminals:
#   tail -f alerts/alert.log
#   sudo journalctl -u ebpf-edr -f | grep "DBG file"

set -euo pipefail

TARGET="sensor-env-sensor-1"   # env-sensor container (has /etc/sensor/tls/ certs)
LOG="alerts/alert.log"

# ── helpers ───────────────────────────────────────────────────────────────────

header() {
    local num=$1 total=$2 name=$3 expect=$4
    echo ""
    echo "══════════════════════════════════════════════════════"
    echo "  TEST ${num}/${total} — ${name}"
    echo "  EXPECT: ${expect}"
    echo "══════════════════════════════════════════════════════"
}

pass() { echo "  [OK] command sent — check alert.log and journalctl DBG lines"; }

check_log() {
    local rule=$1 comm=$2
    sleep 1
    if grep -q "rule=${rule}" "${LOG}" 2>/dev/null && grep -q "comm=${comm}" "${LOG}" 2>/dev/null; then
        echo "  [PASS] found rule=${rule} comm=${comm} in alert.log"
    else
        echo "  [MISS] rule=${rule} comm=${comm} not found yet — check DBG logs:"
        echo "         sudo journalctl -u ebpf-edr --since '30 seconds ago' | grep 'DBG file'"
    fi
}

# ── pre-flight ────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root — sudo ./validate-sensor.sh"
    exit 1
fi

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${TARGET}$"; then
    echo "ERROR: container ${TARGET} is not running"
    echo "       Run: docker compose -f /opt/sensor/docker-compose.yml ps"
    exit 1
fi

if ! pgrep -x ebpf-edr-demo > /dev/null 2>&1; then
    echo "WARN: ebpf-edr-demo process not detected — is the EDR agent running?"
    echo "      Check: sudo systemctl status ebpf-edr"
fi

# Record alert.log line count so we can show only new alerts at the end
LOG_START=$(wc -l < "${LOG}" 2>/dev/null || echo 0)

echo ""
echo "EDR Sensor Validation — 6 attack tests"
echo "Target container: ${TARGET}"
echo ""
echo "Watch alerts live:    tail -f ${LOG}"
echo "Watch debug pipeline: sudo journalctl -u ebpf-edr -f | grep 'DBG file'"
echo ""
echo "Starting in 3 seconds..."
sleep 3

# ── T1: Shell spawn ───────────────────────────────────────────────────────────

header 1 6 "Shell spawn in container" "CRITICAL shell_spawn_container service=env-sensor"
docker exec "${TARGET}" sh -c "id" 2>/dev/null || true
pass
sleep 3

# ── T2: Network recon tool ────────────────────────────────────────────────────

header 2 6 "Network tool in container" "HIGH network_tool_container service=env-sensor"
# Alpine busybox includes nc
docker exec "${TARGET}" nc -w 2 1.1.1.1 80 2>/dev/null || true
pass
sleep 3

# ── T3: Read device private key (the key debug test) ─────────────────────────
# This is the main regression: sensitive_file_access should fire for cat.
# DBG lines show: file-enrich → (file-pending?) → file-detect → alert
# If file-detect appears but no alert: rule logic bug
# If file-enrich appears but no file-detect: enrichedCh drop
# If no file-enrich at all: eBPF probe not capturing the event

header 3 6 "Read device private key" "HIGH sensitive_file_access filename=/etc/sensor/tls/device.key"
echo "  After this command, run:"
echo "    sudo journalctl -u ebpf-edr --since '5 seconds ago' | grep 'DBG file.*device'"
echo ""
docker exec "${TARGET}" cat /etc/sensor/tls/device.key 2>/dev/null || true
pass
check_log "sensitive_file_access" "cat"
sleep 3

# ── T4: Read CA cert (.crt is not in highFileSuffixes — expected: no alert) ───

header 4 6 "Read CA cert (.crt — not a monitored suffix)" "NO ALERT expected for .crt"
docker exec "${TARGET}" cat /etc/sensor/tls/ca.crt 2>/dev/null || true
echo "  NOTE: .crt is NOT in highFileSuffixes — no alert expected."
echo "        If you want .crt monitored, add it to policy.go."
pass
sleep 3

# ── T5: Read /etc/passwd (system recon) ──────────────────────────────────────

header 5 6 "Read /etc/passwd from container" "MEDIUM sensitive_file_access service=env-sensor"
docker exec "${TARGET}" cat /etc/passwd 2>/dev/null || true
pass
check_log "sensitive_file_access" "cat"
sleep 3

# ── T6: Unauthorized external connect ────────────────────────────────────────

header 6 6 "Unauthorized external connect" "HIGH unauthorized_external_connect service=env-sensor"
# nc also triggers network_tool_container — both alerts expected
docker exec "${TARGET}" nc -w 2 8.8.8.8 80 2>/dev/null || true
pass
sleep 3

# ── summary ───────────────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════════════"
echo "  All tests sent. New alerts since test start:"
echo ""
tail -n "+$((LOG_START + 1))" "${LOG}" 2>/dev/null | sed 's/^/  /' || echo "  (no new alerts)"
echo ""
echo "  Expected:"
echo "    T1  CRITICAL shell_spawn_container        service=env-sensor  comm=sh"
echo "    T2  HIGH     network_tool_container        service=env-sensor  comm=nc"
echo "    T3  HIGH     sensitive_file_access         filename=/etc/sensor/tls/device.key  comm=cat"
echo "    T4  (no alert — .crt not in highFileSuffixes)"
echo "    T5  MEDIUM   sensitive_file_access         filename=/etc/passwd  comm=cat"
echo "    T6  HIGH     network_tool_container        service=env-sensor  comm=nc"
echo "         HIGH     unauthorized_external_connect dst=8.8.8.8:80"
echo ""
echo "  Debug pipeline (trace where file events go):"
echo "    sudo journalctl -u ebpf-edr --since '5 minutes ago' | grep 'DBG file' | grep -E 'device|passwd'"
echo "  Look for:"
echo "    DBG file-enrich  → eBPF probe captured the event, state=resolved/pending"
echo "    DBG file-pending → event queued, waiting for container resolution"
echo "    DBG file-drop    → enrichedCh was full, event dropped (should be rare now)"
echo "    DBG file-detect  → event reached detector; if this appears but no alert,"
echo "                       the rule logic itself is the bug"
echo "══════════════════════════════════════════════════════"
