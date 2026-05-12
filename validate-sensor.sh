#!/usr/bin/env bash
# validate-sensor.sh — eBPF EDR sensor validation (runs from your Mac)
#
# All docker exec commands are tunnelled through gcloud compute ssh.
# No manual SSH required — just run this from your Mac.
#
# Usage:
#   ./validate-sensor.sh
#
# Watch alerts live while running (separate terminal):
#   make run-alert-router            # browser dashboard at http://localhost:8888
#   OR: gcloud logging read 'logName="projects/ebpfagent/logs/ebpf-edr-alerts"' \
#         --project=ebpfagent --limit=20 --freshness=5m

set -euo pipefail

VM="sensor-vm"
ZONE="us-west1-a"
PROJECT="ebpfagent"
TARGET="sensor-env-sensor-1"

# ── helpers ───────────────────────────────────────────────────────────────────

# Run a command on the sensor VM as root.
vm() {
    gcloud compute ssh "${VM}" --zone="${ZONE}" --project="${PROJECT}" \
        --command="$*" -- -o LogLevel=ERROR 2>/dev/null
}

# Run a command inside the sensor container.
container() {
    vm "sudo docker exec ${TARGET} $*"
}

header() {
    local num=$1 total=$2 name=$3 expect=$4
    echo ""
    echo "══════════════════════════════════════════════════════"
    echo "  TEST ${num}/${total} — ${name}"
    echo "  EXPECT: ${expect}"
    echo "══════════════════════════════════════════════════════"
}

pass() { echo "  [sent] waiting for alert..."; }

check_cloud_log() {
    local rule=$1
    sleep 3
    local result
    result=$(gcloud logging read \
        "logName=\"projects/${PROJECT}/logs/ebpf-edr-alerts\" AND jsonPayload.rule=\"${rule}\"" \
        --project="${PROJECT}" --limit=3 --freshness=2m \
        --format="value(jsonPayload.level, jsonPayload.rule, jsonPayload.service, jsonPayload.comm, jsonPayload.filename)" \
        2>/dev/null || echo "")
    if [[ -n "${result}" ]]; then
        echo "  [PASS] Cloud Logging:"
        echo "${result}" | sed 's/^/         /'
    else
        echo "  [MISS] not yet in Cloud Logging — check alert.log on VM or wait a few seconds"
        echo "         vm: sudo tail -5 /alerts/alert.log"
    fi
}

# ── pre-flight ────────────────────────────────────────────────────────────────

echo ""
echo "Checking sensor-vm..."

if ! vm "sudo docker ps --format '{{.Names}}'" 2>/dev/null | grep -q "^${TARGET}$"; then
    echo "ERROR: container ${TARGET} is not running on ${VM}"
    echo "       Check: gcloud compute ssh ${VM} --zone=${ZONE} --project=${PROJECT}"
    echo "              sudo docker compose -f /opt/sensor/docker-compose.yml ps"
    exit 1
fi

if ! vm "sudo pgrep -x ebpf-edr-demo" > /dev/null 2>&1; then
    echo "WARN: ebpf-edr-demo is not running on ${VM} — start it first:"
    echo "      gcloud compute ssh ${VM} --zone=${ZONE} -- sudo systemctl restart ebpf-edr"
fi

# Snapshot Cloud Logging so check_cloud_log only sees NEW alerts
LOG_SINCE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "  [OK] container running, agent up"
echo ""
echo "Alerts will appear in Cloud Logging (project=${PROJECT}) and at http://localhost:8888"
echo "Starting in 3 seconds..."
sleep 3

# ── T1: Shell spawn ───────────────────────────────────────────────────────────

header 1 6 "Shell spawn in container" "CRITICAL shell_spawn_container service=env-sensor"
container sh -c "id" || true
pass
sleep 3

# ── T2: Network recon tool ────────────────────────────────────────────────────

header 2 6 "Network tool in container" "HIGH network_tool_container service=env-sensor"
container nc -w 2 1.1.1.1 80 || true
pass
sleep 3

# ── T3: Read device private key (main regression test) ───────────────────────

header 3 6 "Read device private key (.key)" "HIGH sensitive_file_access filename=device.key"
echo "  Tracing debug pipeline:"
echo "    gcloud compute ssh ${VM} --zone=${ZONE} -- 'sudo journalctl -u ebpf-edr --since=\"10 seconds ago\" | grep \"DBG file\"'"
echo ""
container cat /etc/sensor/tls/device.key || true
pass
sleep 4

# Show debug pipeline output from the VM
echo "  DBG pipeline (last 10s on VM):"
vm "sudo journalctl -u ebpf-edr --since='15 seconds ago' --no-pager 2>/dev/null | grep 'DBG file' | grep -i 'device' || echo '  (no DBG lines matched)'"

sleep 2

# ── T4: Read CA cert (.crt — not a monitored suffix) ─────────────────────────

header 4 6 "Read CA cert (.crt)" "NO ALERT — .crt is not in highFileSuffixes"
container cat /etc/sensor/tls/ca.crt || true
echo "  Expected: no alert. To add .crt detection, add \".crt\" to highFileSuffixes in policy.go."
sleep 3

# ── T5: Read /etc/passwd ──────────────────────────────────────────────────────

header 5 6 "Read /etc/passwd (system recon)" "MEDIUM sensitive_file_access"
container cat /etc/passwd || true
pass
sleep 4

echo "  DBG pipeline (last 10s on VM):"
vm "sudo journalctl -u ebpf-edr --since='15 seconds ago' --no-pager 2>/dev/null | grep 'DBG file' | grep -i 'passwd' || echo '  (no DBG lines matched)'"

sleep 2

# ── T6: Unauthorized external connect ────────────────────────────────────────

header 6 6 "Unauthorized external connect" "HIGH unauthorized_external_connect + network_tool_container"
container nc -w 2 8.8.8.8 80 || true
pass
sleep 4

# ── summary ───────────────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════════════"
echo "  Tests complete. Fetching new alerts from Cloud Logging..."
echo ""

gcloud logging read \
    "logName=\"projects/${PROJECT}/logs/ebpf-edr-alerts\" AND timestamp>=\"${LOG_SINCE}\"" \
    --project="${PROJECT}" --limit=30 \
    --format="table(jsonPayload.level, jsonPayload.rule, jsonPayload.service, jsonPayload.comm, jsonPayload.filename, jsonPayload.dst_ip)" \
    2>/dev/null || echo "  (could not fetch from Cloud Logging)"

echo ""
echo "  Expected:"
echo "    T1  CRITICAL shell_spawn_container        service=env-sensor  comm=sh"
echo "    T2  HIGH     network_tool_container        service=env-sensor  comm=nc"
echo "    T3  HIGH     sensitive_file_access         filename=...device.key  comm=cat"
echo "    T4  (no alert — .crt not monitored)"
echo "    T5  MEDIUM   sensitive_file_access         filename=/etc/passwd"
echo "    T6  HIGH     network_tool_container + unauthorized_external_connect  dst=8.8.8.8"
echo ""
echo "  View raw alert log on VM:"
echo "    gcloud compute ssh ${VM} --zone=${ZONE} -- 'sudo tail -20 /alerts/alert.log'"
echo ""
echo "  Full debug pipeline trace:"
echo "    gcloud compute ssh ${VM} --zone=${ZONE} -- 'sudo journalctl -u ebpf-edr --since=\"5 minutes ago\" | grep DBG'"
echo "══════════════════════════════════════════════════════"
