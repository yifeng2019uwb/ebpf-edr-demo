#!/bin/bash
# validate-gke.sh — GKE functional validation
# Tests are distributed across all 4 services to confirm eBPF monitors the full cluster.
# Usage: ./validate-gke.sh [--context <kubectl-context>]
#
# Test-to-service mapping (confirms resolver correctness for each service):
#   auth-service     — V3 (shadow), V8 (net-tool), V10 (reverse-shell)
#   provider-service — V2 (shell-spawn), V7 (ssh-key), V11 (credentials-env)
#   gateway          — V4 (ext-connect), V9 (passwd), V12 (container-mgmt)
#   ai-service       — V5 (allowlist passive check)

set -euo pipefail

# ── deployment target ─────────────────────────────────────────────────────────
NAMESPACE="health-ai"
GATEWAY_HEALTH_PATH="/actuator/health"
# Services to check for false positives in V6 (pipe-separated for grep -E)
APP_SERVICES="gateway|auth-service|provider-service|ai-service"
# Service expected to make external connects without firing HIGH (V5)
ALLOWED_EXT_SERVICE="ai-service"

# ── Cloud Logging project (where ebpf-edr-alerts are published) ──────────────
GCLOUD_PROJECT="ebpfagent"

# ── MITRE rule names (update if rules are renamed) ────────────────────────────
RULE_SHELL="T1059_unix_shell_execution"
RULE_SHADOW="T1003_008_os_credential_dumping"
RULE_EXT_CONNECT="T1041_exfiltration_over_c2"
RULE_PRIV_KEY="T1552_004_private_keys"
RULE_NET_TOOL="T1105_ingress_tool_transfer"
RULE_SYSINFO="T1082_system_info_discovery"
RULE_CREDS_ENV="T1552_001_credentials_in_files"
RULE_CONTAINER_DISC="T1613_container_resource_discovery"

# ─────────────────────────────────────────────────────────────────────────────
PASS=0
FAIL=0
SKIP=0

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; ((PASS++)) || true; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; ((FAIL++)) || true; }
skip() { echo -e "${YELLOW}[SKIP]${NC} $*"; ((SKIP++)) || true; }
info() { echo -e "      $*"; }

# ── parse args ────────────────────────────────────────────────────────────────
CONTEXT_FLAG=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --context) CONTEXT_FLAG="--context $2"; shift 2 ;;
        *) echo "Usage: $0 [--context <kubectl-context>]"; exit 1 ;;
    esac
done

KUBECTL="kubectl $CONTEXT_FLAG"

# ── discover resources ────────────────────────────────────────────────────────
echo "Discovering resources..."

EDR_POD=$($KUBECTL get pod -n kube-system -l app=ebpf-edr \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
AUTH_POD=$($KUBECTL get pod -n "$NAMESPACE" -l component=auth-service \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
PROVIDER_POD=$($KUBECTL get pod -n "$NAMESPACE" -l component=provider-service \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
GW_POD=$($KUBECTL get pod -n "$NAMESPACE" -l component=gateway \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
GATEWAY_IP=$($KUBECTL get svc gateway -n "$NAMESPACE" \
    -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)

[[ -z "$EDR_POD" ]]      && { echo "ERROR: ebpf-edr pod not found in kube-system"; exit 1; }
[[ -z "$AUTH_POD" ]]     && { echo "ERROR: auth-service pod not found in $NAMESPACE"; exit 1; }
[[ -z "$PROVIDER_POD" ]] && { echo "ERROR: provider-service pod not found in $NAMESPACE"; exit 1; }
[[ -z "$GW_POD" ]]       && { echo "ERROR: gateway pod not found in $NAMESPACE"; exit 1; }

echo "  EDR pod:          $EDR_POD"
echo "  auth-service:     $AUTH_POD"
echo "  provider-service: $PROVIDER_POD"
echo "  gateway:          $GW_POD"
echo "  Gateway IP:       ${GATEWAY_IP:-<not available>}"
echo ""

# ── helpers ───────────────────────────────────────────────────────────────────

# Fetch alerts from Cloud Logging after $1 (RFC3339 timestamp) and format each
# entry as a single grep-able line: "level=X rule=Y service=Z namespace=W filename=F dst_ip=I"
_fetch_alerts() {
    local since=$1
    gcloud logging read \
        "logName=\"projects/${GCLOUD_PROJECT}/logs/ebpf-edr-alerts\" AND timestamp>=\"${since}\"" \
        --project="$GCLOUD_PROJECT" --limit=100 --format=json 2>/dev/null \
    | python3 -c "
import json, sys
for e in json.load(sys.stdin):
    p = e.get('jsonPayload', {})
    print('level={} rule={} service={} namespace={} filename={} dst_ip={}'.format(
        p.get('level',''), p.get('rule',''), p.get('service',''),
        p.get('namespace',''), p.get('filename',''), p.get('dst_ip','')))
"
}

# Poll Cloud Logging for a pattern anchored to $3 (RFC3339 timestamp), return 0 if found within timeout.
expect_alert() {
    local pattern=$1
    local timeout=${2:-60}
    local since=${3:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}
    for ((elapsed=0; elapsed<timeout; elapsed+=5)); do
        if _fetch_alerts "$since" | grep -qE "$pattern"; then
            return 0
        fi
        sleep 5
    done
    return 1
}

# Check that a pattern does NOT appear in Cloud Logging over a wait window.
no_alert() {
    local pattern=$1
    local window=${2:-20}
    local since
    since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    sleep "$window"
    if _fetch_alerts "$since" | grep -qE "$pattern"; then
        return 1
    fi
    return 0
}

# ── V2: Shell spawn — provider-service ───────────────────────────────────────
echo "=== V2: Shell spawn detection (provider-service) ==="
V2_SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
$KUBECTL exec "$PROVIDER_POD" -n "$NAMESPACE" -- sh -c "exit 0" >/dev/null 2>&1 || true
if expect_alert "CRITICAL.*${RULE_SHELL}.*service=provider-service.*namespace=${NAMESPACE}" 60 "$V2_SINCE"; then
    pass "V2: CRITICAL ${RULE_SHELL} — service=provider-service namespace=${NAMESPACE}"
else
    fail "V2: no CRITICAL ${RULE_SHELL} within timeout"
fi

# ── V3: Sensitive file access (/etc/shadow) — auth-service ───────────────────
echo "=== V3: Sensitive file access (auth-service) ==="
V3_SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# Alpine JRE image may not have /etc/shadow — create it first so lsm/file_open sees a real read (not ENOENT)
$KUBECTL exec "$AUTH_POD" -n "$NAMESPACE" -- sh -c \
    "echo 'root:!:19000:0:99999:7:::' > /etc/shadow && cat /etc/shadow" >/dev/null 2>&1 || true
if expect_alert "HIGH.*${RULE_SHADOW}.*service=auth-service.*shadow" 60 "$V3_SINCE"; then
    pass "V3: HIGH ${RULE_SHADOW} — /etc/shadow detected"
else
    fail "V3: no HIGH ${RULE_SHADOW} alert within timeout"
fi

# ── V4: Unauthorized external connect — gateway ───────────────────────────────
echo "=== V4: Unauthorized external connect (gateway) ==="
V4_SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
$KUBECTL exec "$GW_POD" -n "$NAMESPACE" -- \
    wget --timeout=3 -q http://8.8.8.8/ -O /dev/null >/dev/null 2>&1 || true
if expect_alert "HIGH.*${RULE_EXT_CONNECT}.*service=gateway.*8\.8\.8\.8" 60 "$V4_SINCE"; then
    pass "V4: HIGH ${RULE_EXT_CONNECT} — 8.8.8.8 detected"
else
    fail "V4: no HIGH ${RULE_EXT_CONNECT} alert within timeout"
fi

# ── V5: Allowlisted service external connect — no HIGH expected ───────────────
echo "=== V5: ${ALLOWED_EXT_SERVICE} external connect allowlist ==="
info "Observing for 20s — ${ALLOWED_EXT_SERVICE} must not fire HIGH..."
if no_alert "HIGH.*${RULE_EXT_CONNECT}.*service=${ALLOWED_EXT_SERVICE}" 20; then
    pass "V5: no unauthorized HIGH for ${ALLOWED_EXT_SERVICE} external connects"
else
    fail "V5: ${ALLOWED_EXT_SERVICE} fired ${RULE_EXT_CONNECT} HIGH — add to externalAllowedServices in policy.go"
fi

# ── V6: No CRITICAL false positives from normal gateway traffic ───────────────
echo "=== V6: No CRITICAL false positives from gateway traffic ==="
if [[ -n "$GATEWAY_IP" ]]; then
    curl -sf "http://$GATEWAY_IP:8080${GATEWAY_HEALTH_PATH}" >/dev/null 2>&1 || true
    info "Observing for 10s after health check..."
    if no_alert "CRITICAL.*(service=${APP_SERVICES}).*namespace=${NAMESPACE}" 10; then
        pass "V6: no CRITICAL false positives from normal gateway traffic"
    else
        fail "V6: CRITICAL alert fired from normal gateway traffic"
    fi
else
    skip "V6: gateway IP not available — skipping"
fi

# ── V7: SSH private key read — provider-service ───────────────────────────────
echo "=== V7: SSH private key read (provider-service) ==="
V7_SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
$KUBECTL exec "$PROVIDER_POD" -n "$NAMESPACE" -- sh -c \
    "mkdir -p /root/.ssh && echo 'test-key' > /root/.ssh/id_rsa && cat /root/.ssh/id_rsa" \
    >/dev/null 2>&1 || true
if expect_alert "CRITICAL.*${RULE_PRIV_KEY}.*service=provider-service.*id_rsa" 60 "$V7_SINCE"; then
    pass "V7: CRITICAL ${RULE_PRIV_KEY} — /root/.ssh/id_rsa detected"
else
    fail "V7: no CRITICAL ${RULE_PRIV_KEY} alert within timeout"
fi

# ── V8: Network recon tool — auth-service ─────────────────────────────────────
echo "=== V8: Network recon tool (auth-service) ==="
V8_SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
V8_TRIGGERED=false
if $KUBECTL exec "$AUTH_POD" -n "$NAMESPACE" -- which wget >/dev/null 2>&1; then
    $KUBECTL exec "$AUTH_POD" -n "$NAMESPACE" -- wget --timeout=2 -q http://1.1.1.1 -O /dev/null >/dev/null 2>&1 || true
    V8_TRIGGERED=true
elif $KUBECTL exec "$AUTH_POD" -n "$NAMESPACE" -- which nc >/dev/null 2>&1; then
    $KUBECTL exec "$AUTH_POD" -n "$NAMESPACE" -- nc -w 2 1.1.1.1 80 >/dev/null 2>&1 || true
    V8_TRIGGERED=true
fi
if [[ "$V8_TRIGGERED" == true ]]; then
    if expect_alert "HIGH.*${RULE_NET_TOOL}.*service=auth-service" 60 "$V8_SINCE"; then
        pass "V8: HIGH ${RULE_NET_TOOL} detected"
    else
        fail "V8: no HIGH ${RULE_NET_TOOL} alert within timeout"
    fi
else
    skip "V8: wget/nc not available in container image"
fi

# ── V9: /etc/passwd recon — gateway ───────────────────────────────────────────
echo "=== V9: /etc/passwd recon (gateway) ==="
V9_SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
$KUBECTL exec "$GW_POD" -n "$NAMESPACE" -- cat /etc/passwd >/dev/null 2>&1 || true
if expect_alert "MEDIUM.*${RULE_SYSINFO}.*service=gateway.*passwd" 60 "$V9_SINCE"; then
    pass "V9: MEDIUM ${RULE_SYSINFO} — /etc/passwd detected"
else
    fail "V9: no MEDIUM ${RULE_SYSINFO} alert within timeout"
fi

# ── V10: Reverse shell simulation — auth-service ──────────────────────────────
echo "=== V10: Reverse shell simulation (auth-service) ==="
V10_SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
$KUBECTL exec "$AUTH_POD" -n "$NAMESPACE" -- sh -c \
    "wget --timeout=2 -q http://8.8.8.8:4444 -O /dev/null || true; sh -c 'exit 0'" \
    >/dev/null 2>&1 || true
if expect_alert "CRITICAL.*${RULE_SHELL}.*service=auth-service" 60 "$V10_SINCE" && \
   expect_alert "HIGH.*${RULE_EXT_CONNECT}.*service=auth-service.*8\.8\.8\.8" 60 "$V10_SINCE"; then
    pass "V10: reverse shell — CRITICAL ${RULE_SHELL} + HIGH ${RULE_EXT_CONNECT} both detected"
else
    fail "V10: reverse shell — one or both alerts missing within timeout"
fi

# ── V11: Credentials in .env file — provider-service ─────────────────────────
echo "=== V11: Credentials in .env file (provider-service) ==="
V11_ENV=$(mktemp /tmp/edr_v11.XXXXXX)
echo "DB_PASSWORD=super_secret_password" > "$V11_ENV"
# Copy file into container first (tar open fires before V11_SINCE — we don't count it)
$KUBECTL cp "$V11_ENV" "$PROVIDER_POD":/tmp/app.env -n "$NAMESPACE" 2>/dev/null || true
rm -f "$V11_ENV"
# Set timestamp AFTER copy so the check captures the cat-triggered alert only
V11_SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
$KUBECTL exec "$PROVIDER_POD" -n "$NAMESPACE" -- cat /tmp/app.env >/dev/null 2>&1 || true
if expect_alert "HIGH.*${RULE_CREDS_ENV}.*service=provider-service.*namespace=${NAMESPACE}" 60 "$V11_SINCE"; then
    pass "V11: HIGH ${RULE_CREDS_ENV} — /tmp/app.env detected"
else
    fail "V11: no HIGH ${RULE_CREDS_ENV} alert within timeout"
fi

# ── V12: Container management tool execution — gateway ────────────────────────
echo "=== V12: Container management tool execution (gateway) ==="
V12_SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# Step 1: copy a binary into the container under the name 'kubectl'.
# sh -c fires T1059 but cp (fork-child) completes before SIGKILL arrives.
$KUBECTL exec "$GW_POD" -n "$NAMESPACE" -- sh -c \
    "cp /bin/cat /usr/local/bin/kubectl 2>/dev/null || cp /usr/bin/cat /usr/local/bin/kubectl 2>/dev/null || true" \
    >/dev/null 2>&1 || true
sleep 3
# Step 2: execute the binary — /usr/local/bin/kubectl matches /kubectl suffix → T1613.
$KUBECTL exec "$GW_POD" -n "$NAMESPACE" -- /usr/local/bin/kubectl /etc/hostname \
    >/dev/null 2>&1 || true
if expect_alert "HIGH.*${RULE_CONTAINER_DISC}.*service=gateway.*namespace=${NAMESPACE}" 60 "$V12_SINCE"; then
    pass "V12: HIGH ${RULE_CONTAINER_DISC} — /usr/local/bin/kubectl detected"
else
    fail "V12: no HIGH ${RULE_CONTAINER_DISC} alert within timeout"
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════"
echo -e "  ${GREEN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}  ${YELLOW}${SKIP} skipped${NC}"
echo "══════════════════════════════════"
[[ $FAIL -eq 0 ]]
