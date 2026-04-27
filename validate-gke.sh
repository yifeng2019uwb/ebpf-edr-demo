#!/bin/bash
# validate-gke.sh — Phase 5 GKE functional validation
# Usage: ./validate-gke.sh [--context <kubectl-context>]
# Runs against the current kubectl context unless --context is specified.

set -euo pipefail

NAMESPACE="order-processor"
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
TARGET_POD=$($KUBECTL get pod -n "$NAMESPACE" -l component=user-service \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
GATEWAY_IP=$($KUBECTL get svc gateway -n "$NAMESPACE" \
    -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)

[[ -z "$EDR_POD" ]]     && { echo "ERROR: ebpf-edr pod not found in kube-system"; exit 1; }
[[ -z "$TARGET_POD" ]]  && { echo "ERROR: user-service pod not found in $NAMESPACE"; exit 1; }

echo "  EDR pod:    $EDR_POD"
echo "  Target pod: $TARGET_POD"
echo "  Gateway IP: ${GATEWAY_IP:-<not available>}"
echo ""

# ── helpers ───────────────────────────────────────────────────────────────────

# Poll EDR logs for a pattern anchored to $3 (RFC3339 timestamp), return 0 if found within timeout.
# Pass the timestamp captured BEFORE the trigger so slow-firing alerts are never missed.
expect_alert() {
    local pattern=$1
    local timeout=${2:-60}
    local since=${3:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}
    for ((elapsed=0; elapsed<timeout; elapsed+=2)); do
        if $KUBECTL logs "$EDR_POD" -n kube-system --since-time="$since" 2>/dev/null \
                | grep -qE "$pattern"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# Check that a pattern does NOT appear in EDR logs over a wait window.
no_alert() {
    local pattern=$1
    local window=${2:-20}
    sleep "$window"
    if $KUBECTL logs "$EDR_POD" -n kube-system --since="${window}s" 2>/dev/null \
            | grep -qE "$pattern"; then
        return 1
    fi
    return 0
}

# ── V2: Shell spawn ───────────────────────────────────────────────────────────
echo "=== V2: Shell spawn detection ==="
V2_SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
$KUBECTL exec "$TARGET_POD" -n "$NAMESPACE" -- bash -c "exit 0" >/dev/null 2>&1 || true
if expect_alert "CRITICAL.*shell_spawn_container.*service=user-service.*namespace=order-processor" 60 "$V2_SINCE"; then
    pass "V2: CRITICAL shell_spawn_container — service=user-service namespace=order-processor"
else
    fail "V2: no CRITICAL shell_spawn_container within timeout"
fi

# ── V3: Sensitive file access ─────────────────────────────────────────────────
echo "=== V3: Sensitive file access ==="
V3_SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
$KUBECTL exec "$TARGET_POD" -n "$NAMESPACE" -- cat /etc/shadow >/dev/null 2>&1 || true
if expect_alert "HIGH.*sensitive_file_access.*service=user-service.*shadow" 60 "$V3_SINCE"; then
    pass "V3: HIGH sensitive_file_access — /etc/shadow detected"
else
    fail "V3: no HIGH sensitive_file_access alert within timeout"
fi

# ── V4: Unauthorized external connect ────────────────────────────────────────
echo "=== V4: Unauthorized external connect ==="
V4_SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
$KUBECTL exec "$TARGET_POD" -n "$NAMESPACE" -- \
    python3 -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('8.8.8.8',80)); s.close()" \
    >/dev/null 2>&1 || true
if expect_alert "HIGH.*unauthorized_external_connect.*service=user-service.*8\.8\.8\.8" 60 "$V4_SINCE"; then
    pass "V4: HIGH unauthorized_external_connect — 8.8.8.8 detected"
else
    fail "V4: no HIGH unauthorized_external_connect alert within timeout"
fi

# ── V5: Inventory allowlist — no HIGH ────────────────────────────────────────
echo "=== V5: Inventory external connect allowlist ==="
info "Observing for 20s — inventory-service must not fire HIGH..."
if no_alert "HIGH.*unauthorized_external_connect.*service=inventory-service" 20; then
    pass "V5: no unauthorized HIGH for inventory-service external connects"
else
    fail "V5: inventory-service fired unauthorized_external_connect HIGH"
fi

# ── V6: No CRITICAL false positives from normal gateway traffic ───────────────
echo "=== V6: No CRITICAL false positives from gateway traffic ==="
if [[ -n "$GATEWAY_IP" ]]; then
    curl -sf "http://$GATEWAY_IP:8080/health" >/dev/null 2>&1 || true
    info "Observing for 10s after health check..."
    if no_alert "CRITICAL.*(service=gateway|service=user-service|service=auth-service|service=order-service).*namespace=order-processor" 10; then
        pass "V6: no CRITICAL false positives from normal gateway traffic"
    else
        fail "V6: CRITICAL alert fired from normal gateway traffic"
    fi
else
    skip "V6: gateway IP not available — skipping"
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════"
echo -e "  ${GREEN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}  ${YELLOW}${SKIP} skipped${NC}"
echo "══════════════════════════════════"
[[ $FAIL -eq 0 ]]
