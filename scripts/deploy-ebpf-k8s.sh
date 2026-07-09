#!/bin/bash
# k8s/deploy-template.sh — Generic eBPF agent deployment for any K8s cluster
# Copy this to your service's k8s/ directory and customize for your environment
# Usage: ./deploy-template.sh

set -e

# ── CONFIGURATION (customize for your environment) ────────────────────────────
# GitHub repo where eBPF DaemonSet is published
GITHUB_REPO="${GITHUB_REPO:-https://github.com/yifeng2019uwb/ebpf-edr-demo}"
GITHUB_BRANCH="${GITHUB_BRANCH:-main}"
EBPF_DS_URL="${EBPF_DS_URL:-https://raw.githubusercontent.com/yifeng2019uwb/ebpf-edr-demo/main/k8s/ebpf-edr-ds.yaml}"

# Container registry where eBPF image is pushed
EBPF_REGISTRY="${EBPF_REGISTRY:-ghcr.io/yifeng2019uwb}"
EBPF_IMAGE="${EBPF_REGISTRY}/ebpf-edr:latest"

# K8s cluster info (set these for your environment)
CLUSTER_NAME="${CLUSTER_NAME:-my-cluster}"
REGION="${REGION:-us-east-1}"

# ── LOGGING ───────────────────────────────────────────────────────────────────
info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
error()   { echo "[ERROR] $*"; exit 1; }

# ── MAIN ──────────────────────────────────────────────────────────────────────
main() {
    # Load credentials from .env if it exists
    if [[ -f "infra/.env" ]]; then
        info "Loading credentials from infra/.env..."
        set -a; source infra/.env; set +a
        info "✓ Loaded DATABASE_URL, PUBSUB_ADDR"
        echo ""
    fi

    info "Deploying eBPF agent to K8s cluster: $CLUSTER_NAME ($REGION)"
    echo ""

    # Check kubectl is available
    command -v kubectl >/dev/null 2>&1 || error "kubectl not found"
    info "kubectl: $(kubectl version --client --short)"

    # Verify cluster connection
    info "Verifying K8s connection..."
    kubectl cluster-info >/dev/null 2>&1 || error "Cannot connect to K8s cluster — check kubeconfig"
    success "Connected to cluster: $(kubectl config current-context)"
    echo ""

    # Create kube-system namespace (should exist, but ensure)
    info "Ensuring kube-system namespace exists..."
    kubectl create namespace kube-system --dry-run=client -o yaml | kubectl apply -f -
    success "kube-system namespace ready"
    echo ""

    # Create Secret for eBPF configuration (if DATABASE_URL is set)
    if [[ -n "${DATABASE_URL}" ]] && [[ -n "${DATABASE_KEY}" ]]; then
        info "Creating eBPF configuration Secret..."
        kubectl create secret generic ebpf-alerts \
            --from-literal=database-key="${DATABASE_KEY}" \
            --from-literal=pubsub-key="${PUBSUB_KEY:-}" \
            -n kube-system \
            --dry-run=client -o yaml | kubectl apply -f -
        success "Secret created"
    else
        warn "DATABASE_URL not set — skipping Secret creation (configure via kubectl later if needed)"
    fi

    # Create ConfigMap for eBPF configuration (if DATABASE_URL is set)
    if [[ -n "${DATABASE_URL}" ]]; then
        info "Creating eBPF configuration ConfigMap..."
        kubectl create configmap ebpf-alerts \
            --from-literal=database-url="${DATABASE_URL}" \
            --from-literal=database-region="${DATABASE_REGION:-}" \
            --from-literal=pubsub-addr="${PUBSUB_ADDR:-}" \
            --from-literal=alert-log-path="${ALERT_LOG_PATH:-/alerts/alert.log}" \
            -n kube-system \
            --dry-run=client -o yaml | kubectl apply -f -
        success "ConfigMap created"
    fi
    echo ""

    # Download and apply eBPF DaemonSet
    info "Downloading eBPF DaemonSet from GitHub..."
    local ds_yaml
    ds_yaml=$(curl -fsSL "$EBPF_DS_URL" 2>/dev/null) || {
        error "Failed to download eBPF DaemonSet from $EBPF_DS_URL"
    }
    success "Downloaded"
    echo ""

    info "Applying eBPF DaemonSet (image: $EBPF_IMAGE)..."
    echo "$ds_yaml" | \
        REGION="$REGION" \
        CLUSTER_NAME="$CLUSTER_NAME" \
        envsubst '${REGION} ${CLUSTER_NAME}' | \
        kubectl apply -f -
    success "DaemonSet applied"
    echo ""

    info "Waiting for eBPF agent to be ready..."
    kubectl rollout status daemonset/ebpf-edr -n kube-system --timeout=120s || {
        warn "DaemonSet rollout timeout — check logs: kubectl logs -n kube-system -l app=ebpf-edr"
    }
    success "eBPF agent deployed"
    echo ""

    # Status
    info "=== eBPF Agent Status ==="
    kubectl get daemonset -n kube-system -l app=ebpf-edr
    echo ""
    kubectl get pods -n kube-system -l app=ebpf-edr
    echo ""

    success "eBPF agent deployment complete!"
    echo ""
    echo "Verify logs:"
    echo "  kubectl logs -n kube-system -l app=ebpf-edr -f"
    echo ""
}

main "$@"
