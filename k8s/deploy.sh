#!/bin/bash
# k8s/deploy.sh — deploy the eBPF DaemonSet to whichever K8s cluster the
# current kubectl context points at. Auto-derives CLUSTER_NAME/REGION from
# the context (DigitalOcean context format: do-<region>-<cluster-name>)
# instead of hardcoding a specific cluster, since this project has moved
# between several DO clusters this session.
#
# Usage: ./k8s/deploy.sh
#   Override auto-detection: CLUSTER_NAME=foo REGION=bar ./k8s/deploy.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

info()  { echo "[INFO]  $*"; }
error() { echo "[ERROR] $*"; exit 1; }

command -v kubectl >/dev/null 2>&1 || error "kubectl not found"

ctx="$(kubectl config current-context 2>/dev/null)" || error "no kubectl context set"

if [[ -z "${CLUSTER_NAME:-}" || -z "${REGION:-}" ]]; then
    if [[ "$ctx" == do-* ]]; then
        # do-sfo3-k8s-1-36-0-do-2-sfo3-xxxx -> region=sfo3, name=rest
        REGION="${REGION:-$(echo "$ctx" | cut -d- -f2)}"
        CLUSTER_NAME="${CLUSTER_NAME:-${ctx#do-*-}}"
    else
        error "context '$ctx' isn't a DigitalOcean context (do-<region>-<name>) — set CLUSTER_NAME and REGION explicitly"
    fi
fi

info "Context: $ctx"
info "Deploying to cluster: $CLUSTER_NAME (region: $REGION)"

cd "$REPO_ROOT"
CLUSTER_NAME="$CLUSTER_NAME" REGION="$REGION" bash scripts/deploy-ebpf-k8s.sh
