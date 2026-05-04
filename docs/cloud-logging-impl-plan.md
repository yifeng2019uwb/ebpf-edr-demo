# Cloud Logging Integration — Implementation Plan

## What Changes

| # | File | Change | Reason |
|---|------|--------|--------|
| 1 | `pkg/workload/identity.go` | Add `Cluster string` to `WorkloadMeta` | payload says `cluster` but struct doesn't have it |
| 2 | `pkg/workload/resolver.go` | Read `CLUSTER_NAME` env var, pass to resolvers | same pattern as `REGION` today |
| 3 | `pkg/workload/k8s_resolver.go` | Set `Cluster` in all `ResolveResult` | propagate to alert payload |
| 4 | `pkg/workload/docker_resolver.go` | Set `Cluster` in all `ResolveResult` | propagate to alert payload |
| 5 | `go.mod` | Add `cloud.google.com/go/logging` | new dependency |
| 6 | `internal/alert/alert.go` | Dual write: file + Cloud Logging; structured payload with `ts`, `cluster`, `schema_version`; drop policy per level | core feature |
| 7 | `k8s/ebpf-edr-ds.yaml` | Add `GOOGLE_CLOUD_PROJECT` + `CLUSTER_NAME` env vars | agent needs project to init SDK; cluster name for payload |

Infra (Pulumi) is a separate step after code works end-to-end.

---

## Step-by-Step with Test Criteria

### Step 1 — Add `Cluster` to WorkloadMeta (changes 1–4)

4 small edits, no logic change.

**Test:**
```bash
# Mac — cross-compile to verify no errors
make build
go vet ./internal/... ./pkg/detector/...
```
**Success:** compiles clean, no vet errors.

---

### Step 2 — Add dependency (change 5)

Must run on GCP VM (requires Linux Go toolchain):
```bash
go get cloud.google.com/go/logging
go mod tidy
make build
```
**Success:** `go.mod` + `go.sum` updated, binary builds.

---

### Step 3 — Cloud Logging dual write in `alert.go` (change 6)

Test in 3 layers:

**Layer A — unit test (Mac, no GCP needed):**
```bash
make test
```
Tests to cover:
- `GOOGLE_CLOUD_PROJECT` unset → Handler initializes file-only, no panic
- `alertPayload` struct serializes to expected JSON fields

**Layer B — Docker VM smoke test:**
```bash
export GOOGLE_CLOUD_PROJECT=ebpfagent
sudo ./ebpf-edr-demo --runtime=docker
# separate terminal:
./validate.sh
```
Verify alerts in Cloud Logging:
```bash
gcloud logging read 'logName="projects/ebpfagent/logs/ebpf-edr-alerts"' \
  --limit=10 --format=json
```
**Success:** alerts appear with all fields (`ts`, `cluster`, `schema_version`, `level`, `service`, etc.)

**Layer C — fallback test:**
```bash
unset GOOGLE_CLOUD_PROJECT
sudo ./ebpf-edr-demo --runtime=docker
```
**Success:** agent starts, logs "Cloud Logging disabled — GOOGLE_CLOUD_PROJECT not set", alerts still write to file.

---

### Step 4 — DaemonSet YAML + GKE deploy (change 7)

After Step 3 passes on Docker VM:
```bash
make docker-push
kubectl rollout restart daemonset/ebpf-edr -n kube-system
kubectl logs -n kube-system -l app=ebpf-edr -f
```
**Success:** logs show `Cloud Logging enabled: project=ebpfagent`.

Run GKE validation:
```bash
./validate-gke.sh
```
Verify GKE alerts in Cloud Logging:
```bash
gcloud logging read \
  'logName="projects/ebpfagent/logs/ebpf-edr-alerts" AND jsonPayload.runtime="k8s"' \
  --limit=10 --format=json
```
**Success:** GKE alerts appear with `runtime=k8s`, `cluster`, `pod`, `namespace` all populated.

---

### Step 5 — Infra: Pulumi stack (after Step 4)

Create `infra/` Pulumi stack provisioning:
- Cloud Logging regional bucket with 365-day retention
- GCS bucket with lifecycle policy (Standard → Coldline at 365d → Archive at 1095d)
- Log sink routing `ebpf-edr-alerts` to GCS
- IAM binding for Workload Identity

**Test:**
```bash
cd infra && pulumi preview   # dry run
pulumi up                    # create resources
```
Verify:
```bash
gcloud logging buckets list --location=us-west1
gsutil ls gs://ebpf-edr-cold-us-west1/
```
**Success:** bucket and sink exist; a test alert written by the agent appears under the GCS path within a few minutes.

---

## Dependency Order

```
Step 1 (Cluster field)  ──┐
                           ├──► Step 3 (alert.go) ──► Step 4 (GKE deploy) ──► Step 5 (Infra)
Step 2 (go.mod dep)    ──┘
```

Steps 1 and 2 can be done in parallel on different machines.
Steps 3, 4, 5 must be sequential.

---

## Status

- [x] Step 1 — Add `Cluster` to WorkloadMeta
- [x] Step 2 — Add `cloud.google.com/go/logging` dependency
- [x] Step 3 — Cloud Logging dual write in `alert.go`
- [ ] Step 4 — DaemonSet YAML + GKE deploy
- [ ] Step 5 — Pulumi infra stack
