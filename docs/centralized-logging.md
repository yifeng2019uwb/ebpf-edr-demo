# Centralized Cloud Logging Design

## Goal

All eBPF EDR alerts — from GKE DaemonSets and Docker VM agents — write directly to
Google Cloud Logging as structured JSON. This provides a single queryable pane across
all environments, supports forensic investigation after incidents, and meets security
log retention regulations.

File + stdout output is always-on local (ops debug, node-level audit); Cloud Logging is
the primary long-term store. A third path — Pub/Sub — feeds real-time monitoring.
See [alert-router-design.md](alert-router-design.md) for the real-time path.

---

## Architecture

```
GKE Node (DaemonSet)          Docker VM
  ebpf-edr agent                ebpf-edr agent
       │                              │
       ├── /alerts/alert.log          ├── /alerts/alert.log   (always-on local)
       │                              │
       └── Cloud Logging SDK ─────────┘
                   │
        log name: ebpf-edr-alerts
        project:  ebpfagent
```

Each agent writes directly via the `cloud.google.com/go/logging` SDK.
GKE stdout forwarding is NOT relied on — direct write ensures structured payload
and works identically on GKE and Docker VM.

### Tradeoff: SDK write vs GKE stdout forwarding

| | GKE stdout (Logging Agent) | Direct SDK write (chosen) |
|---|---|---|
| Buffering & retry | Automatic, node-level durability | Must implement in agent |
| Schema control | Raw text, parsed by log agent | Structured JSON, exact schema |
| Cross-env consistency | GKE only | Works on GKE and Docker VM |
| Failure ownership | Google-managed | Agent-owned |

Decision: direct SDK write chosen for schema control and cross-environment consistency.
The agent must own reliability (see Reliability section below).

---

## Structured Log Payload

Each alert is written as a JSON object. `schema_version` enables forward-compatible
evolution — consumers must ignore unknown fields; breaking changes require a version bump.

```json
{
  "schema_version": 1,
  "ts":              "2026-05-02T21:00:00Z",
  "level":           "CRITICAL",
  "rule":            "T1059_unix_shell_execution",
  "message":         "Shell spawned from container — possible RCE",
  "pid":             1234,
  "ppid":            1,
  "uid":             0,
  "comm":            "bash",
  "runtime":         "k8s",
  "service":         "order-processor",
  "state":           "resolved",
  "cluster":         "gke-prod-cluster-1",
  "pod":             "order-processor-abc123",
  "namespace":       "default",
  "node":            "gke-node-1",
  "region":          "us-west1",
  "filename":        "",
  "dst_ip":          "",
  "dst_port":        0,
  "response_action": "kill_process"
}
```

### Schema Evolution Strategy

- `ts`: event time set by the agent at detection — preserves forensic ordering even if Cloud Logging ingestion is delayed by buffering.
- Add new optional fields freely — consumers ignore unknown fields.
- Never rename or remove existing fields without bumping `schema_version`.
- On version bump: update consumers before deploying new agents (read old + new schema).
- Current version: `1`.

Cloud Logging severity maps from alert level:

| Alert Level | Cloud Logging Severity |
|-------------|----------------------|
| CRITICAL    | Critical (600)       |
| HIGH        | Error (500)          |
| MEDIUM      | Warning (400)        |

---

## Reliability

Choosing direct SDK write means the agent owns reliability. Required design:

### Async buffer
The existing `alertCh` channel in `main.go` already decouples detection from write.
The Cloud Logging SDK client also maintains an internal async buffer — `Flush()` must
be called on shutdown to drain it.

### Retry with backoff
Cloud Logging write failures (network, quota, IAM) must retry with exponential backoff.
The SDK handles transient retries internally for short-lived errors. However, sustained
quota exhaustion or client buffer overflow are not resolved by the SDK alone —
application-level drop policy (see below) handles sustained failures to prevent the
agent from blocking or losing CRITICAL alerts silently.

### Drop policy
| Level    | Policy on persistent failure |
|----------|------------------------------|
| CRITICAL | Retry up to 3× with backoff; if all fail, write to local file and increment `alertDropped` counter; never silently drop |
| HIGH     | Retry once; drop and increment counter on second failure |
| MEDIUM   | Drop immediately on first failure; increment counter |

Rationale: CRITICAL alerts are forensic evidence — loss is unacceptable.
HIGH/MEDIUM are actionable signals but tolerable to lose under sustained API failure.

### Fallback trigger
Cloud Logging is disabled (file+stdout only) when:
- `GOOGLE_CLOUD_PROJECT` env var is unset
- SDK client init fails (logged at startup)
- Sustained write failure after retry exhaustion (per drop policy above)

---

## Throughput and Cost Control

eBPF monitors generate high-frequency kernel events. Without control, Cloud Logging
costs and API quota limits become problems.

Cloud Logging free tier: **50 GiB/project/month**. File events alone can exceed this
on a busy node.

### Rate limiting per rule
Each detection rule should have a per-minute cap before Cloud Logging write.
Local file always receives the full stream; Cloud Logging receives the rate-limited view.

Suggested starting caps (must be tuned using real event volume from production workloads —
these are initial defaults, not validated numbers):

| Rule category | Starting cap |
|---------------|--------------|
| CRITICAL (shell spawn, container escape) | No cap — always write |
| HIGH (network tool, sensitive file) | 60/minute per service |
| MEDIUM (system file access) | 10/minute per service |

### Sampling
For HIGH/MEDIUM bursts (e.g., a misconfigured app reading `/etc/passwd` in a loop),
emit one representative alert per burst window (e.g., 30s) with a `burst_count` field
indicating how many were suppressed. CRITICAL alerts are never sampled.

### Aggregation
Identical `(rule, service, comm)` tuples within a short window (e.g., 5s) can be
collapsed into a single log entry with a count field, rather than N separate entries.

The agent must also export metrics on the logging pipeline itself — write success rate,
retry count, and queue depth — so operators can detect when the pipeline is degraded
before alerts are silently lost. The existing `alertDropped` counter is a start; a
full metrics endpoint (e.g., Prometheus) is the production target.

TODO: Implement rate limiter and burst aggregation in `pkg/detector` or `internal/alert`.

---

## Retention Policy

Retention periods are backed by specific regulations, not arbitrary numbers.

| Tier | Storage | Duration | Regulation Basis |
|------|---------|----------|-----------------|
| Hot  | Cloud Logging custom bucket `ebpf-edr-security-logs-{region}` | 365 days | SOC 2 Type II (1yr minimum), PCI DSS 10.7 (1yr) |
| Cold | GCS bucket `ebpf-edr-cold-{region}` | Day 0 → 1095 days | NIST SP 800-92 §4.2.3 (3yr for security/audit logs) |
| Total | | 3 years | Security operations industry standard |

### Cold Storage Lifecycle

GCS sink runs **from day 0 in parallel** with the Cloud Logging bucket.
Lifecycle transitions are managed by GCS object lifecycle rules:

```
Day 0–365:   Cloud Logging bucket (hot, queryable)
             + GCS Standard (parallel, full copy via sink)
Day 365:     Cloud Logging auto-deletes (bucket retention limit)
             GCS lifecycle rule → transition to Coldline
Day 1095:    GCS lifecycle rule → transition to Archive
             (Archive = GCP equivalent of AWS Glacier — access < once/year)
Day 1095+:   Delete (extend if specific compliance requires longer)
```

GCS storage class costs (approximate):
- Standard:  $0.020/GB/month
- Coldline:  $0.004/GB/month
- Archive:   $0.0012/GB/month

---

## Bucket Organization

### One bucket per region per project

Each project that produces security logs owns its own Cloud Logging bucket and GCS
cold storage bucket, scoped to the region where logs are generated.
Hot and cold buckets are both regional for data residency consistency.

```
Cloud Logging:  ebpf-edr-security-logs-us-west1   (regional bucket)
                ebpf-edr-security-logs-us-east1   (regional bucket, if multi-region)
GCS cold:       gs://ebpf-edr-cold-us-west1/
                gs://ebpf-edr-cold-us-east1/       (if multi-region)
```

### M:N — multiple services × multiple regions

The structured payload already carries `service`, `namespace`, `cluster`, `region`.
Physical bucket separation is **not** needed for filtering — query by payload field.

Per-service buckets are only justified when:
- Services have different retention requirements (e.g., HIPAA workloads need 6yr)
- Services have different IAM access controls

GCS object path within a bucket follows Cloud Logging sink default format:
```
gs://ebpf-edr-cold-us-west1/ebpf-edr-alerts/YYYY/MM/DD/HH/
```

---

## Infrastructure as Code

All cloud resources are created via Pulumi — no manual gcloud commands.

Resources per region (managed by ebpf-edr Pulumi stack):
- Cloud Logging custom bucket with 365-day retention
- Cloud Logging sink routing `ebpf-edr-alerts` to GCS
- GCS bucket with lifecycle policy (Standard → Coldline at 365d → Archive at 1095d)
- IAM binding: agent service account → `roles/logging.logWriter`

TODO: Add Pulumi stack under `infra/` in this repo.

---

## Authentication

Preferred: **Workload Identity** (GKE) — binds a Kubernetes service account to a GCP
service account with only `roles/logging.logWriter`. This follows least-privilege and
works correctly in hardened clusters where node-level OAuth scopes are restricted.

Node default service account scope (`logging.write`) is a fallback only — it grants
permissions to all workloads on the node, which violates least-privilege.

| Environment | Preferred Mechanism | Fallback |
|------------|--------------------|----|
| GKE DaemonSet | Workload Identity → dedicated GCP SA with `roles/logging.logWriter` | Node SA `logging.write` scope (not recommended for production) |
| Docker VM | VM service account with `roles/logging.logWriter` | — |
| Local dev | `GOOGLE_APPLICATION_CREDENTIALS` env var → service account key | — |

The agent reads `GOOGLE_CLOUD_PROJECT` env var to determine the target project.
If unset, Cloud Logging is disabled and the agent falls back to file+stdout only.

---

## Implementation Status

- [x] `internal/alert/alert.go` — Cloud Logging dual write with alertPayload struct
- [x] `k8s/ebpf-edr-ds.yaml` — `GOOGLE_CLOUD_PROJECT`, `CLUSTER_NAME`, `REGION` env vars
- [x] `infra/` — Pulumi stack: custom bucket (365d), sink, cross-project IAM bindings
- [x] Docker VM — OpenClaw compute SA granted `logging.logWriter` on `ebpfagent` via Pulumi
- [x] GKE — `order-processor-sa` granted `logging.logWriter` via Pulumi (`pulumi_registry.go`)
- [ ] `pkg/detector` or `internal/alert` — rate limiter and burst aggregation
