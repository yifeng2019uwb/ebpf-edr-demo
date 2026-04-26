# eBPF EDR — GKE Validation Plan

> Reference: based on validation structure from design review (2026-04-25)
> Environments: VM1 (Docker host agent) + VM2 (GKE DaemonSet)
> Probes: exec (process), open (file), connect (network)

---

## 0. Scope & Goals

Validate that the system is:

- **Correct** — alerts fire when they should, with right severity and identity
- **Quiet** — no high-severity noise on normal traffic
- **Stable** — no drops or stalls under load
- **Accurate** — identity mapping is correct under pod churn and scaling

---

## 1. Metrics (add before running any tests)

Add lightweight in-memory counters, logged every 10s:

```
[METRICS] recv=... enr=... drop=... alerts=... cache_hits=... cache_miss=... unknown=... pending=...
```

| Counter                   | Description                                                   |
|---------------------------|---------------------------------------------------------------|
| `events_received_total`   | raw events read from BPF ring buffer                          |
| `events_enriched_total`   | events that completed enrichment                              |
| `events_dropped_total`    | events dropped (backpressure at any stage)                    |
| `alerts_total{level,rule}`| alerts emitted, by level and rule                             |
| `resolver_cache_hits`     | Resolve() returned from cache                                 |
| `resolver_cache_misses`   | Resolve() triggered async refresh                             |
| `resolver_resolution_latency_ms` | time from first-seen → resolved (for pending-ns events) |
| `unknown_ns_total`        | events that reached CRITICAL after grace period               |
| `pending_ns_total`        | events currently in pending buffer                            |

These make every test measurable. Do not run tests without them.

---

## 2. Functional Detection Tests

### 2.1 Shell spawn in container (CRITICAL)

```bash
# Docker
docker exec -it <container> bash
# GKE
kubectl exec -it <pod> -n order-processor -- bash
```

**Expect:** `LEVEL=CRITICAL RULE=shell_spawn_container`

**Validate:**
- `alerts_total{level=CRITICAL,rule=shell_spawn_container}` >= 1
- `WorkloadIdentity.Service` correct (e.g. `user-service`)
- `WorkloadIdentity.Pod` matches the pod you exec'd into (GKE)
- `WorkloadIdentity.Namespace = "order-processor"` (GKE) or `""` (Docker)

---

### 2.2 Sensitive file access (HIGH/CRITICAL)

```bash
kubectl exec <pod> -n order-processor -- cat /etc/shadow
```

**Expect:** `LEVEL=HIGH RULE=sensitive_file_access`

**Validate:**
- `filename` field = `/etc/shadow`
- `WorkloadIdentity` fields all populated and correct

---

### 2.3 Unauthorized external connect (HIGH)

```bash
# Use a non-inventory pod — inventory is allowlisted
kubectl exec <user-service-pod> -n order-processor -- \
  python3 -c "import urllib.request; urllib.request.urlopen('http://1.1.1.1')"
```

**Expect:** `LEVEL=HIGH RULE=unauthorized_external_connect`

**Validate:**
- `dst_ip` = `1.1.1.1`
- `WorkloadIdentity.Service` = `user-service` (not `inventory-service`)

---

### 2.4 Allowed external connect (LOW)

Verify inventory-service CoinGecko calls produce LOW audit only, not HIGH.

```bash
# Observe naturally — inventory syncs every 5 min
# Or trigger manually if sync endpoint exists
kubectl logs <inventory-pod> -n order-processor | grep coingecko
```

**Expect:** `LEVEL=LOW RULE=external_connect_allowed`

**Validate:**
- `alerts_total{level=HIGH,rule=unauthorized_external_connect}` unchanged after inventory sync

---

### 2.5 Alert content completeness (all fields populated)

For each alert in 2.1–2.4, validate no empty fields:

| Field                       | Expected non-empty                          |
|-----------------------------|---------------------------------------------|
| `WorkloadIdentity.Runtime`  | `"docker"` or `"k8s"`                       |
| `WorkloadIdentity.Service`  | e.g. `"user-service"`                       |
| `WorkloadIdentity.Pod`      | pod name (GKE) or container name (Docker)   |
| `WorkloadIdentity.Namespace`| `"order-processor"` (GKE) or `""` (Docker)  |
| `Comm`                      | process name                                |
| `Filename` / `DstIP`        | file path or destination IP (probe-specific)|

---

## 3. False Positive / Noise Tests

### 3.1 Normal integration traffic

```bash
GATEWAY_HOST=136.109.215.94 python -m pytest integration_tests/ -v
```

**Expect:**
- `alerts_total{level=CRITICAL}` = 0
- `alerts_total{level=HIGH}` = 0
- LOW alerts only from inventory CoinGecko calls

---

### 3.2 High-frequency concurrent traffic

```bash
for i in {1..4}; do
  GATEWAY_HOST=136.109.215.94 python -m pytest integration_tests/ &
done
wait
```

**Expect:** same as 3.1 — no CRITICAL or HIGH from normal traffic

---

### 3.3 Agent self-filter (DaemonSet only)

Verify the agent's own `mnt_ns_id` is in the skip list — events from inside the edr-monitor pod must not fire alerts.

```bash
# exec into the agent pod itself
kubectl exec -it <edr-monitor-pod> -n order-processor -- cat /etc/shadow
```

**Expect:** zero alerts — the agent's own namespace is skipped at startup

---

### 3.4 Pause container filter (GKE only)

Verify events from the K8s pause/infra container do not appear in alerts. Observable passively during any pod restart:

```bash
kubectl rollout restart deployment/user-service -n order-processor
kubectl logs <edr-monitor-pod> -n order-processor | grep pause
```

**Expect:** no alerts attributed to `comm=pause`

---

## 4. Load / Stress Tests (kernel ↔ userspace boundary)

> Do not rely only on service traffic — circuit breakers can mask load.

### 4.1 Synthetic process flood (exec probe)

```bash
kubectl exec <pod> -n order-processor -- \
  sh -c 'while true; do /bin/echo hi >/dev/null; done' &
```

Duration: 60–120s

**Pass:**
- `events_received_total` increases steadily
- `events_dropped_total` == 0 (or < 1% of received)
- Pipeline does not stall; agent remains responsive

---

### 4.2 Synthetic file open flood (open probe)

```bash
kubectl exec <pod> -n order-processor -- \
  sh -c 'while true; do cat /etc/hosts >/dev/null; done' &
```

Same validation as 4.1.

---

### 4.3 Synthetic network flood (connect probe)

```bash
# Internal connect loop — hits lsm-connect without going external
kubectl exec <pod> -n order-processor -- \
  sh -c 'while true; do curl -s http://user-service:8000/health >/dev/null; done' &
```

**Pass:** same as 4.1 — lsm-connect is the highest-frequency probe (fires on every connect()), verify no drops.

---

### 4.4 Combined burst

Run 4.1 + 4.2 + 4.3 in parallel alongside integration tests.

**Validate:**
- No deadlock
- No unbounded queue growth
- `events_dropped_total` / `events_received_total` < 1%
- Agent recovers cleanly after flood stops

---

## 5. Resolver / Identity Validation

### 5.1 New pod resolution — latency (GKE)

```bash
# Scale up and watch agent logs
kubectl scale deployment user-service --replicas=5 -n order-processor
kubectl logs -f <edr-monitor-pod> -n order-processor | grep "pending-ns\|resolved"
```

**Pass:**
- `resolver_resolution_latency_ms` < 3000ms for new pods
- `unknown_ns_total` does NOT increment (no false CRITICAL)
- `pending_ns_total` rises then falls as pods are resolved

---

### 5.2 Rapid pod churn

```bash
for i in {1..5}; do
  kubectl rollout restart deployment/user-service -n order-processor
  sleep 10
done
```

**Validate:**
- No false `CRITICAL unknown_namespace_process`
- `pending_ns_total` stays bounded (does not grow unboundedly)
- All events correctly attributed after each restart

---

### 5.3 Short-lived processes

```bash
kubectl exec <pod> -n order-processor -- \
  sh -c 'for i in $(seq 1 100); do echo hi; done'
```

**Validate:**
- Events attributed to correct pod/service (not `"host"` mislabel)
- `unknown_ns_total` does not spike

---

### 5.4 Pending → retry → CRITICAL flow

> **Implementation note:** this test requires a debug mechanism to delay the resolver — e.g., `--resolver-delay=10s` flag or a mock resolver that refuses to resolve a specific `mnt_ns_id`. Mechanism TBD at Phase 2 implementation.

Scenario A — resolves within grace period:
```
force unknown → pending-ns → resolver refreshes → resolved → no alert
```

Scenario B — exceeds retry cap (3 retries / 10s):
```
force unknown → pending-ns → retry 1 → retry 2 → retry 3 → CRITICAL
```

**Validate both paths produce the expected outcome.**

---

## 6. Timing / Ordering Validation

> **⚠ NOT YET EXECUTABLE** — blocked on kernel timestamp implementation (Section 3 of design doc, known issue). Run as observation only; do not treat results as pass/fail until `KernelTimestamp uint64` field is added.

### 6.1 Event ordering under normal load

Generate known sequence (process → file → network) and observe ordering in agent output.

**Observation only:** note drift between event order and wall-clock timestamp. Record for future kernel timestamp work.

### 6.2 Event ordering under stress

Repeat 6.1 during load test (Section 4.4). Note maximum observed delay.

---

## 7. Pipeline Behavior Validation

### 7.1 Backpressure — slow detector

> **Implementation note:** requires test mode. Add `--slow-detector` debug flag that injects `time.Sleep(50ms)` per event in the detector goroutine.

```bash
./edr-monitor --runtime=k8s --slow-detector &
# Then run synthetic load (Section 4.1)
```

**Validate:**
- `rawCh` fills (expected under slow detector)
- `events_dropped_total` increments (expected — drop strategy fires)
- System does NOT deadlock
- Agent recovers when load stops

---

### 7.2 Alert channel saturation

> **Implementation note:** requires test mode. Add `--alertch-size=1` flag to artificially limit `alertCh` buffer.

**Validate:**
- Drop counter increments (`events_dropped_total`)
- No silent loss — counter is visible in `[METRICS]` log line
- No deadlock

---

## 8. Cross-Environment Consistency

Run tests 2.1–2.4 on both Docker VM and GKE. Compare:

| Check | Docker VM | GKE |
|-------|-----------|-----|
| Same rule fires | ✓ | ✓ |
| `WorkloadIdentity.Service` consistent | e.g. `inventory-service` | e.g. `inventory-service` |
| `WorkloadIdentity.Runtime` | `docker` | `k8s` |
| No env-specific logic leaks into rules | ✓ | ✓ |

Service name consistency validates the normalization decision (`_` → `-`). If names differ, the normalization strategy needs adjustment.

---

## 9. CO-RE / Kernel Compatibility

### 9.1 BPF program load on both kernels

```bash
# VM1 (kernel 6.1.0-44)
sudo bpftool prog list | grep edr

# VM2 / GKE node (kernel 6.8.0-1042-gke)
kubectl exec <edr-monitor-pod> -- bpftool prog list | grep edr
```

**Validate:** programs load without error on both kernels — no struct mismatch, no BTF relocation failures.

---

## 10. Reporting Template

For each test, record:

| Field | Value |
|-------|-------|
| Test name | e.g. `2.1 Shell spawn` |
| Environment | Docker / GKE |
| Input | command run |
| Expected | alert level + rule |
| Observed | actual alert output |
| Metrics snapshot | `[METRICS]` line at test time |
| Result | PASS / FAIL |
| Notes | any anomaly or observation |

---

## Minimal Success Criteria

The system is considered valid when:

| Criterion | Target |
|-----------|--------|
| All functional detections fire | 2.1–2.4 all PASS |
| No CRITICAL/HIGH on normal traffic | 3.1–3.2 PASS |
| Agent self-filter works | 3.3 PASS |
| Drop rate under moderate stress | `dropped / received` < 1% |
| No pipeline deadlock | 7.1–7.2 PASS |
| Resolver accuracy under churn | `unknown_ns_total / events_received_total` < 1% during 5.2 |
| unknown-ns grace period works | 5.4 Scenario A PASS |
| CO-RE loads on both kernels | 9.1 PASS |

---

## Running the Plan

```bash
# Automated scenarios (implement as validate-gke.sh)
./validate-gke.sh [section]   # e.g. ./validate-gke.sh 2 (functional only)
./validate-gke.sh all         # full suite

# Sections 6, 7 require debug flags — run separately
# Section 5.4 requires debug resolver mechanism — implement in Phase 2
```

Keep it executable, not theoretical. Each test produces a metrics snapshot + PASS/FAIL. No framework needed — repeatability and visibility are the goals.
