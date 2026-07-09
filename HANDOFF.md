# Project Handoff — Current Status

**Last Updated:** 2026-07-08
**Status:** ✅ Detection working on DO K8s (`./validate-do-k8s.sh` 11/11) and Docker (`validate.sh`).

**Working:**
- Layer 1 fast-path filtering (ppid==0, pid in safeInfraPIDs)
- Layer 2 whitelisting (global_exceptions + macros; skipped for verified containers)
- Process ancestry cache + bounded ancestry walk (see `docs/DESIGN-PROCESS-ANCESTRY-CACHE.md`)
- K8s + Docker workload resolution — real service/pod/namespace attribution, kill/block responses
- LOW telemetry stream (`state=unknown` residual) → file + Supabase, kept off the Redis dashboard
- Docs aligned with the current design (GKE / Cloud-Logging-era files archived under `docs/archive/`)

**Current focus:** none active. Next candidates are the two YAML rules-engine refactors in
**Planned** below. Work task-by-task; the user reviews each before the next.

---

## Doc map — read these, don't re-derive from code

| Need | Source of truth |
|---|---|
| System architecture / pipeline | `docs/CURRENT_DESIGN.md` |
| Detection rules + policy layers (per-rule) | `docs/DETECTION-RULES-AND-POLICY.md` |
| Parent verification / ancestry cache | `docs/DESIGN-PROCESS-ANCESTRY-CACHE.md` |
| MITRE technique table | `docs/MITRE-COVERAGE.md` |
| Throughput / perf state + targets | `docs/PERFORMANCE.md` |
| Setup / build / deploy / sinks | `docs/SETUP.md` |
| Done / deferred / planned | this file (sections below) |

**Ground truth in code (only when a doc is insufficient):** matching + severity + response live in
`pkg/detector/yaml_detector.go` + `response_policy.go` (**not** the YAML `detections:` block — that
is declarative reference); rule *data* is `rules/default.yaml`; resolver is `pkg/workload/`;
sink/env config is `internal/config/config.go`.

**Hard constraints (also in CLAUDE.md):** never run git; never edit `.bpf.c`; never edit
`infra/.env` (secrets — user edits on the VM); no TODO / future-commitment comments.

---

## Deferred / known issues (documented, none blocking)

- **`./deploy.sh app` never applies the eBPF DaemonSet — Pulumi hang.** health-ai
  `kubernetes/deploy.sh` → `_apply_daemonset()` hangs at two `pulumi stack output` calls
  (region/cluster) that run before `kubectl apply` — GKE/Pulumi-era code we no longer use, so
  the DaemonSet's `kubectl apply` + `rollout restart` never run (the image still lands via
  `rollout restart` + `imagePullPolicy: Always`, so the binary is current but env changes are
  not). Workaround in place: `kubectl -n kube-system set env daemonset/ebpf-edr
  ALERT_LOG_PATH=/alerts/alert.log` — persists in the DS spec and is not clobbered by the
  hanging apply. Proper fix would drop the `pulumi stack output` lookups (hardcode/env
  `${REGION}`/`${CLUSTER_NAME}` for `envsubst`, or move `kubectl apply` ahead of them); the Go
  side (config.go env read + file_sink dir create) is already correct.
- **Supabase sink disabled on K8s.** `DATABASE_URL` resolves over IPv6 and DO nodes have no
  IPv6 route, so LOW telemetry persists only to the node file until the URL uses the
  IPv4/Supavisor endpoint.
- **Docker container cache never evicts.** `listenDockerEvents()` is disabled in
  `DockerResolver.Start()` — its reconnect/recovery path had unresolved issues and is hard to
  test without a scriptable Docker daemon. Cache-cleanup (and `lightweightRefresh()`) lived
  only there, so `r.cache`/`r.containerToNs` only grow. Not a correctness problem — containers
  are still discovered on-demand via `asyncResolvePID` — just a slow memory/staleness leak.
- **File-dedup double-fire.** Some file alerts fire twice ~80ms apart despite the 1s
  `fileDedupWindow` — cosmetic noise, low priority. Likely the dedup key differs subtly between
  the two events (thread vs group-leader pid, or trailing bytes in `Comm`/`Filename`).
- **`validate.sh` T2/T6/T7 removed** — each needs work before it can assert honestly: T2 needs a
  working static `nc`/`wget` in the container; T6 needs a `no_alert` helper; T7's T1611
  host-reads-container-overlay rule is commented out in `checkFileRules`. Header still reads
  `/13` (10 tests now) — cosmetic.

---

## Architecture

```
eBPF Agent (deployed everywhere via DaemonSet)
  ├─ eBPF programs (kernel): execsnoop, opensnoop, lsm-connect
  ├─ Event enrichment: workload resolver (Docker/K8s)
  ├─ Detection: YAML rules + response actions
  └─ Alert sinks: file, Redis, Supabase

Alert Pipeline
  ├─ Redis pub/sub (real-time; LOW dropped)
  ├─ Supabase PostgreSQL (persistent; disabled on K8s — IPv6)
  └─ Alert Router web UI (viewing)

Configuration
  ├─ rules/default.yaml (detection rules)
  ├─ infra/.env (credentials)
  └─ k8s/ebpf-edr-ds.yaml (K8s manifest)
```

---

## Deployment

- **DigitalOcean K8s** — primary (health-ai services deployed)
- **Docker VM** — local testing for eBPF changes

```bash
# Deploy to K8s
bash scripts/deploy-ebpf-k8s.sh
./validate-do-k8s.sh          # expect 11/11

# Rebuild eBPF (Linux VM only) and redeploy
make rebuild
make docker-push-ghcr-prebuilt
bash scripts/deploy-ebpf-k8s.sh
```

Setup / build / sink details: `docs/SETUP.md`. Self-documented rule data: `rules/default.yaml`.

---

## Planned — YAML rules engine evolution

Two related refactors toward making `default.yaml` the real source of truth. Today the Go
detector hardcodes the matching order and severity; the YAML `detections:` block is declarative
reference only (there is no expression evaluator), so Go wins and the two can drift — see
`docs/DETECTION-RULES-AND-POLICY.md` §0/§4.

1. **Read rule/policy from YAML (order + severity as data).** Make the detector look up each
   rule's severity by name from the loaded rules instead of hardcoding `alert.High`/`alert.Critical`
   at the ~15 `newXAlert(...)` call sites, and define the rule *check order* explicitly in YAML so
   the YAML is the spec. Needs the loader to expose `detection.severity` (`RulesDB` currently only
   surfaces `GetList`/`GlobalExceptions`/`Network`). Kills the Go-vs-YAML severity drift (e.g.
   `/etc/shadow` is CRITICAL in Go but HIGH in the YAML block).

2. **Split `default.yaml` by sensor** (process / file / network), so adding an eBPF hook = adding
   one file. Recommended shape: a shared `common.yaml` for the cross-cutting layers
   (`infrastructure_filters`, `global_exceptions`, `ignore_namespaces`, `trusted_parent_names`,
   `private_ranges`, response mapping) + one file per sensor holding that sensor's detections
   (ordered, with severity) and its type-specific lists. Avoid a naive 3-way split — it would
   fragment the shared lists. Do this **after** item 1 (loader work overlaps); the loader then
   loads + merges the set.

---

## Future initiative: Behavioral & Anomaly Detection

Add threat detection from historical alert data in Supabase: baseline normal behavior, detect
anomalies (unusual process chains, abnormal file access, unexpected connections), score
deviations rather than only matching YAML rules. The LOW telemetry stream (off the dashboard,
persisted to file + Supabase) is this service's input. Design and implementation not started;
persistence infrastructure is ready.
