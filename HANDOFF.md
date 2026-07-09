# Project Handoff — Current Status

**Last Updated:** 2026-07-09
**Status:** ✅ Detection working on DO K8s (`./validate-do-k8s.sh` 11/11) and Docker
(`validate.sh` 10/10) — validated with structured-matcher rules (Steps 1–3).

**Working:**
- Layer 1 fast-path filtering (ppid==0, pid in safeInfraPIDs)
- Layer 2 whitelisting (global_exceptions + macros; skipped for verified containers)
- Process ancestry cache + bounded ancestry walk (see `docs/DESIGN-PROCESS-ANCESTRY-CACHE.md`)
- K8s + Docker workload resolution — real service/pod/namespace attribution, kill/block responses
- LOW telemetry stream (`state=unknown` residual) → file + Supabase, kept off the Redis dashboard
- Docs aligned with the current design (GKE / Cloud-Logging-era files archived under `docs/archive/`)

**Current focus:** YAML rules engine — structured matchers (see **Active task** below).
Work step-by-step; STOP after each step for user review before starting the next.

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
`pkg/detector/yaml_detector.go` + `response_policy.go`; rule *data* is `rules/process.yaml` /
`file.yaml` / `network.yaml` (per-sensor detections) + `rules/common.yaml` (shared lists +
Layer 1/2 config); resolver is `pkg/workload/`; sink/env config is `internal/config/config.go`.

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
  ├─ rules/ (process/file/network.yaml detections + common.yaml shared lists)
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

Setup / build / sink details: `docs/SETUP.md`. Self-documented rule data: `rules/` (per-sensor
detections in `process.yaml`/`file.yaml`/`network.yaml`, shared lists in `common.yaml`).

---

## Active task — YAML rules engine: structured matchers (design agreed 2026-07-08)

**Goal:** YAML is the only source of truth for detection rules + policy. Option B agreed —
**structured matchers** (declarative match primitives referencing lists), NOT a Falco-style
expression evaluator (maybe later). One YAML file per eBPF hook, so adding a hook = adding a file.

**Why:** today the Go detector hardcodes matching, order, and severity; the YAML `detections:`
block is loaded but never read → three-way drift (severity: `/etc/shadow` CRITICAL in Go vs HIGH
in YAML; rule NAMES: `T1082_system_discovery` vs Go's `T1082_system_info_discovery`; order:
YAML map has none). YAML detection names must adopt the Go rule names — validate scripts assert
those exact strings.

**Agreed schema** (detections are an ordered LIST, CRITICAL→LOW = check order; loader validates
order, list refs, and severity at load, fail-fast):

```yaml
detections:
  - name: T1059_unix_shell_execution      # = emitted rule name (validate.sh asserts it)
    severity: CRITICAL
    require_container: true               # false = fires for host/unknown too (T1036)
    match:      { comm_suffix_in: shell_processes }     # primitives: comm_suffix_in,
    exceptions: { comm_base_in: customer_applications } #   comm_base_in, comm_prefix_in,
    message: "Shell spawned from container — possible RCE" # file_prefix_in, file_suffix_in,
    response: ~                           # Step 5                # exclude_contains
```

**Agreed decisions:**
- Duplicate `name:` entries allowed (T1552_004: ssh dirs=CRITICAL entry + key-file suffixes=HIGH entry).
- Messages are plain strings (no `%proc.name` templating — comm/service are structured alert fields).
- Severity ordering is a visible behavior change: `/tmp/bash` in container fires T1059 (CRITICAL)
  not T1036 (HIGH) — order is YAML-defined now, accepted.
- Pipeline flow unchanged: Layer 1 safeProcs skip → global_exceptions → rules check. The
  `state=unknown` ancestry-walk → LOW telemetry path, `ppid==1` skip stay Go pipeline logic.
- Shared lists STAY in `common.yaml` until Step 4 (`shell_processes` feeds the ancestry walk,
  `suspicious_exec_paths` feeds anti-spoof — moving them early would break pipeline precomputes).
- Old `macros:` + free-text `condition:` are dead with Option B — deleted in Step 4, not before.

**Steps (STOP after each — user reviews/validates before the next):**
1. ✅ `rules/process.yaml` — DONE (2026-07-08). 4 process detections moved (T1059, T1105,
   T1613, T1036); loader has `DetectionRule`/`MatchSpec` (severity typed `alert.Level`, no
   hardcoded strings), loads process.yaml from the common.yaml dir, REQUIRED + fail-fast
   validation (severity, CRITICAL→LOW order, list refs); `checkProcessRules` = one loop over
   precompiled detections, telemetry path untouched; Dockerfile now `COPY rules/` (whole dir —
   K8s image needs process.yaml or agent fails at startup). Unit tests added
   (`pkg/rules/loader_test.go` incl. real-rules load guard; `pkg/detector/yaml_detector_test.go`
   11 cases). Verified: `make test` green, Docker VM `validate.sh` **10/10**,
   K8s `validate-do-k8s.sh` **11/11** (image re-pushed, agent restarted).
2. ✅ `rules/file.yaml` — DONE (2026-07-08). 9 file detections (T1552_004 split: dirs=CRITICAL
   entry + suffixes=HIGH entry, same emitted name). Schema change: `exceptions:` is now a
   LIST of specs (OR between entries, AND within — needed for "pem CA-bundle OR customer
   app"). New primitives: `file_prefix_in/suffix_in/exact_in/contains_in`. The old global
   file whitelist (customer_applications) is now an explicit per-rule exception; runc-state
   whitelist stays Go pipeline. Behavior deltas (accepted): generic `file_contains_in:
   pem_exclude_paths` excludes ALL key suffixes under /site-packages//certifi/ (Go excluded
   .pem only); alert messages are static (filename is a structured field). Unit tests added
   by user review round. Validated 2026-07-09: Docker VM 10/10, K8s 11/11.
3. ✅ `rules/network.yaml` — DONE (2026-07-08). T1041: match `dst_ip_not_in: private_ranges`
   (replaces per-event isPrivateIP CIDR re-parse — now parsed once at compile), exceptions
   `dst_port_in: allowed_ports` / `service_in: allowed_services`. allowed_ports/services
   moved from the `network:` block into `lists:` (block deleted from common.yaml;
   `RulesDB.Network` struct is now dead — remove in Step 4). matchInput struct carries
   comm/filename/dstIP/dstPort/service through one shared matcher. NOTE (pre-existing, not
   changed): `network_init.go` privateNets (SERVICE_CIDR/GKE CIDR) is populated but never
   read — the YAML private_ranges is the real check. Validated 2026-07-09: Docker VM 10/10,
   K8s 11/11.
4. ✅ Clean up `common.yaml` — DONE (2026-07-09). Deleted dead `detections:`/`macros:` blocks
   (T1611_escape_host_fs deferred note preserved on the `container_fs_paths` list; ns-telemetry
   rationale pointer kept in the file header). Deleted 10 orphan lists referenced by nothing
   (shell_binaries, system_container_detection_tools, container_runtime_execs,
   docker_lifecycle_tools, digitalocean_cloud_agents, k8s_infrastructure_procs,
   gcp_cloud_agents, gke_infrastructure_procs, digitalocean_infrastructure_procs,
   compiled_infra_runtime_whitelist — all dead since the ancestry-walk design; git history has
   the data). Loader: removed dead `Detection`/`MacroDef`/`Network` types, `RulesDB`
   Macros/Detections/Network fields, `GetMacro`. **List placement decision: ALL lists stay in
   common.yaml** — several are shared across sensors/pipeline, and per-sensor lists would need
   loader merge + cross-file ref validation for zero behavior gain. `make test` green
   (loader real-rules guard passes). Awaiting real-env validation.
5. `response:` per detection in YAML (kill_process / block_ip); `response_policy.go` reads
   from rules data instead of its Go table. Only after detection is proven.

---

## Future initiative: Behavioral & Anomaly Detection

Add threat detection from historical alert data in Supabase: baseline normal behavior, detect
anomalies (unusual process chains, abnormal file access, unexpected connections), score
deviations rather than only matching YAML rules. The LOW telemetry stream (off the dashboard,
persisted to file + Supabase) is this service's input. Design and implementation not started;
persistence infrastructure is ready.
