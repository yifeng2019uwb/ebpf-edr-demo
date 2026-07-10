# Project Handoff — Current Status

**Last Updated:** 2026-07-10
**Status:** ✅ Detection + response working and validated on DO K8s
(`./validate-do-k8s.sh` 11/11) and Docker VM (`validate.sh` 12/12). Alerts + LOW
telemetry persist to Supabase from both environments.

**Next:** see **Plan** below (order-service K8s deploy → load test → block_ip).
For multi-step work: STOP after each step for user review before starting the next.

---

## Doc map — read these, don't re-derive from code

| Need | Source of truth |
|---|---|
| System architecture / pipeline | `docs/CURRENT_DESIGN.md` |
| Detection rules + policy layers (per-rule) | `docs/DETECTION-RULES-AND-POLICY.md` |
| Parent verification / ancestry cache | `docs/DESIGN-PROCESS-ANCESTRY-CACHE.md` |
| MITRE technique table + responses | `docs/MITRE-COVERAGE.md` |
| Throughput / perf state + targets | `docs/PERFORMANCE.md` |
| Setup / build / deploy / validate / sinks | `docs/SETUP.md` |
| Open issues / next steps | this file |

**Ground truth (YAML rules + Go engine):** matching, severity, order, and `response:` are
declared in `rules/process.yaml` / `file.yaml` / `network.yaml` (per-sensor detections);
`rules/common.yaml` holds shared lists + Layer 1/2 config. `pkg/detector/yaml_detector.go` is
the engine (plus Go-only pipeline logic: ppid==1 skip, ancestry walk, telemetry);
`pkg/detector/response.go` executes responses. Resolver is `pkg/workload/`; sink/env config is
`internal/config/config.go`.

**Deploy flows:** health-ai `kubernetes/deploy.sh app` refreshes the `ebpf-alerts`
ConfigMap/Secret from this repo's `infra/.env` (`_ensure_ebpf_config`) and applies the local
DS manifest. The standalone `scripts/deploy-ebpf-k8s.sh` does the same but curls the manifest
from GitHub main — keep the two scripts' ConfigMap keys in sync.

**Hard constraints (also in CLAUDE.md):** never run git; never edit `.bpf.c`; never edit
`infra/.env` (secrets — user edits on the VM); no TODO / future-commitment comments.

---

## Plan — next steps

1. **K8s load test — via the order service.** health-ai is unsuitable for load testing
   (each account needs manual creation work). The order service already has extensive
   integration tests incl. traffic load tests, but is NOT yet deployed to K8s — deploying
   it there is the prerequisite (extra work, scope TBD). Then run the load test per the
   open task in `docs/PERFORMANCE.md`: baseline → ramp load → find per-source ceiling
   (watch `rawDropped`/`enrichedDropped`/`alertDropped` + `produced≫resolved` backlog +
   agent CPU) → `validate-do-k8s.sh` under peak load → soak for memory growth.
2. **Activate `block_ip` kernel side — AFTER the load test** (active blocking would skew
   test traffic). Needs `lsm-connect.bpf.c` map uncomment + `go generate` on the Linux VM
   (documented activation path in `pkg/detector/response.go`) — the sanctioned exception
   to the no-BPF-edits rule. validate.sh T4's block-verification steps (bpftool flush,
   EPERM checks) are already in place and become meaningful once this lands.
3. **Opportunistic, no schedule:** items in Deferred / known issues below.

---

## Deferred / known issues (documented, none blocking)

- **`block_ip` kernel side not compiled** (= plan item 2). T1041 declares
  `response: block_ip` but the `blocked_ips` LPMTrie map in `kernel/lsm-connect.bpf.c` is
  commented out — responder skips with a log line (alert-only in practice).
- **`validate.sh` T1611 overlay test out.** Blocked on the disabled T1611
  host-reads-container-overlay rule and its allowlist design; the rule's data
  (`container_fs_paths`) stays in common.yaml.
- **Docker container cache never evicts.** `listenDockerEvents()` is disabled in
  `DockerResolver.Start()` — its reconnect/recovery path had unresolved issues and is hard to
  test without a scriptable Docker daemon. Cache-cleanup (and `lightweightRefresh()`) lived
  only there, so `r.cache`/`r.containerToNs` only grow. Not a correctness problem — containers
  are still discovered on-demand via `asyncResolvePID` — just a slow memory/staleness leak.
- **File-dedup shard maps never evict.** `fileDedupShards_array` (main.go) has no sweep — the
  cleanup worker only sweeps the ancestry cache — so entries ({pid, filename} → time) accumulate
  forever. Tiny entries, slow growth; same class as the Docker cache leak. Fix is a periodic
  sweep dropping entries older than `fileDedupWindow`.
- **`network_init.go` privateNets is dead code** — populated (SERVICE_CIDR/GKE CIDR) but never
  read; the YAML `private_ranges` list is the real check. Remove or wire when touched next.

**Dedup gotcha (keep in mind when touching the enricher):** `fileDedupKey` is {Pid, Filename}
— deliberately no comm (sensor comm is the THREAD name; including it caused double alerts).
`runc:[…]` events are excluded from the dedup map: runc reads /etc/passwd + /etc/group during
docker-exec setup and then execs the target under the SAME pid, so recording them would
dedup-shadow the target's own first read (T1082 missed `cat /etc/passwd`).

---

## Future initiative: Behavioral & Anomaly Detection

Add threat detection from historical alert data in Supabase: baseline normal behavior, detect
anomalies (unusual process chains, abnormal file access, unexpected connections), score
deviations rather than only matching YAML rules. The LOW telemetry stream (off the dashboard,
persisted to file + Supabase) is this service's input. Design and implementation not started;
persistence infrastructure is ready — Supabase now receives from both Docker VM and DO K8s.
