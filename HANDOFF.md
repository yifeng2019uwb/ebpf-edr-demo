# Project Handoff — Current Status

**Last Updated:** 2026-07-09
**Status:** ✅ Detection + response working on DO K8s (`./validate-do-k8s.sh` 11/11) and
Docker VM (`validate.sh` 10/10). YAML rules engine complete — no active task.

**Next candidates:** deferred issues below, or the Behavioral & Anomaly Detection
initiative (last section).
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
  host-reads-container-overlay rule is disabled (its data `container_fs_paths` stays in
  common.yaml). Header still reads `/13` (10 tests now) — cosmetic.
- **`block_ip` kernel side not compiled.** T1041 declares `response: block_ip` but the
  `blocked_ips` LPMTrie map in `kernel/lsm-connect.bpf.c` is commented out — responder skips
  with a log line (alert-only in practice). Activation steps in `pkg/detector/response.go`.
- **`network_init.go` privateNets is dead code** — populated (SERVICE_CIDR/GKE CIDR) but never
  read; the YAML `private_ranges` list is the real check. Remove or wire when touched next.

---

## Completed (details in git history + docs)

- **YAML rules engine — structured matchers** (2026-07-08 → 09, validated both envs):
  per-sensor rule files + shared lists, ordered CRITICAL→LOW evaluation, fail-fast load
  validation, per-detection `response:` (kill_process / block_ip), old Go rule table /
  macros / `response_policy.go` deleted. Design details: `docs/DETECTION-RULES-AND-POLICY.md`.
- **Process ancestry cache + bounded walk** — parent-verified trust for `state=unknown`,
  LOW telemetry stream (off Redis dashboard, persisted to file + Supabase).
  Design: `docs/DESIGN-PROCESS-ANCESTRY-CACHE.md`.
- **K8s + Docker workload resolution** — real service/pod/namespace attribution.
- **Docs aligned** with the current design (GKE/Cloud-Logging-era files under `docs/archive/`).

---

## Future initiative: Behavioral & Anomaly Detection

Add threat detection from historical alert data in Supabase: baseline normal behavior, detect
anomalies (unusual process chains, abnormal file access, unexpected connections), score
deviations rather than only matching YAML rules. The LOW telemetry stream (off the dashboard,
persisted to file + Supabase) is this service's input. Design and implementation not started;
persistence infrastructure is ready.
