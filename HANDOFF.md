# Project Handoff — Current Status

**Last Updated:** 2026-07-09
**Status:** ✅ Detection + response working on DO K8s (`./validate-do-k8s.sh` 11/11) and
Docker VM (`validate.sh` 10/10). YAML rules engine complete — no active task.

**Next:** see **Plan** section below (issue fixes → K8s load test via order service).
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

## Plan — next steps (prioritized 2026-07-09)

1. ✅ **Supabase sink on K8s → IPv4 Supavisor pooler.** DONE (2026-07-09) — `supabase sink
   connected` on DO K8s. The lever is `DATABASE_REGION` (=`1-us-east-1`, already in
   `infra/.env`), which selects `aws-<region>.pooler.supabase.com` + `postgres.<project>`
   user, port 5432 session mode. Wired: DS manifest env (optional configMapKeyRef
   `database-region`), deploy-ebpf-k8s.sh ConfigMap keys (also added `alert-log-path` —
   previously only the removed set-env workaround provided it), sink logs `connected via
   <host>` (visible after next image push). health-ai `deploy.sh` now runs
   `_ensure_ebpf_config` before the DS apply — refreshes ConfigMap/Secret from the ebpf
   repo's `infra/.env`, so no manual `kubectl patch` in the future (keep its keys in sync
   with deploy-ebpf-k8s.sh). Validated: alert rows confirmed in the Supabase `alerts` table.
2. **Fix file-dedup double-fire** — root cause found + fixed (2026-07-09), pending real-env
   validation. The sensor's pid is the tgid (process), but its comm is the THREAD name
   (`bpf_get_current_comm`), so two differently-named threads opening the same file made
   distinct dedup keys → double alerts. Fix: `Comm` removed from `fileDedupKey`
   ({Pid, Filename} only, main.go). Confirm diagnosis against historical data: a dup pair
   in Supabase should show different `comm` values. Validate: rebuild/push image, redeploy,
   rerun the noisy scenario → single alert.
3. **validate.sh cheap fixes:** `/13` header → 10; add `no_alert` helper to restore T6;
   stage a static `nc`/`wget` to restore T2. (T7 stays blocked on the T1611 overlay-rule
   allowlist — separate design task.)
4. **K8s load test — via the order service.** health-ai is unsuitable for load testing
   (each account needs manual creation work). The order service already has extensive
   integration tests incl. traffic load tests, but is NOT yet deployed to K8s — deploying
   it there is the prerequisite (extra work, scope TBD). Then run the load test per the
   open task in `docs/PERFORMANCE.md`: baseline → ramp load → find per-source ceiling
   (watch `rawDropped`/`enrichedDropped`/`alertDropped` + `produced≫resolved` backlog +
   agent CPU) → `validate-do-k8s.sh` under peak load → soak for memory growth.
5. **Activate `block_ip` kernel side — AFTER the load test** (active blocking would skew
   test traffic). Needs `lsm-connect.bpf.c` map uncomment + `go generate` on the Linux VM
   (documented activation path in `pkg/detector/response.go`) — the sanctioned exception
   to the no-BPF-edits rule.
6. **Opportunistic, no schedule:** remove dead `network_init.go` privateNets when next in
   the detector; Docker cache eviction stays deferred (test-VM-only slow leak).

---

## Deferred / known issues (documented, none blocking)

- **Docker container cache never evicts.** `listenDockerEvents()` is disabled in
  `DockerResolver.Start()` — its reconnect/recovery path had unresolved issues and is hard to
  test without a scriptable Docker daemon. Cache-cleanup (and `lightweightRefresh()`) lived
  only there, so `r.cache`/`r.containerToNs` only grow. Not a correctness problem — containers
  are still discovered on-demand via `asyncResolvePID` — just a slow memory/staleness leak.
- **File-dedup double-fire — FIXED 2026-07-09, pending real-env validation** (see plan item 2).
- **File-dedup shard maps never evict.** `fileDedupShards_array` (main.go) has no sweep — the
  cleanup worker only sweeps the ancestry cache — so entries ({pid, filename} → time) accumulate
  forever. Tiny entries, slow growth; same class as the Docker cache leak. Fix is a periodic
  sweep dropping entries older than `fileDedupWindow`.
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
