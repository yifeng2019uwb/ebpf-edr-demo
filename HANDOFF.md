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
2. ✅ **Fix file-dedup double-fire** — DONE + validated (2026-07-09, no more dup file
   alerts). Root cause: the sensor's pid is the tgid (process), but its comm is the THREAD
   name (`bpf_get_current_comm`), so two differently-named threads opening the same file
   made distinct dedup keys → double alerts. Fix: `Comm` removed from `fileDedupKey`
   ({Pid, Filename} only, main.go).
3. **validate.sh cheap fixes** — DONE in code (2026-07-09), pending a VM run. Now **12
   tests** (was 10): headers/counts fixed (incl. the stale `header 5 0`); new
   `expect_no_alert` helper; T11 restores T1105 ingress-tool (cp-rename an in-container
   binary to `wget` and exec — the rule matches the exec path, no static tool needed);
   T12 restores the no-alert allowlist test (inventory_service external connect →
   suppressed; uses 1.1.1.1 so T4's future 8.8.8.8 block can't mask it; SKIPs if the
   container isn't running). After the first green 12/12 run, sweep the "10 tests /
   10/10" counts in docs (VALIDATION, NOTES, MITRE-COVERAGE, HANDOFF status).
   (T1611 overlay test stays out — blocked on the rule's allowlist, separate design task.)
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
- **File-dedup shard maps never evict.** `fileDedupShards_array` (main.go) has no sweep — the
  cleanup worker only sweeps the ancestry cache — so entries ({pid, filename} → time) accumulate
  forever. Tiny entries, slow growth; same class as the Docker cache leak. Fix is a periodic
  sweep dropping entries older than `fileDedupWindow`.
- **`validate.sh` T1611 overlay test still out** (T2/T6 equivalents restored as T11/T12,
  headers fixed — see plan item 3). Blocked on the disabled T1611
  host-reads-container-overlay rule and its allowlist design; the rule's data
  (`container_fs_paths`) stays in common.yaml.
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
