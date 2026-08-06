# Project Handoff — Current Status

**Last Updated:** 2026-08-05

**Status:** Detection + response engine working on both Docker VM (`validate.sh`) and DO K8s
(`validate-do-k8s.sh`). Trusted-app whitelist (service + scoped actions) is the main
**not-yet-built** feature — see **Active design** below.

**Deadline: DO credit expires 2026-08-16.** Prioritizing finishing the rest of the project over
polishing already-working parts — known, non-blocking gaps are deliberately left for later.

For multi-step work: STOP after each step for user review before starting the next.

## Notes — pending discussion, not started

- **Wire in `runtime.MemStats` periodic logging** — add a lightweight ticker (matching the
  existing 10s DEBUG pattern in `startEventReader`, `cmd/edr-monitor/main.go`) logging
  `Alloc`/`Sys`/`HeapObjects`/`NumGC`/goroutine count, so the next load test round produces
  real heap composition data instead of struct-size estimates (see `docs/PERFORMANCE.md`).
- **`StatePending` retry window (3s × 20 = 60s, `cmd/edr-monitor/main.go:32-34`)** — is 60s too
  conservative? Covers K8s cold-start latency (image pull + init containers), not resolver
  compute time; shortening trades faster resolution for more false CRITICAL
  `unknown_namespace_process` alerts on legitimately slow-starting pods. Not decided.

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

**Deploy flows:** health-ai `kubernetes/deploy.sh app-deploy`/`ebpf-deploy` refreshes the
`ebpf-alerts` ConfigMap/Secret from this repo's `infra/.env` (`_ensure_ebpf_config`) and applies
the local DS manifest. The standalone `scripts/deploy-ebpf-k8s.sh` does the same but curls the
manifest from GitHub main — keep the two scripts' ConfigMap keys in sync.

**Hard constraints (also in CLAUDE.md):** never run git; never edit `.bpf.c`; never edit
`infra/.env` (secrets — user edits on the VM); no TODO / future-commitment comments.

---

## Recently completed (2026-08-03 → 2026-08-05) — validated via validate.sh/validate-do-k8s.sh

- **Resolver rewrite.** Single runtime-agnostic `Engine` (`pkg/workload/resolver_engine.go`),
  replacing per-`--runtime` resolvers. Fixed permanent `Unknown` caching, no cache eviction,
  DOKS `enrich()` never querying a client, and the cgroup-migration case
  (`isContainerRuntimeDaemonCgroup`) — see code comments there for why, not repeated here.
- **Rule redesign vs Falco/Tetragon.** Added `has_tty`/`args` to `exec_event`
  (`execsnoop.bpf.c`/`event.h`), tightened `T1059`/`T1105`/`T1036` (`rules/process.yaml`
  comments explain each). Still-open gaps documented as comments in `rules/*.yaml`, no code:
  `T1611`/`T1053.003` need `Fmode & FMODE_WRITE` gating, `T1070.003` needs `O_TRUNC`/
  `unlink`/`rename`, `T1003.008`'s credential path list is incomplete, network hook could add
  `l4proto`.

**Still open (not blocking, parallel-track — revisit opportunistically before 8/16):**
- **Short-id fallback can still stick permanently** if `RuntimeClient.Enrich` fails once —
  blocks the trusted-app whitelist below (`service_in` needs a real name, not a short-id).
- **`DEBUG:` log lines kept intentionally** — personal project, no strict log hygiene needed.

---

## Implemented but NOT yet live-validated

- **Process-rule severity downgrade for unresolved service (2026-08-05)** — `T1059`, both
  `T1105` entries, `T1613` (not `T1036`); see comments in `rules/process.yaml`,
  `pkg/rules/loader.go`, `pkg/detector/yaml_detector.go` for what/why. **Verified unit-level
  only** (`Detect()` called directly with a mocked unresolved service) — not yet confirmed
  against a real running agent/alert pipeline.

---

## Active design — trusted-application whitelist (agreed direction, NOT yet built)

**Problem.** `customer_applications` matches on comm, not the app: localstack reading its own
TLS cert has `comm=python`, so `T1552_004` fires and `kill_process` SIGKILLs it — adding
`localstack` to the whitelist does nothing. Same class of bug killed cilium on K8s.

**Agreed model:** identify by resolved **service** (not comm), scoped to **known actions only**
(not blanket trust) — e.g. localstack may read its own `*.pem/.key` and call AWS, nothing else
outside that profile is exempted. Options weighed: global service skip (too coarse, rejected),
per-rule `service_in` exception (reuses the existing, tested primitive — **chosen
mechanism**), path exception (narrowest, whack-a-mole per app). Direction = `service_in`
expressed as a per-service action profile — design the profile shape before coding, do NOT
quick-patch.

**First narrow use, DONE (2026-08-05) — not the full redesign.**
`T1552_004_private_keys` excepts `service_in: own_tls_cert_services` for localstack's cert
read (see `rules/common.yaml`/`file.yaml` comments for why). Process rules still don't carry
`service` at all — only file/network rules do.

**Out of scope: cilium.** Resolves to `service=k8s-pod-<hash>`, empty namespace (resolver
can't identify kube-system pods before CNI is up) — needs a namespace-resolution fix first.

---

## Plan — next steps

1. **K8s load test — paused, not closed out (2026-07-14).** order-processor capped at ~300
   req/s (LocalStack's own routing layer was the bottleneck; swapping to
   `amazon/dynamodb-local` gave ~4x throughput but still short of the 50k/5k target — see
   `docs/PERFORMANCE.md` Attempt 2). eBPF agent itself handled the load fine (no crashes, no
   kill_process incidents) — one EDR pod OOMKilled ~9h15m in, see Deferred issues below.
   Next candidate if resumed: a synthetic load generator in a VM, not another REST app on K8s.
2. **Activate `block_ip` kernel side — AFTER any load test** (active blocking would skew
   traffic). Needs `lsm-connect.bpf.c` map uncomment + `go generate` on the Linux VM — the
   sanctioned exception to the no-BPF-edits rule (see `pkg/detector/response.go`).
3. **Opportunistic, no schedule:** items in Deferred / known issues below.

---

## Deferred / known issues (documented, none blocking)

- **EDR pod OOMKilled after ~9h15m uptime (2026-07-14, exit 137) — cause unconfirmed, not
  root-caused.** No crash-loop/panic, just ran out of memory during a load-test burst
  (~45-47k events/10s). Decision: treat as resource sizing (bump DaemonSet limits to match
  actual expected event rate) rather than root-causing now — not confirmed to be a leak.
- **`block_ip` kernel side not compiled** (= Plan item 2). `blocked_ips` LPMTrie map in
  `kernel/lsm-connect.bpf.c` is commented out — responder skips with a log line (alert-only).
- **`validate.sh` T1611 overlay test out** — blocked on the disabled T1611
  host-reads-container-overlay rule and its allowlist design.
- **File-dedup shard maps never evict** — `fileDedupShards_array` (main.go) has no sweep;
  entries ({pid, filename} → time) accumulate forever. Tiny/slow growth. Fix: periodic sweep
  dropping entries older than `fileDedupWindow`.
- **`network_init.go` privateNets is dead code** — populated but never read; `private_ranges`
  YAML list is the real check. Remove or wire when touched next.
- **EDR DaemonSet removed from DO K8s once (2026-07-10)** — was SIGKILLing cilium (T1552_004 on
  its Hubble `server.key`), blocking node scheduling. Re-add only after the trusted-app
  whitelist fix, else it re-kills cilium on the next Hubble cert rotation.
- **cilium namespace resolution** — kube-system pods resolve to `service=k8s-pod-<hash>`, empty
  namespace (resolver needs CNI that cilium itself provides — chicken/egg on a cold node), so
  `ignore_namespaces: [kube-system]` doesn't catch them. See Active design "out of scope" note.
- **Short-id fallback caches permanently** — see "Recently completed" above.

**Dedup gotcha (keep in mind when touching the enricher):** `fileDedupKey` is {Pid, Filename}
— deliberately no comm (sensor comm is the THREAD name; including it caused double alerts).
`runc:[…]` events are excluded from the dedup map: runc reads /etc/passwd + /etc/group during
docker-exec setup and then execs the target under the SAME pid, so recording them would
dedup-shadow the target's own first read (T1082 missed `cat /etc/passwd`).

---

## Future ideas (not built, no commitment to build)

**Behavioral & anomaly detection.** Baseline normal behavior from historical Supabase alert
data, score deviations instead of only matching YAML rules. Not started; persistence
infrastructure (Supabase, both environments) is ready — that's the input this would use.
Input source, confirmed 2026-08-05: the LOW/info-level alert stream specifically — individually
noisy, low-confidence events are exactly the raw material this needs, not a byproduct to
filter out. The `service_unresolved_severity` downgrade (see "Implemented but NOT yet
live-validated" above) is a direct contributor — it turns what would otherwise be a full-severity
alert or a silently dropped event into a LOW-severity record, feeding this future input rather
than being discarded either way.

**Exception scaling** (found 2026-08-05, via localstack's `T1036` false positive). A
service-name-keyed exception list doesn't scale: grows unboundedly (whack-a-mole per app), and
goes stale the moment an image's startup behavior changes. Customer-authored exception rules
are rejected outright, not just deferred — a compromised workload could blind its own
detection. Middle path worth remembering: key the exception profile by **container image
digest**, derive it from **observed behavior during a bounded learning window**, not authored
by anyone — a new digest has no profile yet, so it falls back to strict detection (safe
default) instead of silently mismatching a stale entry. Narrower than the anomaly-detection
idea above (a bounded per-workload baseline, not general statistical scoring). Real
infrastructure (learning-mode state machine, per-digest storage) — bigger than a rule tweak,
solo-dev time/cost doesn't currently support it.
