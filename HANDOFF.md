# Project Handoff — Current Status

**Last Updated:** 2026-07-14
**Status:** ✅ Detection + response working and validated on DO K8s
(`./validate-do-k8s.sh` 11/11) and Docker VM (`validate.sh` 12/12). Alerts + LOW
telemetry persist to Supabase from both environments. EDR DaemonSet is deployed and running
on a fresh DO K8s cluster (order-processor namespace) — 2/2 pods, no kill_process/cilium
issues observed over a multi-hour order-processor load test (see Plan item 1 below); the
`localstack`-killing crisis described in **Active design** did not reproduce here (order-
processor now runs `amazon/dynamodb-local`, not LocalStack — see `docs/PERFORMANCE.md`
Attempt 2). Trusted-app whitelist design itself is still **not built**.

**Next:** trusted-application whitelist redesign (see **Active design** below) is the next
real feature — not urgently blocking right now, but still not built. (One EDR pod OOMKilled
after ~9h15m uptime under sustained load — see Deferred issues below; cause unconfirmed
— prior long runs haven't OOMed, so a slow leak isn't the obvious explanation, more likely
tied to this round's load-test burst. Decided **not** to root-cause it now, just size
CPU/memory limits to the actual deployment's expected event rate. At realistic steady-state
rates, e.g. ~1000 events/s, current limits are likely fine.)
For multi-step work: STOP after each step for user review before starting the next.

**Paused (2026-07-14) — resuming in ~3-5 days.** Testing on hold; focus shifts to reading
the codebase line by line and researching how Falco and other eBPF projects handle the same
problems (resolution, dedup/cache eviction, retry/backoff policy, resource sizing), before
coming back to test with that context. DO K8s cluster **already destroyed** (both droplets)
to save cost while paused — redeploy via `kubernetes/do/deploy.sh` (order-processor) + `k8s/deploy.sh`
(EDR DaemonSet) when resuming; expect a fresh cluster (new node names/IPs) same as the last
rebuild.

## Notes — pending discussion, not started

Raised in conversation, not yet acted on. Revisit when testing resumes.

- **Wire in `runtime.MemStats` periodic logging** — add a lightweight ticker (matching the
  existing 10s DEBUG pattern in `startEventReader`, `cmd/edr-monitor/main.go`) logging
  `Alloc`/`Sys`/`HeapObjects`/`NumGC`/goroutine count, so the next load test round produces
  real heap composition data instead of struct-size estimates (see `docs/PERFORMANCE.md` for
  the estimate this would replace). Agreed in principle; no code written yet.
- **`StatePending` retry window (3s × 20 = 60s, `cmd/edr-monitor/main.go:32-34`)** — question
  raised: is 60s too conservative? Rationale in the existing code comments: covers K8s
  cold-start latency (image pull + init containers before `crictl` even has the pod's
  metadata) — not resolver compute time. Shortening it trades faster resolution for more
  false CRITICAL `unknown_namespace_process` alerts on legitimately slow-starting pods.
  Considered checking alert history for evidence of unnecessary waits before deciding either
  way — not done yet.
- **Customer exceptions system** — Create separate `rules/customer_exceptions.yaml` (independent
  of core detection rules) for service-specific exceptions. LocalStack example: suppress
  T1059/T1552/T1041 when service=localstack (shell startup, own cert reading, AWS API calls).
  Allows ops/app teams to maintain exceptions without coupling to EDR release cycle. Test with/without
  to verify core detections still work. Build exception loader in detector or at rule load time.

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

## Active design — trusted-application whitelist (agreed direction, NOT yet built)

**Problem (confirmed on the VM 2026-07-10).** The current `customer_applications` whitelist
matches on **comm** (`comm_base_in` → `filepath.Base(comm)`). comm is the binary/interpreter,
not the app: localstack reads its own TLS cert (`/var/lib/localstack/cache/server.test.pem.key`)
with `comm=python`, so `T1552_004` fires and `kill_process` SIGKILLs it. Adding `localstack` to
`customer_applications` does nothing — comm is `python`, never `localstack`. Same class of bug
killed cilium on K8s (comm=cilium-agent reading its Hubble `server.key`).

**Agreed model: trusted app = identify by SERVICE, allow only KNOWN actions.** Not blanket
trust. Two parts combined:
1. **Identity by resolved service, not comm.** The alert already carries the stable
   `service=localstack` (resolved workload identity). comm can't identify an app; service can.
2. **Scoped to expected actions.** A trusted service is exempted only for its *known* behaviors
   (e.g. localstack: read its own `*.pem/.key` under `/var/lib/localstack/`, connect out to
   AWS). Anything outside the profile (localstack spawning a shell, reading `/etc/shadow`) still
   alerts. This keeps monitoring on a trusted-but-compromised app.

**Options weighed (for the eventual build):**
- A — global service skip (`trusted_services` → skip ALL detection): simplest, but too coarse
  (blanket trust, no monitoring if compromised). Rejected as the whole answer.
- B — per-rule `service_in` exception: reuses the existing, tested `service_in` primitive
  (T1041 already uses it); needs `service` populated into file/process `matchInput` (currently
  only network sets it). This is the mechanism for "scoped to known actions".
- C — path exception (add `/var/lib/localstack/` to an exclude list, like `pem_exclude_paths`):
  narrowest, but whack-a-mole per app and ignores the network alerts.

Direction = **B as the mechanism, expressed as a per-service action profile** (service +
its allowed actions/paths). Design the profile shape before coding — do NOT quick-patch.

**Out of scope for this change (separate issue): cilium.** It resolved to
`service=k8s-pod-<hash>` with empty namespace (resolver can't identify kube-system pods before
CNI is up), so no service/name whitelist reliably catches it. Needs a namespace-resolution fix.

---

## Plan — next steps

1. **K8s load test — via the order service. DONE for this round (2026-07-14), see
   `docs/PERFORMANCE.md` Attempt 2 for full detail — paused, not closed out.**
   Rebuilt on a **fresh** DO K8s cluster after the old one lost its nodes (cilium
   CrashLoopBackOff after a bad node-pool recovery attempt — abandoned rather than fixed).
   order-processor redeployed via `kubernetes/do/deploy.sh`; EDR DaemonSet redeployed via
   this repo's `k8s/deploy.sh` (new script, auto-derives cluster/region from
   `kubectl config current-context`).
   - Found and fixed 6 real app/K8s bottlenecks (uvicorn workers, DynamoDB-emulator
     resources, replica count, botocore/PynamoDB pool size stuck at 10, redundant
     coin-price sync) — throughput crept ~50→80 req/s, still far short of useful load.
   - Root cause of the remaining ceiling: **LocalStack's own routing layer**, not app code.
     Swapped it for `amazon/dynamodb-local` (AWS's own DynamoDB-only emulator, no proxy
     hop) — throughput jumped **~4x to ~300 req/s**, latency 400-1100ms → ~310ms, zero pod
     restarts. Confirmed ~300 req/s is a real backend ceiling, not client-concurrency-limited
     (4x'ing load-generator workers gave no throughput gain, only added latency/queueing).
   - eBPF agent handled this fine: no crashes, no kill_process incidents, cilium stayed
     healthy throughout. `file produced` typically ~20k/10s (steady), briefly bursted to
     ~45-47k/10s without the agent crashing (resolver fell behind during the burst — a
     backlog, not a crash).
   - **Target (50k produced/s, 5k resolved/s) not reached** — order-processor's ~300
     req/s ceiling caps how much load this app can generate; assessment is roughly **10x**
     more sustained load is needed. **Decision: pausing K8s-based event-performance testing
     here** — next candidate if picked back up is a direct synthetic generator in a VM
     instead of another REST app on K8s.
   - **New issue found instead:** one EDR pod OOMKilled after ~9h15m uptime during/after
     this test round (exit 137) — see Deferred issues below.
2. **Activate `block_ip` kernel side — AFTER the load test** (active blocking would skew
   test traffic). Needs `lsm-connect.bpf.c` map uncomment + `go generate` on the Linux VM
   (documented activation path in `pkg/detector/response.go`) — the sanctioned exception
   to the no-BPF-edits rule. validate.sh T4's block-verification steps (bpftool flush,
   EPERM checks) are already in place and become meaningful once this lands.
3. **Opportunistic, no schedule:** items in Deferred / known issues below.

---

## Deferred / known issues (documented, none blocking)

- **EDR pod OOMKilled after ~9h15m uptime (observed 2026-07-14, exit 137) — cause
  unconfirmed, not being root-caused for now.** One of 2 DaemonSet pods on the fresh DO K8s
  cluster, during/after the order-processor load test round (see Plan item 1). Confirmed via
  `kubectl describe pod` (`Last State: Terminated, Reason: OOMKilled`) and `kubectl logs
  --previous` (agent was still logging normal produced/resolved counters right up to the
  kill — no crash-loop, no panic, just ran out of memory). Current DaemonSet limits are
  tight (128Mi mem / 200m CPU, `64Mi`/`50m` requests — `k8s/ebpf-edr-ds.yaml`).
  **Not confirmed to be a slow cumulative leak** — prior long-running deployments haven't
  hit an OOM before, which argues against the two documented unbounded-growth leaks (Docker
  container cache, file-dedup shard maps — see below) as the sole/main driver on their own.
  More likely a factor: this OOM's timing coincides with this round's load test, which
  included a burst pushing `produced` to ~45-47k events/10s (see `docs/PERFORMANCE.md`
  Attempt 2) — a burst that size could spike buffer/channel memory pressure momentarily,
  separate from any gradual leak. **Decision (2026-07-14): don't root-cause this now —
  treat as resource sizing instead.** Bump CPU/memory limits to match the actual
  deployment's expected sustained event rate when that's known; this isn't confirmed to be
  a correctness problem with the agent itself. At realistic lower steady-state rates (e.g.
  ~1000 events/s) the current limits are probably already fine — no change needed unless
  running a longer soak test at a similar or higher rate.
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
- **EDR DaemonSet removed from DO K8s (2026-07-10).** `kubectl -n kube-system delete ds ebpf-edr`
  — it was SIGKILLing cilium (T1552_004 on cilium's Hubble `server.key`), so a fresh node's
  cilium never bootstrapped and the node's `agent-not-ready` taint never cleared, blocking all
  scheduling. Image was `ghcr.io/yifeng2019uwb/ebpf-edr:latest`. Re-add (health-ai
  `deploy.sh` or `scripts/deploy-ebpf-k8s.sh`) ONLY after the trusted-app whitelist fix +
  image rebuild, else it re-kills cilium on the next Hubble cert rotation.
- **cilium namespace resolution.** kube-system pods can resolve to `service=k8s-pod-<hash>`,
  empty namespace (resolver needs CNI that cilium itself provides — chicken/egg on a cold
  node), so `ignore_namespaces: [kube-system]` doesn't catch them. Blocks reliably trusting
  cilium; see Active design "out of scope" note. Also an instance of the write-once cache bug
  below.
- **K8s resolver caches the `k8s-pod-<hash>` fallback permanently — SHOULD FIX.** Root cause of
  the empty pod/namespace columns (and a chunk of the false positives). The resolution `cache`
  (mntNsID → result) is written **once**, on a namespace's first sighting, and never reconciled.
  If a container's first traced event beats the 5s crictl refresh (`k8sRefreshInterval`), the
  container ID resolves but `containerIDMap` misses → the `k8s-pod-<hash>` fallback (empty
  pod/namespace) is cached as `StateResolved` (`k8s_resolver.go` ~274). `refreshCrictlCache`
  only rebuilds `containerIDMap` (~152), never the `cache`; the hot path returns any cache hit
  unconditionally (~126); the K8s cache has no eviction — so the fallback sticks for the
  container's **entire life**, even though the correct pod/namespace lands in `containerIDMap`
  ~5s later. The 60s `StatePending` retry doesn't help: resolution "succeeds" fast with the
  fallback, so retries are cache hits, not re-resolves. Startup/bootstrap traffic (localstack →
  AWS, cilium bootstrap) reliably loses this race. **Cost beyond cosmetics:** the stale
  `k8s-pod-<hash>` service means `service_in` whitelist exceptions never match (e.g. T1041's
  inventory-service → CoinGecko), so legit traffic keeps alerting for the container's whole
  lifetime — and the trusted-app whitelist design depends on `service_in`, so this blocks it.
  **Fix = update-in-place, NOT eviction** (the container is alive — don't remove it): the
  fallback entry already stores `Meta.Container` (~281), so on each refresh, patch cache entries
  still on the fallback by re-looking-up `containerIDMap[container]`. No removal, no re-resolve,
  no `/proc` re-read, no re-running the race. (Eviction is a separate concern, only for *dead*
  containers.) Not an eBPF/execve fix — pod name + K8s namespace are CRI-label data, absent from
  kernel data, so no sensor change can supply them.

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
