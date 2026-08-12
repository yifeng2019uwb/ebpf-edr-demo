# Project Handoff — Archived

**Last Updated:** 2026-08-12

**Status: closed.** The detection + response engine works and was validated on both the Docker VM
(`validate.sh`) and DigitalOcean Kubernetes (`validate-do-k8s.sh`). Development stopped here
deliberately — not because the remaining work was uninteresting, but because the DigitalOcean
credit expires 2026-08-16 and with it the only real test environment. A runtime security agent
cannot be changed responsibly without somewhere to run it, so the code was frozen at a working
state rather than accumulating unvalidated changes.

Effort moved upstream instead: contributing to `cilium/ebpf` (the library this project already
depends on) and reading Tetragon, where the same problems are solved at production scale.

**This file is the record of what works, what does not, and why.** Known gaps below are stated
plainly rather than hidden — several are things production EDRs solve differently, and the
comparison is the most useful part of the project.

---

## Doc map

| Need | Source of truth |
|---|---|
| System architecture / pipeline | `docs/CURRENT_DESIGN.md` |
| Detection rules + policy layers (per-rule) | `docs/DETECTION-RULES-AND-POLICY.md` |
| Parent verification / ancestry cache | `docs/DESIGN-PROCESS-ANCESTRY-CACHE.md` |
| MITRE technique table + responses | `docs/MITRE-COVERAGE.md` |
| Throughput / perf state | `docs/PERFORMANCE.md` |
| Setup / build / deploy / validate / sinks | `docs/SETUP.md`, `docs/DEPLOYMENT.md` |
| Behavior module (baseline/deviation scoring) — DRAFT, never built | `docs/BEHAVIOR-MODULE-DESIGN.md` |

**Ground truth (YAML rules + Go engine):** matching, severity, order, and `response:` are declared
in `rules/process.yaml` / `file.yaml` / `network.yaml` (per-sensor detections); `rules/common.yaml`
holds shared lists + Layer 1/2 config. `pkg/detector/yaml_detector.go` is the engine (plus Go-only
pipeline logic: ppid==1 skip, ancestry walk, telemetry); `pkg/detector/response.go` executes
responses. Resolver is `pkg/workload/`; sink/env config is `internal/config/config.go`.

---

## What works

- **Three kernel sensors** — `execsnoop.bpf.c` (`tracepoint/syscalls/sys_enter_execve`),
  `lsm-file.bpf.c` (`lsm.s/file_open`, plus `do_sys_openat2` k/kretprobes for the denial path),
  `lsm-connect.bpf.c` (`lsm/socket_connect`).
- **Declarative detection.** Rules, severities, exceptions, and responses live in YAML; tuning a
  rule needs no Go or kernel change. The loader fail-fasts on unknown severities, out-of-order
  detections, unknown list references, and invalid responses.
- **Runtime-agnostic workload resolution.** One `Engine` (`pkg/workload/resolver_engine.go`)
  resolves Docker and CRI containers by mount namespace, with cache eviction and a `/proc` prewarm
  that sidesteps the cgroup-migration race.
- **Response actions.** `kill_process` works. `block_ip` is alert-only (see below).
- **Alert sinks.** File (always), Redis pub/sub (live dashboard, drops LOW), Postgres/Supabase
  (persistence).

## Known limitations

These are real and unfixed. Each notes how a production EDR handles it.

- **PID-reuse race in `kill_process`.** The responder calls `syscall.Kill(a.Pid, SIGKILL)` on a pid
  read from an event that may be up to 60s old (see the pending buffer below). Nothing verifies the
  pid still refers to the process that generated the event, so on a churning node the signal can
  land on an unrelated process. *Tetragon keys process identity on an `ExecId` derived from pid +
  start time, so a recycled pid never matches.* The cheap fix here would be to refuse to act on any
  alert older than a few hundred ms.
- **Unbounded pending buffer.** `pendingBuf` (`cmd/edr-monitor/main.go`) holds events whose
  namespace has not resolved yet, for up to 60s, with no size cap; each entry pins its raw event
  allocation. A burst or a K8s cold start can accumulate a large number of them. The retry worker
  also holds `pendingMu` across an entire tick while calling `syscall.Kill(pid, 0)` per entry, so a
  large buffer stalls the enricher and kernel events get dropped.
- **Alert dispatch is synchronous and untimed.** One goroutine writes to every sink in series with
  `context.Background()` — no timeout — and the Supabase sink does one un-batched `INSERT` per
  alert. A slow or hung database blocks the whole alert path until `alertCh` fills and alerts are
  dropped. Sinks should each own a goroutine and a bounded queue.
- **Detection is per-event, with no state.** Rules match a single event; there is no correlation,
  sequencing, or behavioral baseline. `docs/BEHAVIOR-MODULE-DESIGN.md` sketches one; it was never
  built.
- **`block_ip` kernel side is not compiled.** The `blocked_ips` LPMTrie in `kernel/lsm-connect.bpf.c`
  is commented out, so the responder logs and skips — network rules are alert-only. Activation
  steps are in `pkg/detector/response.go`.
- **GKE service CIDR is not covered.** `rules/common.yaml` `private_ranges` lists RFC 1918,
  loopback, and link-local. GKE ClusterIPs are `34.118.x.x`, outside all of them, so
  ClusterIP-to-ClusterIP traffic on GKE fires `T1041` as external exfiltration. There used to be
  Go code auto-detecting this CIDR from GCP metadata, but it wrote to a variable nothing read; it
  was deleted 2026-08-12. The fix is one entry in `private_ranges`, not Go code. DOKS is unaffected
  (its service CIDR is inside RFC 1918).
- **Trusted-application whitelisting is unsolved.** `customer_applications` matches on `comm`, not
  on the application, so an app whose `comm` is `python` cannot be whitelisted meaningfully. This
  is not academic: it caused the agent to SIGKILL cilium on DOKS (T1552_004 on its Hubble
  `server.key`), and the DaemonSet was pulled on 2026-07-10 as a result. A narrow fix landed for
  one case (`T1552_004` excepts `service_in: own_tls_cert_services`), but the general problem — a
  per-service action profile rather than a global name list — was never designed. **Do not
  redeploy to a cilium cluster without addressing this.**
- **kube-system pods do not resolve on a cold node.** They come back as `service=k8s-pod-<hash>`
  with an empty namespace, because resolution needs a CNI that cilium itself provides — so
  `ignore_namespaces: [kube-system]` does not catch them.
- **Short-id fallback is sticky.** If `RuntimeClient.Enrich` fails once, the namespace caches a
  `container-<shortid>` service name and never retries.
- **Event structs are hand-mirrored.** `internal/processor` duplicates `kernel/event.h` by hand and
  nothing enforces that they match. bpf2go already emits a BTF-derived `processExecEvent`
  (`pkg/bpf/process_x86_bpfel.go`) that cannot drift — it is simply unused, because importing it
  would make `internal/processor` and the detector linux-only and untestable off a BPF host. A
  compile-time size assertion in `pkg/bpf` would close the gap for `exec_event` at zero runtime
  cost. *Tetragon generates its event types from BTF rather than keeping a parallel copy.*
- **Unexplained OOMKill (2026-07-14, exit 137).** One EDR pod ran out of memory ~9h15m into a load
  test. The most likely cause — a file-dedup map that never evicted — was fixed on 2026-08-12
  (`internal/dedup`), but this was never re-run against load, so the fix is unconfirmed against the
  original symptom.
- **The network rules and the ancestry walk have no unit tests.** `cmd/edr-monitor` has none at
  all — it cannot be tested off a BPF host, which is part of why the dedup cache was extracted to
  `internal/dedup`. Run `make test` for the current state rather than trusting any figure here.
- **`validate.sh` T1611 overlay test is disabled**, pending the host-reads-container-overlay rule
  and its allowlist design.

## Performance

Load testing was paused, not completed (`docs/PERFORMANCE.md`). The order-processor test workload
capped at ~300 req/s — LocalStack's own routing was the bottleneck, and swapping to
`amazon/dynamodb-local` gave ~4x but still fell short of the 50k/5k target. The eBPF agent itself
handled the offered load without crashes or spurious `kill_process` incidents. The agent's own
ceiling was never actually measured, so no throughput claim should be made from this.

---

## Close-out changes (2026-08-12)

Only changes verifiable without a live environment were made — compiler, `go vet`, and unit tests.
Anything whose correctness depends on runtime behavior under load was documented above instead.

- **File-dedup cache extracted to `internal/dedup` and given a sweep.** The old sharded maps in
  `main.go` were keyed by `{pid, filename}` and never evicted; because pids keep changing, nothing
  was ever overwritten and the maps grew for the process lifetime. Now swept on a 10s ticker, with
  unit tests covering the window, sharding, growth bound, and concurrent access under `-race`.
- **Shutdown no longer panics.** `close(rawCh)` used to race the ring-buffer readers, which are
  never signalled — sending on a closed channel panics, so SIGTERM on a busy node produced a stack
  trace instead of a clean exit. Now the loader closes first (readers exit on `os.ErrClosed`),
  shutdown waits on their `WaitGroup`, and only then closes `rawCh`. `enrichedCh`/`alertCh` are
  deliberately left open — their producers are still draining, and closing them would reintroduce
  the same race. The drain is best-effort: in-flight events past the window are lost, not flushed.
- **Dead code removed.** `network_init.go` (whole file, see the GKE note above), the `-runtime`
  flag's orphaned constants, `extractPPidFromStatus`, `NewYAMLDetector`, a `lastLogged` map that
  was written but never read, and the ancestry cache's write-only hit/miss counters.
- **Logging trimmed.** All 18 `DEBUG:` lines are gone — per-event traces, resolve/detect timing,
  and the 10s event counters. Error and degradation paths kept their logs.
- **Makefile.** `make test` now runs with `-race` and includes `pkg/rules` + `pkg/workload`;
  the dead `--runtime=docker` argument was removed from the run targets.

**Not done, deliberately:** the PID-reuse guard, the pending-buffer cap, and async alert dispatch.
All three change runtime behavior under load, which is exactly what can no longer be validated.

---

## Notes for anyone reading the code

**Dedup key.** `internal/dedup` keys on `{pid, filename}` — deliberately no `comm`. The sensor's
pid is the tgid (same for every thread), but its `comm` is the THREAD name
(`bpf_get_current_comm`), so including it made differently-named threads of one process produce
distinct keys and double-fire alerts ~80ms apart. `runc:[…]` events skip dedup entirely: runc reads
`/etc/passwd` + `/etc/group` during docker-exec setup and then execs the target under the SAME pid,
so recording them would dedup-shadow the target's own first read (T1082 would miss
`cat /etc/passwd`).

**Severity downgrade for unresolved services.** `service_unresolved_severity` in the process rules
emits a reduced severity when a confirmed container has no real service name yet. This was verified
at unit level only (`Detect()` with a mocked unresolved service), never against a running pipeline.

**Build constraint.** `cmd/edr-monitor` embeds the generated `pkg/bpf/*.o` objects, which are
gitignored. From a fresh clone it cannot be built or vetted until `make generate` runs on a Linux
host with clang. `make vet` excludes it for this reason.
