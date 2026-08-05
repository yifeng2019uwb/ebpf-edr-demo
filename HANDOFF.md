# Project Handoff — Current Status

**Last Updated:** 2026-08-05

**Status:** Detection + response engine working on both Docker VM (`validate.sh`) and DO K8s
(`validate-do-k8s.sh`). Resolver rewritten to a single runtime-agnostic `Engine`
(`pkg/workload/resolver_engine.go`); rules recently redesigned against Falco/Tetragon with 2
new exec fields (`has_tty`, `args`). Trusted-app whitelist (service + scoped actions) remains
the main **not-yet-built** feature — see **Active design** below.

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

## Resolver engine rewrite — multi-runtime Engine (2026-08-03) — DONE, validated

Replaced `DockerResolver`/`K8sResolver` (one per `--runtime` flag) with a single
runtime-agnostic `Engine` (`pkg/workload/resolver_engine.go`), dispatching to pluggable
`RuntimeClient`s (`DockerClient`, `CriClient`) keyed by cgroup leaf prefix. Root-caused and
fixed: containers permanently stuck at `Unknown` (a cgroup-migration race during
`docker exec`/health checks — fixed via `prewarmFromProc()` at startup), no cache eviction for
destroyed containers (fixed via `EvictStale()`), and a DOKS-specific bug where `enrich()` never
queried a runtime client at all on the cgroupfs driver (`validate-do-k8s.sh` went 2/11 → 11/11
after the fix — cgroupfs leaves carry no runtime prefix, so `enrich()` now always tries
`RuntimeDocker` then `RuntimeK8s` instead of only trying already-connected clients).

**Still open:**
- **Live-path version of the cgroup-migration race.** Prewarm only covers containers already
  running at agent startup; a container that starts *after* the agent can still hit the same
  race on its first event. Fix: retry via a live `/proc/<pid>/cgroup` read when the
  kernel-captured leaf doesn't parse as a container (not just when it's empty).
- **Short-id fallback can still stick permanently** if `RuntimeClient.Enrich` fails once
  (docker/crictl briefly unreachable) — same shape as the old K8s `k8s-pod-<hash>` bug (see
  Deferred issues below). Fix = update-in-place on retry, not eviction. Blocks the trusted-app
  whitelist below, since that depends on `service_in` matching a real (not short-id) name.
- Temporary `DEBUG:` log lines still remain in `resolver_engine.go`/`cri_client.go`/`main.go`;
  decide whether to remove, downgrade, or keep.

---

## Falco/Tetragon-informed rule redesign — new exec fields (2026-08-05) — DONE, validated

Compared all 14 detection rules against Falco's/Tetragon's actual conditions for the same
MITRE techniques, scoped to fields addable within the existing 3 eBPF hooks (no new probes).
Added `has_tty` and `args` (argv[1:], fixed 32-byte NUL-padded slots, `MAX_ARGS=4`) to
`exec_event` (`execsnoop.bpf.c`) — grew the struct past the 512-byte BPF stack limit, moved to
a per-CPU `BPF_MAP_TYPE_PERCPU_ARRAY` scratch map. `cwd` was considered and explicitly not
added: needs `bpf_d_path()`, which requires a sleepable program (this hook isn't one) —
documented in `event.h`/`T1036`'s rule comment as a bigger change than adding a field.

Used the new fields to tighten `T1059` (`tty_required: true` — a script's non-interactive
`sh -c` no longer fires), `T1105` (nc/ncat now gated on `args_contains_in: reverse_shell_flags`;
`wget` kept separate/ungated since its own `-c` would collide with the same flag list), and
`T1036` (added a `shell + args_contains_in: suspicious_exec_paths` entry closing the
`sh -c /dev/shm/x` bypass — the `cd /dev/shm && ./x` relative-exec bypass is still open, same
`cwd` gap as above). New matcher primitives: `tty_required`, `args_contains_in`
(`pkg/rules/loader.go`, `pkg/detector/yaml_detector.go`).

**Documented-but-not-built gaps** (comments in `rules/*.yaml`, no code):
- `T1611`/`T1053.003` should require `Fmode & FMODE_WRITE` (already captured, just needs DSL
  wiring like `tty_required` above).
- `T1070.003` needs `O_TRUNC` (one more bit, same file hook) for `> file`/`cat /dev/null >`,
  and separately `unlink`/`rename` (a new probe, out of scope) for `rm`/`mv`.
- `T1003.008`'s credential path list is missing `/etc/sudoers`/`/etc/pam.conf`/
  `/etc/security/pwquality.conf` — pure YAML, no code.
- Network hook could add `l4proto` (tcp/udp) for a future behavioral project; no rule needs it.

Validated via `validate.sh` (Docker VM) after fixing `validate.sh`/`validate-do-k8s.sh`'s
shell-spawn tests to use `-t`/pseudo-TTY (required now that `tty_required` is a real gate).

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
  (T1041 already uses it). This is the mechanism for "scoped to known actions".
- C — path exception (add `/var/lib/localstack/` to an exclude list, like `pem_exclude_paths`):
  narrowest, but whack-a-mole per app and ignores the network alerts.

Direction = **B as the mechanism, expressed as a per-service action profile** (service +
its allowed actions/paths). Design the profile shape before coding — do NOT quick-patch.

**Option B's mechanism given a first, narrow use (2026-08-05) — not the full redesign.**
`service` is now populated into file-rule `matchInput` (previously only network did this).
Used for one scoped exception: `T1552_004_private_keys` excepts
`service_in: own_tls_cert_services`, stopping `kill_process` from SIGKILLing `localstack` over
its own `server.test.pem`/`.pem.key` (this was actively breaking Docker-VM deploys). Not the
general per-service action-profile system above — `process` `matchInput` still doesn't carry
`service` (T1059/T1105/T1036/T1613 have no `service_in` exceptions yet).

**Out of scope for this change (separate issue): cilium.** It resolved to
`service=k8s-pod-<hash>` with empty namespace (resolver can't identify kube-system pods before
CNI is up), so no service/name whitelist reliably catches it. Needs a namespace-resolution fix.

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
- **Short-id fallback caches permanently** — see **Resolver engine rewrite** "Still open" above.

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

---

## Possible direction: exception scaling (understood, not built — separate from the above)

**The problem this is a response to (found 2026-08-05, via the localstack `T1036_masquerading`
alert on `/bin/sh` + args containing `/tmp/...`).** A hand-maintained exception list keyed by
*service name* (`customer_applications`, `allowed_services`, `own_tls_cert_services`, ...) has
two failure modes that get worse as more environments/apps are onboarded: the list grows
without bound (whack-a-mole, one entry per app-specific quirk), and it's *wrong* the moment a
new image version changes its startup behavior — the stale exception either wrongly still
applies (blind spot) or wrongly stops applying (false positive returns), and either way nobody
finds out until an incident or a support ticket. Different environments/nodes genuinely run
different apps with different configs, and new images get deployed over time — a static,
name-keyed list can't track that.

**Why "let each deployment upload its own exception rules" is rejected, not just deferred.**
That's the classic "attacker turns off the alarm" problem: if a compromised (or malicious)
workload can add itself to an exception list, the EDR is blinded exactly where it matters most.
Not a time/cost tradeoff — a correctness one.

**A middle path worth understanding, distinct from the Behavioral & Anomaly Detection initiative
above:** key the exception profile by **container image digest**, not service name, and
**derive it from observed behavior during a bounded learning window** (e.g., the first few
minutes after a *new* digest is first seen) instead of anyone — customer or operator —
hand-writing it.
- A new image digest has no existing profile yet, so it falls back to strict detection by
  default (a safe failure mode) instead of silently over- or under-matching a stale, name-keyed
  entry.
- The profile is *recorded*, not *authored* — a compromised workload can't retroactively
  rewrite a baseline that was already captured from a prior clean run.
- Narrower than the Behavioral & Anomaly Detection initiative above: this isn't "learn what's
  statistically normal over months of alert history and score drift" — it's closer to "capture
  this one image's own entrypoint/init behavior once, then require repeat runs of the same
  image to match it." A bounded per-workload baseline, not general anomaly scoring.

**Why this stays understood-only, not planned:** this is real infrastructure — a learning-mode
state machine, per-digest storage, a "not yet profiled" safe-default state — meaningfully
bigger than a rule tweak. Solo-dev time/cost for this project doesn't currently support it.
No commitment is being made to build this; it's recorded here so the tradeoff and the rejected
alternatives (name-keyed lists, customer-authored rules) don't have to be re-derived later.
