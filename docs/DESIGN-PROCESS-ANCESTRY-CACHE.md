# Design: Process Ancestry Cache for Parent Verification

**Date:** 2026-07-06
**Status:** APPROVED DESIGN — implementation not started
**Supersedes:** the parent-verification sections of HANDOFF.md "Two-Stage Parent Process Verification" and the ephemeral-parent race discussion. Older docs in this folder describe abandoned iterations; this doc is the current source of truth for this feature.

---

## 1. Problem

Transient processes (curl, grep, sleep, tail, bash) spawned during docker deploy/destroy,
health checks, and SSH logins exit before the async resolver classifies them → `state=unknown`
→ CRITICAL T1611 false positives (100+/sec during deploys).

The fix requires verifying the process's *ancestry* (was it spawned by infrastructure?),
but the current implementation is broken in three inconsistent ways:

1. `isGloballyExcepted` (`parent_context: infrastructure`) checks **direct ppid only**
   against the static `safeInfraPIDs` snapshot. Misses anything shell-mediated, and misses
   sshd session workers (forked per-connection, never in the startup snapshot).
2. `checkProcessRules` Stage 2 reads `/proc/<ppid>/comm` **reactively at alert time** —
   racy (parent often already dead) — with a one-off grandparent hop only when parent is
   literally bash/sh/dash/zsh.
3. The YAML rule `T1611_escape_host_ns` excludes by the **alerting process's own name**
   (`proc.name not_in (...)`), which is the wrong signal entirely: safety is a property of
   *who spawned it*, not *what it's called* (the "attacker uses curl instead of wget" gap).

## 2. How Falco solves this (reference)

- Falco maintains a **live, in-memory process tree**, populated continuously from every
  fork/exec/exit since startup. `proc.pname` / `proc.aname[N]` at rule-eval time are pointer
  hops through data captured **when each process was born** — never a fresh /proc read,
  never racing process death.
- Its `container_entrypoint` macro checks the **parent's name** against a short fixed list
  (`runc, containerd-shim, systemd, crio, conmon, ...`) — never the child's name.
- When parent info is missing (`not proc.pname exists or ...`), Falco is **permissive**:
  the check passes. Missing ancestry is treated as noise, not risk, because container
  identity is independently confirmed by a stronger signal (live cgroup context).

## 3. Design

### 3.1 The cache

A live map in the detector, populated passively from the exec events we already receive:

```
pid (uint32) → { ppid uint32, execPath string, firstSeen time.Time }
```

- **Source:** every `ProcessEvent` flowing through the pipeline already carries
  `Pid`, `Ppid`, and `Comm`. No new instrumentation, no .bpf.c changes.
- **Key property:** `ProcessEvent.Comm` is the **full executable path**
  (e.g. `/usr/bin/curl`, 128 bytes — see `internal/processor/processor.go`). The cache
  therefore stores exec-time path data, enabling prefix validation (like Layer 1
  `trusted_prefixes`) on *parents* without any /proc read. This is an anti-spoofing
  property Falco's name-only `proc.pname` does not have.
- **Population point:** enricher goroutine in `cmd/edr-monitor/main.go` (it sees every
  raw process event before Layer 1 skip logic and detection), or the detector's
  `Detect()` entry. Decision at implementation time; enricher preferred so the cache
  also learns from events that Layer 1 skips (infrastructure children).

### 3.2 Eviction (answer to "how do we stop it growing?")

We do NOT need entries to live as long as their process. We only need a parent's entry
to exist when its **child's event arrives** — milliseconds to seconds after spawn.
Three mechanisms, combined:

1. **Replace-on-exec (free):** a reused or re-exec'd PID's next exec event overwrites
   the old entry automatically.
2. **TTL sweep:** background ticker (same pattern as the fileDedup cleanup in main.go)
   evicts entries older than ~10 min. Long-lived daemons falling out is fine — persistent
   infrastructure is covered by the static Layer 1 `safeInfraPIDs`; the cache only needs
   to cover the dynamic middle layer (session shells, deployment scripts, sshd workers).
3. **Hard size cap** (e.g. 65536 entries, ~100B each ≈ 6MB) as a safety valve against
   exec storms; evict oldest first.

### 3.3 PID reuse (accepted residual risk)

Scenario: containerd-shim (pid 1234) dies → kernel reuses 1234 → new process's child
looks up 1234 and sees the stale "containerd-shim" entry → wrong suppress.

- Storing extra name fields does NOT detect this: at lookup time the child event carries
  only `ppid`; there is nothing to compare a cached name against (the true parent may be
  legitimately dead — that's the case the cache exists for).
- Mitigations that DO bound it: replace-on-exec (a reusing process almost always execs,
  overwriting the entry before it can spawn children) + TTL (stale window ≤ minutes).
- The only definitive check (kernel `starttime` from `/proc/<pid>/stat`, unique per PID
  incarnation) requires a /proc read per exec at insert AND a live parent at lookup —
  defeats the purpose. Rejected.
- `firstSeen` is logged at DEBUG when a suppress decision uses an old entry, so test runs
  can spot anomalies.

### 3.4 Coverage gap: fork-without-exec (accepted, with fallback)

Our sensor hooks **execve only** (`kernel/execsnoop.bpf.c`); we never see bare forks.
A process that forks and never execs (pure subshell, some daemon workers) is invisible
to the cache. Covering it would require a fork/clone hook in .bpf.c — ruled out for now
(CLAUDE.md: avoid .bpf.c changes).

Fallback order on cache miss: read `/proc/<ppid>/exe` (full binary path) → if that also
fails, the parent is unresolvable → §3.6. We read `exe`, not `comm`: `comm` is a bare
15-char name, but `exe` gives the full path, so the same trusted-prefix anti-spoof check
(`isTrustedParentExec`) applies on the fallback path. Either read only succeeds while the
parent is still alive; a dead + uncached parent is unresolvable by design. The cache makes
the race *rare*; it does not pretend to eliminate it.

### 3.5 The single trusted-parent check (replaces all three implementations)

One function, used identically by `isGloballyExcepted` (`parent_context: infrastructure`)
and the T1611 `state=unknown` path:

```
isParentTrusted(ppid):
  1. ppid in safeInfraPIDs (static Layer 1 snapshot)          → trusted
  2. cache[ppid].execPath: base name in trusted_parent_names
     AND path has a trusted prefix                            → trusted
  3. if cache[ppid] is a shell (bash/sh/dash/zsh):
     one more hop → apply 1+2 to the grandparent              → trusted if it passes
  4. otherwise                                                → not trusted
```

**YAML is the source of the knowledge, Go is only the mechanism.** New list in
`rules/default.yaml`:

```yaml
# Trusted parent names — processes allowed to spawn transient utilities.
# Checked against the LIVE ancestry cache (exec-time data), with path-prefix validation.
- name: trusted_parent_names
  items: [containerd-shim, containerd-shim-runc-v2, dockerd, containerd, docker-proxy,
          runc, sshd, systemd, snap, snapd]
```

Shell names come from the existing `shell_processes` list. Path validation is
**env-agnostic**: rather than allowlisting per-distro system dirs (which differ across
Docker, DO/GKE/minikube K8s, bare-metal), `hasTrustedInfraPrefix` denylists only
attacker-writable locations (`suspicious_exec_paths`: `/tmp`, `/dev/shm`, `/var/tmp`,
`/run/user`). A real daemon lives somewhere normal on every runtime; a spoofed
`/tmp/dockerd` does not — same anti-spoof intent, zero per-env maintenance. K8s infra
names (`kubelet`, `kube-proxy`, `crio`, `conmon`) are in `trusted_parent_names`; the
walk itself is runtime-agnostic.

This also fixes the sshd-worker hole: a per-connection sshd worker execs (`sshd -R`...),
lands in the cache with its real path, and its children (session bash → motd scripts →
grep/find/awk) verify through the cache chain instead of failing the static-PID check.

### 3.6 Unresolvable parent → noise, not CRITICAL (Falco-aligned, data-validated)

When the parent is unresolvable (dead + not in cache + /proc gone), current behavior is
"secure fail" → CRITICAL alert. Field data shows these are overwhelmingly noise.

New behavior: route the event to the **existing LOW rule
`EDR_telemetry_unresolved_namespace`** instead of CRITICAL T1611, and emit a DEBUG log
with full context (comm, pid, ppid, state, which lookup steps failed). Nothing is
silently dropped:

- Every such event still reaches the alert log / Supabase at LOW → the validation
  dataset for test runs (docker deploy/destroy, SSH logins) comes for free.
- After test runs confirm the LOW stream is noise, decide: keep LOW telemetry, or drop.

Justification for permissiveness (mirrors Falco's reasoning): the event's own
`mnt_ns_id` was captured atomically in-kernel at exec time — that identity signal is
never racy. Ancestry is a *secondary* refinement, not the last line of defense.

## 4. Implementation phases (stop for review after each)

- **Phase 1 — cache only.** Add the cache + eviction + hit/miss DEBUG counters.
  No detection behavior changes. Verify: counters look sane during a docker deploy.
- **Phase 2 — unified check.** Add `trusted_parent_names` to YAML; implement
  `isParentTrusted()`; wire into `isGloballyExcepted` + T1611 path; delete the three
  divergent checks (static-only ppid check in isGloballyExcepted, reactive /proc Stage 2,
  bash-only grandparent hop). Verify: deploy/destroy run produces no CRITICAL T1611 for
  infra-descended tools; a manually spawned `bash -c curl` from a non-infra parent still alerts.
- **Phase 3 — noise downgrade.** Unresolvable-parent events → LOW telemetry + DEBUG.
  User runs docker deploy/destroy + SSH login tests, inspects LOW stream to confirm noise.

## 5. Deliberately deferred

- Falco-style `proc.pname` / `proc.aname[N]` grammar in YAML conditions. The cache
  provides the data for it; the expression evaluator is a separate project
  (see "use YAML rules, not hardcoded Go" direction). `parent_context` +
  `trusted_parent_names` covers the current need declaratively.
- fork/clone eBPF hook (would close §3.4 gap; requires .bpf.c change + Linux rebuild).
- `state=unknown` as an escape signal is fundamentally a resolver-timing artifact, not a
  security signal (Falco has no equivalent state; it derives container identity
  synchronously from the event's cgroup data). Long-term, T1611 should key on actual
  escape primitives (setns, release_agent writes, privileged mounts). Out of scope here.
