# File-Open Event Design — Threat Model Analysis

**Based on:** MITRE-COVERAGE.md file rules (T1552.004, T1003.008, T1552.001, T1082, T1053.003,
T1070.003, T1611) + DETECTION-RULES-AND-POLICY.md §2.2.
**Method:** same as EXECVE-EVENT-DESIGN.md — a field earns its place only if a rule consumes it,
or it catches something the sensor structurally cannot. Companion doc: EXECVE-EVENT-DESIGN.md.

> **Active sensor:** the file sensor is **`lsm-file.bpf.c`** (`lsm.s/file_open`).
> `opensnoop.bpf.c` is superseded and dead — retire it.

---

## Hooks compared — and the decision

The file rules need three things, and no single hook provides all of them — so the decision is
which hooks to combine:
- the **path** (every rule),
- **read vs write** (T1053 cron, T1070 history — both are writes),
- **denied attempts** on existing sensitive files (T1003/T1552 as non-root).

| Hook                  | Syscalls                                             | Path | Read/write | Denials (EACCES/EPERM) | Cost |
|-----------------------|------------------------------------------------------|------|---|---|---|
| **`lsm.s/file_open`** | all — open/openat/openat2/open_by_handle_at/io_uring | **canonical** (`bpf_d_path`) | `file->f_mode`          | ❌ fires after the DAC check | 1 probe, no map |
| `sys_enter/exit_openat`| openat only | raw user string | openat flags | ✅ | 2-probe + map |
| **`do_sys_openat2`** kprobe+kretprobe | open/openat/openat2 | raw user string | flags | ✅ | state map; internal fn (ABI risk) |

**Why the LSM hook can't see denials:** it fires inside `do_dentry_open()`, *after* the DAC
check. A DAC `-EACCES` returns from `inode_permission()` before any LSM hook runs, so no LSM hook
(`file_open`, `file_permission`, `inode_permission`) ever sees a denied open. Denials are only
observable below the DAC gate — at the syscall return or a VFS-function kretprobe.

**Decision — two hooks, split by outcome so they never overlap:**
- **`lsm.s/file_open` emits SUCCESSFUL opens.** Every syscall, canonical path, read/write via
  `f_mode`, one probe, no map. (Fires only on a permitted open, so ENOENT never reaches it.) A
  successful `open_by_handle_at` escape arrives here too, with its resolved target path.
- **`do_sys_openat2` emits DENIED opens only.** It *sees* every outcome (success, EACCES, EPERM,
  ENOENT), but we *emit* just `EACCES`/`EPERM`, because:
  - successes are already covered by the LSM hook (with a better canonical path) — emitting them
    here too would double-count;
  - `ENOENT` is probing noise — the file doesn't exist, so there's nothing to detect.

  So this hook fills the one gap the LSM hook structurally can't: a **denied attempt on a file
  that exists** (a non-root process denied read of a root-only file). Matters mainly for non-root
  containers (root isn't DAC-denied). Caveat: internal kernel function → a kernel change could
  force a rebuild.

---

## Reference

File-sensor references, if needed: Falco's `openat.bpf.c` (and open/openat2/open_by_handle_at
siblings) under `falco/libs/driver/modern_bpf/programs/tail_called/events/syscall_dispatched_events/`;
Tetragon's LSM file monitoring in `tetragon/bpf/process/bpf_generic_lsm_core.c`.

---

## Field decision — read/write for T1053/T1070 (via `f_mode`, not syscall flags)

Today lsm-file captures path + context, no read/write distinction. Two rules are semantically
about **writes** but fire on any open — false positives on benign reads:

| Rule                       | Threat is a…                  | Benefit of a write bit |
|----------------------------|-------------------------------|------------------------------------------|
| **T1053.003 cron**         | write (install persistence)   | skip the cron daemon *reading* its config |
| **T1070.003 clear history** | write/truncate (erase tracks) | skip a shell *reading* history |

In the LSM hook this is cleaner than the syscall-flags route: read `file->f_mode` and test
`FMODE_WRITE` (vs `FMODE_READ`) directly off `struct file` — no need to parse openat's flags
argument. So the write-detection refinement is available here too, if the T1053/T1070 FPs matter.

- **`f_mode` write bit: optional** — consumed by T1053 + T1070 only.
- **`mode` (create perms): out** — no rule reads it.

The other read-only rules (T1003.008, T1552.004, T1552.001, T1082, T1611) don't need it — any
access to those paths is the signal.

---

## Event fields — scope-derived

The `file_event` struct lives in `opensnoop.h` (misnamed — it's lsm-file's event; rename to
`file_event.h`). Every file rule's consumer is already present; the only optional addition is
`f_mode`, and it reuses the existing `pad` slot — no size change.

```c
struct file_event {
    __u64 mnt_ns_id;                  // container-context gating
    int   pid;                        // response, dedup key
    int   ppid;                       // ancestry walk
    __u32 uid;                        // alert context
    __u32 f_mode;                     // OPTIONAL — was `pad`; test FMODE_WRITE for T1053/T1070
    char  comm[TASK_COMM_LEN];        // reader-gating (T1082), reporting            (128)
    char  filename[MAX_FILENAME_LEN]; // full abs path (bpf_d_path); every path rule (256)
};
// total 408 B (unchanged — f_mode takes the existing pad slot)
```

- **cgroup:** same as the execve sensor (leaf name → faster container resolution, drops the
  resolver's procfs read). Decide both sensors together — see EXECVE-EVENT-DESIGN.md.
- **dev/ino, overlay-layer:** no current consumer (hardlink-identity; the disabled T1611 overlay
  rule) — out until a rule needs them.

---

## False alerts — the whitelist gap, not missing fields

More struct fields barely help the file false-positives; they split into two kinds.

**Identity FPs — no field can fix.** A trusted service legitimately touching a sensitive-looking
resource — reading its *own* TLS key/cert (T1552.004), its *own* secrets (T1552.001), or
world-readable/host files at startup (T1082, T1611) — trips the credential/discovery rules. The
worst case carries `kill_process`, so it **kills legitimate workloads** (observed). No eBPF field
distinguishes "a service reading its own cert" from "an attacker reading a stolen key" — only
**resolved service identity + a scoped exception** does. Fix = the trusted-app whitelist (HANDOFF
Active design), not the sensor.

**Read-vs-write FPs — the `f_mode` bit fixes them.** The write-oriented rules — cron persistence
(T1053), history clearing (T1070) — fire on benign *reads* of the same files (a daemon reading
its config, a shell loading history). The `f_mode` write bit scopes them to writes. Latent: only
fires if those readers run in-container.

**Conclusion:** the file-FP fix is the trusted-app whitelist (service-scoped exceptions), not
sensor changes. `f_mode` is a small, separate refinement. No other field reduces an observed FP.

---

## Open items

- **`open_by_handle_at` denied attempt → do nothing.** It fails at the `CAP_DAC_READ_SEARCH`
  check before any file exists — no path, only an opaque handle, and the escape was already
  blocked. Nothing actionable. (Successful handle escapes are already caught by lsm/file_open
  with the resolved path.)

**Decisions still open:**
1. **`f_mode` write bit** — add (tighten T1053/T1070 to writes), or skip?
2. **cgroup capture** — decide alongside the execve sensor.
3. **do_sys_openat2 denials** — build now, or accept lsm-file-successes-only until non-root
   containers are in the deployment (the gap is minor when workloads run as root)?
