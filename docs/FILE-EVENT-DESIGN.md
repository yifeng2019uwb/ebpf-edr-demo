# File Sensor — Design

**Sensor:** `kernel/lsm-file.bpf.c`, two hooks split by outcome:
- **`lsm.s/file_open`** — emits **successful** opens (every syscall, canonical path, read/write).
- **`do_sys_openat2` kprobe** — emits **denied** opens only (`EACCES`/`EPERM`).

**References:** Falco's `openat` / `open_by_handle_at` sensors and Tetragon's
`bpf/process/bpf_generic_lsm_core.c`. (`opensnoop.bpf.c` was the old sensor — retired.)

This doc is the *rationale*. The authoritative field list and layout live in code —
`kernel/event.h` (`struct file_event`) and `internal/processor` (`FileEvent`).

## Why two hooks

The file rules need three things and no single hook provides all of them:

- **canonical path** (every rule) — the LSM hook gives it via `bpf_d_path` (needs the sleepable
  `lsm.s` variant); a syscall tracepoint only sees the raw user string.
- **read vs write** (T1053 cron, T1070 history are writes) — `file->f_mode` off the LSM hook.
- **denied attempts on files that exist** (T1003/T1552 as non-root) — the LSM hook **can't** see
  these: it fires inside `do_dentry_open()`, *after* the DAC check, so a DAC `-EACCES` returns
  before any LSM hook runs. Only a syscall-return or VFS kretprobe sees denials.

So `do_sys_openat2` fills the one gap the LSM hook structurally can't. It emits **only** denials:
successes are already covered by the LSM hook (with a better path), and `ENOENT` is probing noise.
Caveat: it's an internal kernel function, so a kernel change could force a rebuild.

## What it captures, and why

| Field | Serves |
|---|---|
| `filename` (canonical path) | every file rule |
| `comm` | T1082 reader-gate (only a recon/shell tool reading `/etc/passwd` is the signal); reporting |
| `f_mode` (READ/WRITE bit) | scopes T1053 / T1070 to writes — see gap below |
| `ret` | denial path: a non-root process denied read of a root-only file |
| `mnt_ns_id` | container-context gating |
| `cgroup` (leaf) | resolver → service identity, captured in-kernel to drop a `/proc` read |
| `pid` | response target; file-dedup key |
| `ppid` | ancestry walk |
| `uid` | alert context |
| `event_time` | ordering/deltas for the future behavior-analysis service |

## Open gaps (tracked in `rules/*.yaml`, not here)

- **`f_mode` is captured but not all write-oriented rules require it yet.** T1053 (cron) and T1070
  (history) still fire on benign reads; requiring `FMODE_WRITE` is a Go-only fix. T1070 also wants
  the `O_TRUNC` flag (`> ~/.bash_history`), a small sensor addition on the same hook.
- **Identity false positives are not a field problem.** A trusted service reading its *own*
  cert/key (T1552) or world-readable files at startup (T1082) trips the rules — worst case with
  `kill_process`. No eBPF field separates "reading its own key" from "reading a stolen key"; only
  resolved service identity + a scoped exception does. Fix = the trusted-app whitelist, not the
  sensor.

## Deliberately excluded

- **`mode`** (create perms) — no rule reads it.
- **dev / ino / overlay-layer** — hardlink identity and the disabled T1611 overlay rule; out until
  a rule needs them.
