// Originally downloaded from https://github.com/eunomia-bpf/bpf-developer-tutorial (lesson 04 opensnoop)
// Rewritten from scratch:
//   - replaced bpf_printk() stub with full ring buffer event pipeline
//   - added struct file_event with pid, ppid, uid, mnt_ns_id, comm, filename
//   - added mnt_ns_id via BPF_CORE_READ for container correlation
//   - changed from perf buffer to ring buffer (BPF_MAP_TYPE_RINGBUF) — lower overhead
//   - filtered to process-level opens only (tgid == tid)
//   - split into enter+exit probes: only emit on successful open (ret >= 0)
//     eliminates false positives from config file probing (curl ~/.curlrc, etc.)
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "opensnoop.h"

// errno constants — not available via errno.h in BPF programs
// Values are stable Linux ABI (uapi/asm-generic/errno-base.h)
#define EPERM   1   // operation not permitted
#define ENOENT  2   // no such file or directory
#define EACCES  13  // permission denied

char LICENSE[] SEC("license") = "GPL";

// Ring buffer — emits successfully opened file events to Go userspace
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// ── Two-probe pattern ────────────────────────────────────────────────────────
// Problem with a single sys_enter hook: we emit an event for every openat()
// call, including probes for files that do not exist (e.g. curl checks
// ~/.curlrc on every invocation — gets ENOENT, never reads the file).
// This generates HIGH alerts for harmless config-file probing.
//
// Solution: split into enter + exit.
//   sys_enter_openat — capture filename + process context, store in hash map
//   sys_exit_openat  — read return value; emit ONLY if ret >= 0 (file opened)
//
// ret >= 0 = valid file descriptor: the file was actually opened.
// ret <  0 = errno (ENOENT, EACCES, …): syscall failed, no file was read.
//
// pending_opens is a per-tid scratch space between the two probes.
// Keyed by tid (not tgid) so concurrent threads don't overwrite each other.
// ────────────────────────────────────────────────────────────────────────────

// BPF-internal only — NOT shared with Go userspace.
// Stores event data between sys_enter and sys_exit.
struct pending_open {
	__u64 mnt_ns_id;
	int   pid;
	int   ppid;
	__u32 uid;
	__u32 _pad;                        // explicit pad — keeps struct size 8-byte aligned
	char  comm[TASK_COMM_LEN];
	char  filename[MAX_FILENAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);        // max concurrent in-flight opens
	__type(key,   __u32);             // tid
	__type(value, struct pending_open);
} pending_opens SEC(".maps");

// sys_enter_openat — capture filename and process context.
// Does NOT emit yet — we don't know if the open will succeed.
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_enter(struct trace_event_raw_sys_enter *ctx)
{
	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	u32 tid  = (u32)id;

	// ignore thread-level calls — only track process-level opens
	if (tgid != tid)
		return 0;

	struct pending_open po = {};
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	po.mnt_ns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	po.pid       = tgid;
	po.ppid      = BPF_CORE_READ(task, real_parent, tgid);
	po.uid       = (u32)bpf_get_current_uid_gid();
	po._pad      = 0;

	bpf_get_current_comm(&po.comm, sizeof(po.comm));

	// args[1] is the filename pointer passed to openat syscall
	// must read from user space here — pointer is valid at entry time
	char *filename_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
	bpf_probe_read_user_str(po.filename, sizeof(po.filename), filename_ptr);

	bpf_map_update_elem(&pending_opens, &tid, &po, BPF_ANY);
	return 0;
}

// sys_exit_openat — emit on success OR on permission-denied attempts.
//
// ret >= 0          file opened successfully                      → emit
// ret == -EACCES    file EXISTS, OS blocked access (uid mismatch) → emit
// ret == -EPERM     operation not permitted on existing file      → emit
// ret == -ENOENT    file does not exist — probing only            → drop
// other negative    benign errors (ENOTDIR, ELOOP, …)            → drop
//
// WHY: "cat /etc/shadow" as uid=1000 returns -EACCES.
// Dropping all negative returns silently misses this attack.
// The attempt against an existing sensitive file IS the signal,
// whether the OS allowed it or not.
SEC("tracepoint/syscalls/sys_exit_openat")
int handle_exit(struct trace_event_raw_sys_exit *ctx)
{
	u64 id  = bpf_get_current_pid_tgid();
	u32 tid = (u32)id;

	struct pending_open *po = bpf_map_lookup_elem(&pending_opens, &tid);
	if (!po)
		return 0;

	// always delete — whether we emit or not, entry is done
	bpf_map_delete_elem(&pending_opens, &tid);

	// drop only if file does not exist — harmless config file probing
	// keep if open succeeded OR if OS denied access to an existing file
	if (ctx->ret < 0 && ctx->ret != -EACCES && ctx->ret != -EPERM)
		return 0;

	struct file_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->mnt_ns_id = po->mnt_ns_id;
	e->pid       = po->pid;
	e->ppid      = po->ppid;
	e->uid       = po->uid;
	e->pad       = 0;

	__builtin_memcpy(e->comm,     po->comm,     sizeof(e->comm));
	__builtin_memcpy(e->filename, po->filename, sizeof(e->filename));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
