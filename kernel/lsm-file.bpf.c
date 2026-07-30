// lsm-file.bpf.c — file-open sensor. Two hooks, split by outcome (docs/FILE-EVENT-DESIGN.md):
//
//   lsm.s/file_open      — SUCCESSFUL opens. Every syscall (open/openat/openat2/
//                          io_uring), canonical path via bpf_d_path, read/write via
//                          f_mode. One probe, no map. ret = 0.
//   do_sys_openat2 k(ret)probe — DENIED opens only (EACCES/EPERM). The LSM hook fires
//                          after the DAC check, so it structurally cannot see a denial;
//                          this pair fills that one gap. Successes and ENOENT are dropped
//                          here (successes are the LSM hook's job with a better path;
//                          ENOENT is probing noise). ret < 0.
//
// Both hooks emit struct file_event to the same ring buffer; Go distinguishes
// success from denial by the ret field.
//
// WHY lsm.s/file_open instead of tracepoint/sys_enter_openat:
//   openat tracepoint only fires for SYS_openat (syscall 257). Alpine busybox
//   (sh, cat) calls SYS_open (syscall 2) directly. lsm/file_open runs inside
//   do_dentry_open() for every file open regardless of syscall.
//
// WHY lsm.s (sleepable): bpf_d_path() resolves the full absolute path and requires
//   a sleepable program. bpf_lsm_file_open is in the sleepable LSM hook set (5.11+).
//
// CAVEAT: do_sys_openat2 is an internal kernel function — a kernel change could
//   rename/inline it and force a rebuild. Accepted per the design.


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "event.h"

char LICENSE[] SEC("license") = "GPL";

// 256 KB ring buffer — same size as lsm-connect.bpf.c.
// Must be a power of 2 (kernel requirement for BPF_MAP_TYPE_RINGBUF).
#define RINGBUF_SIZE (256 * 1024)

// errno values for the denial filter (vmlinux.h does not provide these macros).
#define EPERM  1
#define EACCES 13

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} rb SEC(".maps");

// fill_common populates the process-context fields shared by both hooks.
static __always_inline void fill_common(struct file_event *e, struct task_struct *task)
{
	u64 id = bpf_get_current_pid_tgid();

	e->mnt_ns_id  = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	e->event_time = bpf_ktime_get_ns();
	e->pid       = id >> 32;
	e->ppid      = BPF_CORE_READ(task, real_parent, tgid);
	e->uid       = (u32)bpf_get_current_uid_gid();
	e->pad       = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// leaf cgroup name (v2 unified hierarchy) — replaces the resolver's /proc read.
	// Init first: bpf_ringbuf_reserve does not zero the buffer, so a failed read
	// would otherwise leave garbage (exec_event gets this for free via `= {0}`).
	e->cgroup[0] = '\0';
	const char *cgroup_name = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, name);
	bpf_probe_read_kernel_str(&e->cgroup, sizeof(e->cgroup), cgroup_name);
}

// ── SUCCESS path: lsm.s/file_open ────────────────────────────────────────────
// Fires inside do_dentry_open() after the kernel resolves the path and passes
// the permission check, before returning the fd.
// @ret: return value of any prior LSM hook. Non-zero means a prior module
//       (SELinux, AppArmor) already denied — pass through, audit-only.
SEC("lsm.s/file_open")
int BPF_PROG(handle_file_open, struct file *file, int ret)
{
	// Respect prior denials from other LSM hooks — do not override.
	if (ret != 0)
		return ret;

	struct file_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	fill_common(e, task);

	e->ret    = 0;                            // success
	e->f_mode = BPF_CORE_READ(file, f_mode);  // FMODE_WRITE bit scopes T1053/T1070 in Go

	// bpf_d_path resolves the full absolute path (e.g. "/etc/shadow") from the
	// kernel struct path. Requires sleepable context — provided by lsm.s.
	// On error (path too long, unusual mount), discard rather than emit garbage.
	e->filename[0] = '\0';
	long r = bpf_d_path(&file->f_path, e->filename, sizeof(e->filename));
	if (r < 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ── DENIAL path: do_sys_openat2 kprobe + kretprobe ──────────────────────────
// Per-thread scratch carries the filename pointer from entry to return, so the
// kretprobe can emit only on EACCES/EPERM. Keyed by pid_tgid.
struct openat2_args {
	__u64 filename; // raw user pointer captured at entry (u64, not char* — bpf2go
	                // cannot generate a Go binding for a map value with a pointer field)
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, struct openat2_args);
} openat2_pending SEC(".maps");

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(handle_openat2_enter, int dfd, const char *filename)
{
	u64 id = bpf_get_current_pid_tgid();
	struct openat2_args args = {};
	args.filename = (u64)filename;
	bpf_map_update_elem(&openat2_pending, &id, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/do_sys_openat2")
int BPF_KRETPROBE(handle_openat2_exit, long ret)
{
	u64 id = bpf_get_current_pid_tgid();
	struct openat2_args *args = bpf_map_lookup_elem(&openat2_pending, &id);
	if (!args)
		return 0;

	// Emit only denied attempts on existing files. Successes are covered by the
	// LSM hook (better canonical path); ENOENT/other errors are probing noise.
	if (ret != -EACCES && ret != -EPERM)
		goto cleanup;

	struct file_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		goto cleanup;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	fill_common(e, task);

	e->ret    = (s32)ret; // -EACCES / -EPERM
	e->f_mode = 0;        // denial path: no struct file, mode unknown

	// Raw user path string captured at entry. At the kretprobe the open has
	// already failed, so there is no struct file/f_path to canonicalize with
	// bpf_d_path; this string may be relative or contain unresolved symlinks.
	e->filename[0] = '\0';
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (const char *)args->filename);

	bpf_ringbuf_submit(e, 0);

cleanup:
	bpf_map_delete_elem(&openat2_pending, &id);
	return 0;
}
