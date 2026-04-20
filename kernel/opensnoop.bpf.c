// Originally downloaded from https://github.com/eunomia-bpf/bpf-developer-tutorial (lesson 04 opensnoop)
// Rewritten from scratch:
//   - replaced bpf_printk() stub with full ring buffer event pipeline
//   - added struct file_event with pid, ppid, uid, mnt_ns_id, comm, filename
//   - added mnt_ns_id via BPF_CORE_READ for container correlation
//   - changed from perf buffer to ring buffer (BPF_MAP_TYPE_RINGBUF) — lower overhead
//   - filtered to process-level opens only (tgid == tid)
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "opensnoop.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task;
	struct file_event *e;
	u64 id;
	u32 tgid, tid;

	id   = bpf_get_current_pid_tgid();
	tgid = id >> 32;
	tid  = (u32)id;

	// ignore thread-level calls — only track process-level opens
	if (tgid != tid)
		return 0;

	// reserve space in ring buffer
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();

	e->mnt_ns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	e->pid       = tgid;
	e->ppid      = BPF_CORE_READ(task, real_parent, tgid);
	e->uid       = (u32)bpf_get_current_uid_gid();
	e->pad       = 0;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// args[1] is the filename pointer passed to openat syscall
	char *filename_ptr = (char *)BPF_CORE_READ(ctx, args[1]);
	bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename_ptr);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
