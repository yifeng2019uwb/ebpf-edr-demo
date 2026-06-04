// lsm/socket_connect sensor — captures outbound IPv4 connection attempts.
// Emits net_event to ring buffer for all non-loopback connects.
// Policy decisions (private IP filtering, allowlists, block_ip response) are made in Go.
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "lsm-connect.h"

char LICENSE[] SEC("license") = "GPL";

#define AF_INET       2     // IPv4
#define LOOPBACK_BYTE 0x7F  // 127.x.x.x — covers all loopback (RFC 1122 /8)

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Fires before every connect() syscall. No TOCTOU gap — runs in the same
// security context as the connecting process. Always returns 0 (audit-only).
SEC("lsm/socket_connect")
int BPF_PROG(handle_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
	if (ret != 0)
		return ret;

	if (address->sa_family != AF_INET)
		return 0;

	struct sockaddr_in *addr = (struct sockaddr_in *)address;
	__u32 dst_ip = addr->sin_addr.s_addr;

	// Skip loopback in BPF — filters constant health-check noise before ring buffer.
	// All other private ranges (10.x, 172.16.x, 192.168.x) filtered in Go.
	if ((dst_ip & 0xFF) == LOOPBACK_BYTE)
		return 0;

	struct net_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;

	e->mnt_ns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	e->dst_ip    = dst_ip;
	e->dst_port  = addr->sin_port;
	e->pad1      = 0;
	e->pid       = tgid;
	e->ppid      = BPF_CORE_READ(task, real_parent, tgid);
	e->uid       = (u32)bpf_get_current_uid_gid();
	e->pad2      = 0;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
