// Originally downloaded from https://github.com/eunomia-bpf/bpf-developer-tutorial (lesson 19 lsm-connect)
// Rewritten from scratch:
//   - replaced hardcoded IP block with full ring buffer event pipeline
//   - added struct net_event with mnt_ns_id, dst_ip, dst_port, pid, ppid, uid, comm
//   - audit mode only — never blocks, always returns 0
//   - skips loopback (127.x.x.x) in BPF to reduce ring buffer traffic
//   - all policy decisions (private IP ranges, container allowlist) made in Go userspace
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "lsm-connect.h"

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2  // IPv4 — we only track IPv4 connections

// dst_ip is stored in network byte order (big-endian).
// On x86 little-endian, the first octet (127 for loopback) sits in the lowest byte.
// (127.x.x.x bytes in memory: [7F, xx, xx, xx] → read as LE uint32: 0xXXXXXX7F)
#define LOOPBACK_BYTE 0x7F  // 127 — any 127.x.x.x address

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// lsm/socket_connect — fires before every connect() syscall at kernel level.
// No TOCTOU gap — runs in the same security context as the connecting process.
// Audit mode: always returns 0 (allow). Policy enforcement happens in Go.
SEC("lsm/socket_connect")
int BPF_PROG(handle_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
	// respect prior denials from other LSM hooks
	if (ret != 0)
		return ret;

	// only track IPv4 — skip IPv6, Unix domain sockets, etc.
	if (address->sa_family != AF_INET)
		return 0;

	struct sockaddr_in *addr = (struct sockaddr_in *)address;
	__u32 dst_ip = addr->sin_addr.s_addr;

	// skip loopback in BPF — health checks and inter-process comms use 127.x.x.x
	// constantly; filtering here prevents flooding the ring buffer with noise.
	// all other private ranges (10.x, 172.16.x, 192.168.x) filtered in Go
	// so policy can be updated without recompiling BPF.
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
	return 0;  // audit mode — never block
}
