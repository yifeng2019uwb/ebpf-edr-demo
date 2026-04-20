// lsm-connect.h — shared struct between lsm-connect.bpf.c and Go userspace
//
// Field layout chosen to avoid implicit C alignment padding.
// sizeof = 8+4+2+2+4+4+4+4+128 = 160 bytes — no tail padding (160 % 8 == 0)
// Go binary.Size(NetEvent{}) must match exactly.

#ifndef __LSM_CONNECT_H
#define __LSM_CONNECT_H

#define TASK_COMM_LEN 128

// ── Why network byte order for dst_ip and dst_port? ──────────────────────────
// sin_addr.s_addr and sin_port are stored in network byte order (big-endian)
// by the kernel. We store them as-is — no conversion in BPF.
// Go userspace converts using byte extraction:
//   ip octet 0 = byte(DstIp)         (lowest byte in little-endian read)
//   ip octet 1 = byte(DstIp >> 8)
//   port       = (DstPort >> 8) | (DstPort << 8)  (byte swap)
// This works because reading big-endian bytes as little-endian uint reverses
// the byte order, and extracting LSB→MSB gives back the original octets.

struct net_event {
	__u64 mnt_ns_id;         // offset 0  — mount namespace ID (container identity)
	__u32 dst_ip;            // offset 8  — destination IP (network byte order)
	__u16 dst_port;          // offset 12 — destination port (network byte order)
	__u16 pad1;              // offset 14 — explicit padding
	int   pid;               // offset 16 — process ID
	int   ppid;              // offset 20 — parent process ID
	__u32 uid;               // offset 24 — user ID
	__u32 pad2;              // offset 28 — explicit padding
	char  comm[TASK_COMM_LEN]; // offset 32 — process name
	// total: 8+4+2+2+4+4+4+4+128 = 160 bytes
};

#endif /* __LSM_CONNECT_H */
