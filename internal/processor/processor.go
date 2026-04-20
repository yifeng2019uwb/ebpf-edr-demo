// Package processor defines the event structs that map 1:1 onto the C structs
// produced by each eBPF kernel program, plus byte-conversion helpers.
//
// Field order, types, and padding must EXACTLY match the corresponding .h header:
//
//	ProcessEvent  ↔  execsnoop.h   struct event
//	ExitEvent     ↔  exitsnoop.h   struct event  (kept for reference; not loaded at runtime)
//	FileEvent     ↔  opensnoop.h   struct file_event
//	NetEvent      ↔  lsm-connect.h struct net_event
//
// Go maps raw kernel bytes directly onto these structs via binary.Read — there is
// no serialization layer, so the layout must be byte-perfect.
package processor

import (
	"bytes"
	"net"
)

// TaskCommLen must match #define TASK_COMM_LEN 128 in all .h files.
const TaskCommLen = 128

// ── Event structs ─────────────────────────────────────────────────────────────

// ProcessEvent matches execsnoop.h struct event.
// sizeof = 4+4+4+4+128 = 144 bytes, no implicit padding.
type ProcessEvent struct {
	Pid     int32             // process ID (from kernel tgid)
	Ppid    int32             // parent process ID
	Uid     int32             // user ID (0=root)
	MntNsId uint32            // mount namespace ID — identifies container
	Comm    [TaskCommLen]byte // full executable path (e.g. /usr/bin/bash)
}

// FileEvent matches opensnoop.h struct file_event.
// sizeof = 8+4+4+4+4+128+256 = 408 bytes, no implicit padding.
type FileEvent struct {
	MntNsId  uint64            // offset 0   — mount namespace ID
	Pid      int32             // offset 8   — process ID
	Ppid     int32             // offset 12  — parent process ID
	Uid      uint32            // offset 16  — user ID
	Pad      uint32            // offset 20  — explicit padding (see opensnoop.h)
	Comm     [TaskCommLen]byte // offset 24  — process name
	Filename [256]byte         // offset 152 — file path being opened
}

// ExitEvent matches exitsnoop.h struct event.
// Kept for reference — exitsnoop is not loaded at runtime (rule was dropped).
// sizeof = 8+4+4+4+4+128 = 152 bytes, no implicit padding.
type ExitEvent struct {
	DurationNs uint64            // offset 0  — duration in nanoseconds
	Pid        uint32            // offset 8
	Ppid       uint32            // offset 12
	ExitCode   uint32            // offset 16
	Pad        uint32            // offset 20 — explicit pad matches C struct
	Comm       [TaskCommLen]byte // offset 24
}

// NetEvent matches lsm-connect.h struct net_event.
// sizeof = 8+4+2+2+4+4+4+4+128 = 160 bytes, no implicit padding.
type NetEvent struct {
	MntNsId uint64            // offset 0  — mount namespace ID
	DstIp   uint32            // offset 8  — destination IP (network byte order)
	DstPort uint16            // offset 12 — destination port (network byte order)
	Pad1    uint16            // offset 14 — explicit padding
	Pid     int32             // offset 16
	Ppid    int32             // offset 20
	Uid     uint32            // offset 24
	Pad2    uint32            // offset 28 — explicit padding
	Comm    [TaskCommLen]byte // offset 32
}

// ── Converters ────────────────────────────────────────────────────────────────

// CString converts a fixed-size BPF byte array to a Go string using C semantics.
// Uses IndexByte to find the first null byte — correct for BPF buffers where
// bpf_ringbuf_reserve does NOT zero-initialize, so bytes after the null are garbage.
func CString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// NetIP converts DstIp (network byte order stored as little-endian uint32)
// back to a net.IP by extracting bytes in wire order.
func NetIP(n uint32) net.IP {
	return net.IPv4(byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
}

// NetPort converts DstPort (network byte order stored as little-endian uint16)
// to host byte order by swapping the two bytes.
func NetPort(n uint16) uint16 {
	return (n >> 8) | (n << 8)
}
