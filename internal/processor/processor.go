// Package processor defines the event structs that map 1:1 onto the C structs
// produced by each eBPF kernel program, plus byte-conversion helpers.
//
// Field order, types, and padding must EXACTLY match kernel/event.h:
//
//	ProcessEvent  ↔  struct exec_event
//	FileEvent     ↔  struct file_event
//	NetEvent      ↔  struct net_event
//
// Go maps raw kernel bytes directly onto these structs — there is no
// serialization layer, so the layout must be byte-perfect.
package processor

import (
	"bytes"
	"net"

	"ebpf-edr-demo/pkg"
)

// ── Event structs ─────────────────────────────────────────────────────────────

// ProcessEvent matches event.h struct exec_event.
// sizeof = 4+4+4+4+8+256+128+4+128+4 = 544 bytes, no implicit padding.
type ProcessEvent struct {
	Pid       int32                 // offset 0   — process ID (from kernel tgid)
	Ppid      int32                 // offset 4   — parent process ID
	Uid       int32                 // offset 8   — user ID (0=root)
	MntNsId   uint32                // offset 12  — mount namespace ID — identifies container
	EventTime uint64                // offset 16  — bpf_ktime_get_ns() (monotonic; convert via boot offset)
	ExecPath  [pkg.ExecPathLen]byte // offset 24  — path as invoked (execve arg 0)
	Cgroup    [pkg.CgroupLen]byte   // offset 280 — leaf cgroup name
	HasTty    uint32                // offset 408 — 1 = controlling terminal attached (interactive)
	Args      [pkg.ArgsLen]byte     // offset 412 — argv[1:], space-joined, bounded
	Pad       uint32                // offset 540 — explicit padding (keeps size an 8-multiple)
}

// FileEvent matches event.h struct file_event.
// sizeof = 8+8+4+4+4+4+4+4+16+256+128 = 440 bytes, no implicit padding.
type FileEvent struct {
	MntNsId   uint64                   // offset 0   — mount namespace ID
	EventTime uint64                   // offset 8   — bpf_ktime_get_ns() (monotonic; convert via boot offset)
	Pid       int32                    // offset 16  — process ID
	Ppid      int32                    // offset 20  — parent process ID
	Uid       uint32                   // offset 24  — user ID
	Fmode     uint32                   // offset 28  — FMODE_READ(0x1)/FMODE_WRITE(0x2); 0 on denial path
	Ret       int32                    // offset 32  — 0 = success (lsm hook); -EACCES/-EPERM = denied (kprobe)
	Pad       uint32                   // offset 36  — explicit padding
	Comm      [pkg.TaskCommLen]byte    // offset 40  — process name
	Filename  [pkg.MaxFilenameLen]byte // offset 56  — canonical path (success) or raw user string (denial)
	Cgroup    [pkg.CgroupLen]byte      // offset 312 — leaf cgroup name
}

// NetEvent matches event.h struct net_event.
// sizeof = 8+8+4+2+2+4+4+4+4+16 = 56 bytes, no implicit padding.
type NetEvent struct {
	MntNsId   uint64                // offset 0  — mount namespace ID
	EventTime uint64                // offset 8  — bpf_ktime_get_ns() (monotonic; convert via boot offset)
	DstIp     uint32                // offset 16 — destination IP (network byte order)
	DstPort   uint16                // offset 20 — destination port (network byte order)
	Pad1      uint16                // offset 22 — explicit padding
	Pid       int32                 // offset 24
	Ppid      int32                 // offset 28
	Uid       uint32                // offset 32
	Pad2      uint32                // offset 36 — explicit padding
	Comm      [pkg.TaskCommLen]byte // offset 40
}

// ── Resolver input ────────────────────────────────────────────────────────────

// ResolveInfo returns the fields the workload resolver needs from an event: the mount
// namespace (its cache key), the pid, the cgroup leaf (dispatch hint), and whether the
// event carries a cgroup at all. Net events return hasCgroup=false — they resolve from
// the cache only and never drive resolution. Implemented on each event so the resolver
// takes any event via one interface, with no per-type switch.
func (e *ProcessEvent) ResolveInfo() (mntNsID, pid uint32, cgroupLeaf string, hasCgroup bool) {
	return e.MntNsId, uint32(e.Pid), CString(e.Cgroup[:]), true
}

func (e *FileEvent) ResolveInfo() (mntNsID, pid uint32, cgroupLeaf string, hasCgroup bool) {
	return uint32(e.MntNsId), uint32(e.Pid), CString(e.Cgroup[:]), true
}

func (e *NetEvent) ResolveInfo() (mntNsID, pid uint32, cgroupLeaf string, hasCgroup bool) {
	return uint32(e.MntNsId), uint32(e.Pid), "", false
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
