// Package processor defines the event types that raw kernel bytes are mapped
// onto, plus byte-conversion helpers.
//
//	ProcessEvent  ↔  struct exec_event  (kernel/event.h)
//	FileEvent     ↔  struct file_event
//	NetEvent      ↔  struct net_event
//
// Each is a defined type over the bpf2go-generated struct. Those layouts are
// derived from the compiled object's BTF, so they cannot drift from the C
// definition — which is why there is no hand-written mirror here any more.
// Per-field documentation lives in kernel/event.h.
//
// Defined types rather than aliases: the workload resolver dispatches on the
// ResolveInfo method, and methods cannot be attached to another package's type.
package processor

import (
	"bytes"
	"net"
	"unsafe"

	"ebpf-edr-demo/pkg/bpf"
)

// ── Event types ───────────────────────────────────────────────────────────────

type (
	ProcessEvent bpf.ProcExecEvent
	FileEvent    bpf.FsFileEvent
	NetEvent     bpf.SockNetEvent
)

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

// CString converts a fixed-size BPF character array to a Go string using C semantics.
// Takes []int8 because bpf2go renders C `char` arrays as int8; reinterpreting them as
// bytes is layout-identical and allocation-free.
// Uses IndexByte to find the first null byte — correct for BPF buffers where
// bpf_ringbuf_reserve does NOT zero-initialize, so bytes after the null are garbage.
func CString(b []int8) string {
	if len(b) == 0 {
		return ""
	}
	s := unsafe.Slice((*byte)(unsafe.Pointer(&b[0])), len(b))
	if i := bytes.IndexByte(s, 0); i >= 0 {
		return string(s[:i])
	}
	return string(s)
}

// RawString converts a fixed-size BPF character array to a Go string keeping the
// whole buffer, nulls included. exec_event.args packs argv[1:] into fixed
// NUL-padded slots, so stopping at the first null (as CString does) would drop
// every argument after the first. Copies, so the result does not alias the
// ring-buffer sample it came from.
func RawString(b []int8) string {
	if len(b) == 0 {
		return ""
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(&b[0])), len(b)))
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
