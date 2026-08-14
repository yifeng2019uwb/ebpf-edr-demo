//go:build linux

package bpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ProcessEventBurstSize is the perf buffer size for process events.
// Sized to absorb container startup bursts: typical container spawns 200-300 processes rapidly.
// 256KB buffer can hold ~940 ProcessEvent structs (544 bytes each), providing safe headroom
// for concurrent process creation without kernel dropping/truncating events.
// If "rawCh full" warnings appear, increase this constant.
const ProcessEventBurstSize = 512 * 1024

// Loader holds all loaded BPF objects, kernel attachments, and event readers.
// Call Close() to detach all probes and release kernel resources.
type Loader struct {
	// Exported readers — callers consume events from these.
	ProcessRd *perf.Reader
	FileRd    *ringbuf.Reader
	NetRd     *ringbuf.Reader

	// kernel resources — closed by Close()
	processObjs ProcObjects
	fileObjs    FsObjects
	lsmObjs     SockObjects
	links       []link.Link
}

// Load loads all eBPF programs, attaches them to kernel hooks, and opens event readers.
// Returns a ready Loader, or an error with all partial resources already cleaned up.
func Load() (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	l := &Loader{}

	// ── Load eBPF object collections ──────────────────────────────────────────

	if err := LoadProcObjects(&l.processObjs, nil); err != nil {
		return nil, fmt.Errorf("loading process objects: %w", err)
	}

	if err := LoadFsObjects(&l.fileObjs, nil); err != nil {
		l.processObjs.Close()
		return nil, fmt.Errorf("loading file objects: %w", err)
	}

	if err := LoadSockObjects(&l.lsmObjs, nil); err != nil {
		l.processObjs.Close()
		l.fileObjs.Close()
		return nil, fmt.Errorf("loading lsm objects: %w", err)
	}

	// ── Attach kernel hooks ────────────────────────────────────────────────────

	if err := l.attachLinks(); err != nil {
		l.Close()
		return nil, err
	}

	// ── Open event readers ─────────────────────────────────────────────────────

	var err error

	l.ProcessRd, err = perf.NewReader(l.processObjs.Events, ProcessEventBurstSize)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("opening process perf reader: %w", err)
	}

	l.FileRd, err = ringbuf.NewReader(l.fileObjs.Rb)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("opening file ringbuf reader: %w", err)
	}

	l.NetRd, err = ringbuf.NewReader(l.lsmObjs.Rb)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("opening lsm ringbuf reader: %w", err)
	}

	return l, nil
}

func (l *Loader) attachLinks() error {
	processTp, err := link.Tracepoint("syscalls", "sys_enter_execve",
		l.processObjs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		return fmt.Errorf("attaching process tracepoint: %w", err)
	}
	l.links = append(l.links, processTp)

	fileLsmLink, err := link.AttachLSM(link.LSMOptions{Program: l.fileObjs.HandleFileOpen})
	if err != nil {
		return fmt.Errorf("attaching lsm file_open hook: %w", err)
	}
	l.links = append(l.links, fileLsmLink)

	lsmLink, err := link.AttachLSM(link.LSMOptions{Program: l.lsmObjs.HandleConnect})
	if err != nil {
		return fmt.Errorf("attaching lsm connect hook: %w", err)
	}
	l.links = append(l.links, lsmLink)

	return nil
}

// Close detaches all kernel probes and releases all resources.
// Safe to call even if Load() failed partway through.
func (l *Loader) Close() {
	if l.ProcessRd != nil {
		l.ProcessRd.Close()
	}
	if l.FileRd != nil {
		l.FileRd.Close()
	}
	if l.NetRd != nil {
		l.NetRd.Close()
	}
	for _, lnk := range l.links {
		lnk.Close()
	}
	l.processObjs.Close()
	l.fileObjs.Close()
	l.lsmObjs.Close()
}
