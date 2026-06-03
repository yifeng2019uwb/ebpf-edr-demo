package detector

import (
	"log"
	"net"
	"syscall"

	"github.com/cilium/ebpf"

	"ebpf-edr-demo/internal/alert"
)

// Responder executes response actions for alerts.
// blockedIPs is nil until the blocked_ips BPF map is compiled and go generate is run on Linux.
// Pass loader.BlockedIPs from cmd/edr-monitor/main.go once the kernel side is activated.
type Responder struct {
	blockedIPs *ebpf.Map
}

func NewResponder(blockedIPs *ebpf.Map) *Responder {
	return &Responder{blockedIPs: blockedIPs}
}

// Respond executes the response action for an alert.
// Returns the action that was actually executed — empty string if skipped (e.g. nil map).
// Called synchronously in the detector goroutine immediately after detection fires.
func (r *Responder) Respond(a *alert.Alert, action ResponseAction) ResponseAction {
	switch action {
	case ActionKillProcess:
		killProcess(a)
		return ActionKillProcess
	case ActionBlockIP:
		if r.blockIP(a) {
			return ActionBlockIP
		}
		return ActionNone
	// Phase 2: ActionQuarantineFile: quarantineFile(a.Filename)
	}
	return ActionNone
}

// killProcess sends SIGKILL to the process that triggered the alert.
// The process may have already forked children; those are not killed here.
// Phase 2: kill the entire process group (syscall.Kill(-pgid, SIGKILL)) or walk
// /proc/<ppid>/task/ to kill all threads before they can spawn further children.
func killProcess(a *alert.Alert) {
	pid := int(a.Pid)
	if pid <= 0 {
		return
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		log.Printf("response: kill failed pid=%d rule=%s: %v", pid, a.Rule, err)
		return
	}
	log.Printf("response: killed pid=%d comm=%s rule=%s level=%s", pid, a.Comm, a.Rule, a.Level)
}

// blockIP adds the destination IP to the blocked_ips LPMTrie in the kernel.
// Subsequent connect() calls to this IP return -EPERM before the TCP handshake completes.
//
// Scope: outbound only — lsm/socket_connect fires on connect(), not accept().
// Lifetime: IPs are blocked until the agent restarts (BPF map is cleared on program unload).
//
// Activation steps (kernel side not yet compiled):
//  1. Uncomment blocked_ips map + lpm_key in kernel/lsm-connect.bpf.c and kernel/lsm-connect.h
//  2. Run `go generate ./pkg/bpf/...` on GCP VM (Linux) — adds lsmObjs.BlockedIps to generated code
//  3. In pkg/bpf/loader.go: set l.BlockedIPs = l.lsmObjs.BlockedIps in Load()
//  4. In cmd/edr-monitor/main.go: pass loader.BlockedIPs to NewResponder()
func (r *Responder) blockIP(a *alert.Alert) bool {
	if r.blockedIPs == nil {
		log.Printf("response: blockIP skipped — blocked_ips map not loaded (activate kernel side first)")
		return false
	}
	ip := net.ParseIP(a.DstIP).To4()
	if ip == nil {
		log.Printf("response: blockIP skipped — invalid or non-IPv4 address: %s", a.DstIP)
		return false
	}
	// lpmKey mirrors struct lpm_key in kernel/lsm-connect.h.
	// prefixlen=32 blocks a single host (/32). Use <32 for CIDR range blocking.
	type lpmKey struct {
		Prefixlen uint32
		Addr      [4]byte // network byte order — same representation as lsm-connect.h lpm_key.addr
	}
	key := lpmKey{Prefixlen: 32}
	copy(key.Addr[:], ip)
	if err := r.blockedIPs.Put(key, uint8(1)); err != nil {
		log.Printf("response: blockIP failed ip=%s: %v", a.DstIP, err)
		return false
	}
	log.Printf("response: blocked ip=%s rule=%s level=%s", a.DstIP, a.Rule, a.Level)
	return true
}

// Phase 2 — quarantineFile: move the accessed file to a quarantine directory and chmod 000.
// Limitation: open() is post-facto — the read has already completed when the alert fires.
// Quarantine prevents future reads, not the current one.
// func quarantineFile(path string) { ... }
