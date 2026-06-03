package detector

import (
	"log"
	"syscall"

	"ebpf-edr-demo/internal/alert"
)

// Respond executes the response action for an alert.
// Called synchronously in the detector goroutine immediately after detection fires.
func Respond(a *alert.Alert, action ResponseAction) {
	switch action {
	case ActionKillProcess:
		killProcess(a)
	// Phase 2: ActionBlockIP:        blockIP(a.DstIP)
	// Phase 2: ActionQuarantineFile: quarantineFile(a.Filename)
	}
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

// Phase 2 — blockIP: block the destination IP before future connections complete.
//
// Kill-after-connect fires after the TCP handshake — data may have already been sent.
// The clean approach: write the IP to the blocked_ips LPMTrie map in lsm-connect.bpf.c.
// The LSM hook checks the map before the handshake and returns -EPERM to deny.
//
// To implement:
//  1. Uncomment blocked_ips map in lsm-connect.bpf.c and lpm_key in lsm-connect.h
//  2. Run `go generate ./pkg/bpf/...` — adds lsmObjs.BlockedIps *ebpf.Map to generated code
//  3. Pass *ebpf.Map into Respond(), then:
//
//     type lpmKey struct {
//         Prefixlen uint32
//         Addr      [4]byte  // network byte order
//     }
//     key := lpmKey{Prefixlen: 32}
//     copy(key.Addr[:], net.ParseIP(ip).To4())
//     blockedIPs.Put(key, uint8(1))
//
// func blockIP(blockedIPs *ebpf.Map, ip string) { ... }

// Phase 2 — quarantineFile: move the accessed file to a quarantine directory and chmod 000.
//
// Limitation: open() is post-facto — the read has already completed when the alert fires.
// Quarantine prevents future reads, not the current one. More useful for write events
// (process drops a .sh file; we move it before exec).
//
// func quarantineFile(path string) { ... }
