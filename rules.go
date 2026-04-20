//go:build linux

// rules.go — detection logic only.
// All allow/block lists and thresholds live in policy.go.
// All event structs and converters live in processors.go.

package main

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

// ─────────────────────────────────────────────
// Helper functions
// ─────────────────────────────────────────────

func matchesSuffix(comm string, list []string) bool {
	for _, s := range list {
		if strings.HasSuffix(comm, s) {
			return true
		}
	}
	return false
}

// isPemExcluded returns true if the .pem file is a CA bundle rather than a private key.
// Python certifi and similar libraries load CA bundles on every HTTPS request —
// flagging them as HIGH would fire on every API call made by inventory_service.
func isPemExcluded(filename string) bool {
	for _, path := range pemExcludePaths {
		if strings.Contains(filename, path) {
			return true
		}
	}
	return false
}

func isWhitelisted(comm string) bool {
	base := filepath.Base(comm)
	for _, w := range whitelistComm {
		if base == w {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────
// Process rules
// ─────────────────────────────────────────────

func checkProcessRules(event ProcessEvent, container string) *Alert {
	comm := cstring(event.Comm[:])

	if isWhitelisted(comm) {
		return nil
	}

	// CRITICAL: process in a namespace that is neither host nor any known container
	// After immediate /proc rescan still unresolved — strong container escape indicator
	if container == "unknown-ns" {
		return &Alert{
			Level:     "CRITICAL",
			Rule:      "unknown_namespace_process",
			Message:   "Process in unrecognized namespace — possible container escape",
			Pid:       event.Pid,
			Ppid:      event.Ppid,
			Uid:       event.Uid,
			Comm:      comm,
			Container: container,
		}
	}

	// never alert on host processes — only watch containers
	if container == "host" {
		return nil
	}

	// Alert: shell spawned inside a container — possible RCE
	if matchesSuffix(comm, shellBinaries) {
		return &Alert{
			Level:     "CRITICAL",
			Rule:      "shell_spawn_container",
			Message:   "Shell spawned from container — possible RCE",
			Pid:       event.Pid,
			Ppid:      event.Ppid,
			Uid:       event.Uid,
			Comm:      comm,
			Container: container,
		}
	}

	// Alert: raw network tools (nc, ncat, wget) from containers
	if matchesSuffix(comm, networkBinaries) {
		return &Alert{
			Level:     "HIGH",
			Rule:      "network_tool_container",
			Message:   "Network tool executed from container — possible exfiltration",
			Pid:       event.Pid,
			Ppid:      event.Ppid,
			Uid:       event.Uid,
			Comm:      comm,
			Container: container,
		}
	}

	return nil
}

// ─────────────────────────────────────────────
// Exit rules
// ─────────────────────────────────────────────

func checkExitRules(event ExitEvent, container string, ppid uint32) *Alert {
	comm := cstring(event.Comm[:])

	// skip if container is unknown — exit event arrived but exec was never cached
	// (process started before EDR, or fork without exec). No container context = no reliable signal.
	if container == "unknown" {
		return nil
	}

	// never alert on host processes — mirrors checkProcessRules behavior
	// host python3/bash from integration tests and SSH sessions exit non-zero constantly
	if container == "host" {
		return nil
	}

	for _, w := range exitWhitelist {
		if comm == w {
			return nil
		}
	}

	// Alert: process exited with non-zero code AND very short duration
	// Possible: crash, killed process, failed exploit attempt
	durationMs := event.DurationNs / 1_000_000
	if event.ExitCode != 0 && durationMs < shortLivedThresholdMs {
		return &Alert{
			Level:     "LOW",
			Rule:      "short_lived_failure",
			Message:   "Process exited quickly with error — possible failed exploit",
			Pid:       int32(event.Pid),
			Ppid:      int32(ppid),
			Comm:      comm,
			Container: container,
		}
	}

	return nil
}

// ─────────────────────────────────────────────
// File access rules
// ─────────────────────────────────────────────

func checkFileRules(event FileEvent, container string) *Alert {
	filename := cstring(event.Filename[:])
	comm := cstring(event.Comm[:])

	// CRITICAL: host process reading Docker container filesystem directly
	// /var/lib/docker/overlay2/ is where container filesystems live on disk
	// No legitimate host process (other than dockerd internals) reads this at runtime
	// This indicates privilege escalation or an attacker reading container secrets from host
	if container == "host" {
		if strings.HasPrefix(filename, "/var/lib/docker/overlay2/") {
			return &Alert{
				Level:     "CRITICAL",
				Rule:      "host_reads_container_fs",
				Message:   "Host process accessed Docker container filesystem: " + filename,
				Pid:       event.Pid,
				Ppid:      event.Ppid,
				Uid:       int32(event.Uid),
				Comm:      comm,
				Container: container,
			}
		}
		return nil
	}

	// skip truly unresolvable events (should not happen after rescan, defensive only)
	if container == "" {
		return nil
	}

	// skip container runtime — reads /etc/passwd during container init
	for _, w := range fileCommWhitelist {
		if comm == w {
			return nil
		}
	}

	for _, prefix := range criticalFilePrefixes {
		if strings.HasPrefix(filename, prefix) {
			return &Alert{
				Level:     "CRITICAL",
				Rule:      "sensitive_file_access",
				Message:   "Container accessed SSH credential file: " + filename,
				Pid:       event.Pid,
				Ppid:      event.Ppid,
				Uid:       int32(event.Uid),
				Comm:      comm,
				Container: container,
			}
		}
	}

	for _, prefix := range highFilePrefixes {
		if strings.HasPrefix(filename, prefix) {
			return &Alert{
				Level:     "HIGH",
				Rule:      "sensitive_file_access",
				Message:   "Container accessed sensitive file: " + filename,
				Pid:       event.Pid,
				Ppid:      event.Ppid,
				Uid:       int32(event.Uid),
				Comm:      comm,
				Container: container,
			}
		}
	}

	for _, suffix := range highFileSuffixes {
		if strings.HasSuffix(filename, suffix) {
			// .pem files in Python package paths are CA bundles, not private keys
			if suffix == ".pem" && isPemExcluded(filename) {
				continue
			}
			return &Alert{
				Level:     "HIGH",
				Rule:      "sensitive_file_access",
				Message:   "Container accessed sensitive file: " + filename,
				Pid:       event.Pid,
				Ppid:      event.Ppid,
				Uid:       int32(event.Uid),
				Comm:      comm,
				Container: container,
			}
		}
	}

	for _, prefix := range mediumFilePrefixes {
		if strings.HasPrefix(filename, prefix) {
			return &Alert{
				Level:     "MEDIUM",
				Rule:      "sensitive_file_access",
				Message:   "Container accessed system file: " + filename,
				Pid:       event.Pid,
				Ppid:      event.Ppid,
				Uid:       int32(event.Uid),
				Comm:      comm,
				Container: container,
			}
		}
	}

	return nil
}

// ─────────────────────────────────────────────
// Network rules
// ─────────────────────────────────────────────

func isPrivateIP(ip net.IP) bool {
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// checkNetworkRules evaluates outbound connection attempts.
// ip and port are already converted to host byte order by the caller.
//
// Policy:
//   - private/internal IPs → skip (Docker bridge, service mesh, internal traffic)
//   - inventory_service → external allowed (CoinGecko market data) → LOW audit log
//   - all other containers → external connection unauthorized → HIGH alert
//   - host processes → skip (too noisy without full host allowlist)
func checkNetworkRules(event NetEvent, container string, ip net.IP, port uint16) *Alert {
	// skip host — no host-level network policy without a full process allowlist
	if container == "host" {
		return nil
	}

	// skip private and internal IP ranges — Docker bridge, inter-service traffic
	if isPrivateIP(ip) {
		return nil
	}

	comm := cstring(event.Comm[:])

	// check if this container is in the external allowlist
	// allowedMarketAPI is logged for audit — DNS not resolved in BPF,
	// so we log the destination IP and expected domain for operator review
	for _, allowed := range externalAllowedContainers {
		if container == allowed {
			return &Alert{
				Level:     "LOW",
				Rule:      "external_connect_allowed",
				Message:   fmt.Sprintf("%s external connect to %s:%d (expected: %s)", container, ip, port, allowedMarketAPI),
				Pid:       event.Pid,
				Ppid:      event.Ppid,
				Uid:       int32(event.Uid),
				Comm:      comm,
				Container: container,
			}
		}
	}

	// any other container connecting to an external IP is unauthorized
	return &Alert{
		Level:     "HIGH",
		Rule:      "unauthorized_external_connect",
		Message:   fmt.Sprintf("Container made unauthorized external connection to %s:%d", ip, port),
		Pid:       event.Pid,
		Ppid:      event.Ppid,
		Uid:       int32(event.Uid),
		Comm:      comm,
		Container: container,
	}
}
