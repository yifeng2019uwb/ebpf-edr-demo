// Package detector implements detection logic for the EDR agent.
// All allow/block lists and thresholds live in policy.go.
// Event structs and converters live in internal/processor.
package detector

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"ebpf-edr-demo/internal/alert"
	"ebpf-edr-demo/internal/processor"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

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

func isPrivateIP(ip net.IP) bool {
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ── Process rules ─────────────────────────────────────────────────────────────

func CheckProcessRules(event processor.ProcessEvent, container string) *alert.Alert {
	comm := processor.CString(event.Comm[:])

	if isWhitelisted(comm) {
		return nil
	}

	// CRITICAL: process in a namespace that is neither host nor any known container
	if container == "unknown-ns" {
		return &alert.Alert{
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
		return &alert.Alert{
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
		return &alert.Alert{
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

// ── File access rules ─────────────────────────────────────────────────────────

func CheckFileRules(event processor.FileEvent, container string) *alert.Alert {
	filename := processor.CString(event.Filename[:])
	comm := processor.CString(event.Comm[:])

	// CRITICAL: host process reading Docker container filesystem directly
	if container == "host" {
		if strings.HasPrefix(filename, "/var/lib/docker/overlay2/") {
			return &alert.Alert{
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
			return &alert.Alert{
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
			return &alert.Alert{
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
			if suffix == ".pem" && isPemExcluded(filename) {
				continue
			}
			return &alert.Alert{
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
			return &alert.Alert{
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

// ── Network rules ─────────────────────────────────────────────────────────────

// CheckNetworkRules evaluates outbound connection attempts.
// ip and port are already converted to host byte order by the caller.
func CheckNetworkRules(event processor.NetEvent, container string, ip net.IP, port uint16) *alert.Alert {
	if container == "host" {
		return nil
	}

	if isPrivateIP(ip) {
		return nil
	}

	comm := processor.CString(event.Comm[:])

	for _, allowed := range externalAllowedContainers {
		if container == allowed {
			return &alert.Alert{
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

	return &alert.Alert{
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
