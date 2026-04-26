// Package detector implements detection logic for the EDR agent.
// All allow/block lists and thresholds live in policy.go.
// Event structs live in internal/processor; pipeline types in pkg/pipeline.
package detector

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"ebpf-edr-demo/internal/alert"
	"ebpf-edr-demo/internal/processor"
	"ebpf-edr-demo/pkg/pipeline"
	"ebpf-edr-demo/pkg/workload"
)

// RuleDetector implements pipeline.Detector using the policy defined in policy.go.
type RuleDetector struct{}

func NewRuleDetector() *RuleDetector { return &RuleDetector{} }

// Detect applies all rules to the enriched event and returns any triggered alerts.
func (d *RuleDetector) Detect(ev pipeline.EnrichedEvent) []alert.Alert {
	var a *alert.Alert
	switch ev.Type {
	case pipeline.ProcessEventType:
		a = checkProcessRules(*ev.Process, ev.Workload)
	case pipeline.FileEventType:
		a = checkFileRules(*ev.File, ev.Workload)
	case pipeline.NetEventType:
		ip := processor.NetIP(ev.Net.DstIp)
		port := processor.NetPort(ev.Net.DstPort)
		a = checkNetworkRules(*ev.Net, ev.Workload, ip, port)
	}
	if a == nil {
		return nil
	}
	return []alert.Alert{*a}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func matchesSuffix(comm string, list []string) bool {
	for _, s := range list {
		if strings.HasSuffix(comm, s) {
			return true
		}
	}
	return false
}

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

func checkProcessRules(event processor.ProcessEvent, id workload.WorkloadIdentity) *alert.Alert {
	comm := processor.CString(event.Comm[:])

	if isWhitelisted(comm) {
		return nil
	}

	if id.Service == "unknown-ns" {
		return &alert.Alert{
			Level:    "CRITICAL",
			Rule:     "unknown_namespace_process",
			Message:  "Process in unrecognized namespace — possible container escape",
			Pid:      event.Pid,
			Ppid:     event.Ppid,
			Uid:      event.Uid,
			Comm:     comm,
			Workload: id,
		}
	}

	if id.Service == "host" {
		return nil
	}

	if matchesSuffix(comm, shellBinaries) {
		return &alert.Alert{
			Level:    "CRITICAL",
			Rule:     "shell_spawn_container",
			Message:  "Shell spawned from container — possible RCE",
			Pid:      event.Pid,
			Ppid:     event.Ppid,
			Uid:      event.Uid,
			Comm:     comm,
			Workload: id,
		}
	}

	if matchesSuffix(comm, networkBinaries) {
		return &alert.Alert{
			Level:    "HIGH",
			Rule:     "network_tool_container",
			Message:  "Network tool executed from container — possible exfiltration",
			Pid:      event.Pid,
			Ppid:     event.Ppid,
			Uid:      event.Uid,
			Comm:     comm,
			Workload: id,
		}
	}

	return nil
}

// ── File access rules ─────────────────────────────────────────────────────────

func checkFileRules(event processor.FileEvent, id workload.WorkloadIdentity) *alert.Alert {
	filename := processor.CString(event.Filename[:])
	comm := processor.CString(event.Comm[:])

	if id.Service == "host" {
		if strings.HasPrefix(filename, "/var/lib/docker/overlay2/") {
			return &alert.Alert{
				Level:    "CRITICAL",
				Rule:     "host_reads_container_fs",
				Message:  "Host process accessed Docker container filesystem: " + filename,
				Pid:      event.Pid,
				Ppid:     event.Ppid,
				Uid:      int32(event.Uid),
				Comm:     comm,
				Workload: id,
				Filename: filename,
			}
		}
		return nil
	}

	for _, w := range fileCommWhitelist {
		if comm == w {
			return nil
		}
	}

	for _, prefix := range criticalFilePrefixes {
		if strings.HasPrefix(filename, prefix) {
			return &alert.Alert{
				Level:    "CRITICAL",
				Rule:     "sensitive_file_access",
				Message:  "Container accessed SSH credential file: " + filename,
				Pid:      event.Pid,
				Ppid:     event.Ppid,
				Uid:      int32(event.Uid),
				Comm:     comm,
				Workload: id,
				Filename: filename,
			}
		}
	}

	for _, prefix := range highFilePrefixes {
		if strings.HasPrefix(filename, prefix) {
			return &alert.Alert{
				Level:    "HIGH",
				Rule:     "sensitive_file_access",
				Message:  "Container accessed sensitive file: " + filename,
				Pid:      event.Pid,
				Ppid:     event.Ppid,
				Uid:      int32(event.Uid),
				Comm:     comm,
				Workload: id,
				Filename: filename,
			}
		}
	}

	for _, suffix := range highFileSuffixes {
		if strings.HasSuffix(filename, suffix) {
			if suffix == ".pem" && isPemExcluded(filename) {
				continue
			}
			return &alert.Alert{
				Level:    "HIGH",
				Rule:     "sensitive_file_access",
				Message:  "Container accessed sensitive file: " + filename,
				Pid:      event.Pid,
				Ppid:     event.Ppid,
				Uid:      int32(event.Uid),
				Comm:     comm,
				Workload: id,
				Filename: filename,
			}
		}
	}

	for _, prefix := range mediumFilePrefixes {
		if strings.HasPrefix(filename, prefix) {
			return &alert.Alert{
				Level:    "MEDIUM",
				Rule:     "sensitive_file_access",
				Message:  "Container accessed system file: " + filename,
				Pid:      event.Pid,
				Ppid:     event.Ppid,
				Uid:      int32(event.Uid),
				Comm:     comm,
				Workload: id,
				Filename: filename,
			}
		}
	}

	return nil
}

// ── Network rules ─────────────────────────────────────────────────────────────

func checkNetworkRules(event processor.NetEvent, id workload.WorkloadIdentity, ip net.IP, port uint16) *alert.Alert {
	if id.Service == "host" {
		return nil
	}

	if isPrivateIP(ip) {
		return nil
	}

	comm := processor.CString(event.Comm[:])
	ipStr := ip.String()

	for _, allowed := range externalAllowedServices {
		if id.Service == allowed {
			return &alert.Alert{
				Level:    "LOW",
				Rule:     "external_connect_allowed",
				Message:  fmt.Sprintf("%s external connect to %s:%d (expected: %s)", id.Service, ipStr, port, allowedMarketAPI),
				Pid:      event.Pid,
				Ppid:     event.Ppid,
				Uid:      int32(event.Uid),
				Comm:     comm,
				Workload: id,
				DstIP:    ipStr,
				DstPort:  port,
			}
		}
	}

	return &alert.Alert{
		Level:    "HIGH",
		Rule:     "unauthorized_external_connect",
		Message:  fmt.Sprintf("Container made unauthorized external connection to %s:%d", ipStr, port),
		Pid:      event.Pid,
		Ppid:     event.Ppid,
		Uid:      int32(event.Uid),
		Comm:     comm,
		Workload: id,
		DstIP:    ipStr,
		DstPort:  port,
	}
}
