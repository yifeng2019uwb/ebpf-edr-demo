// Package detector implements detection logic for the EDR agent.
// All allow/block lists and thresholds live in policy.go.
// Event structs live in internal/processor; pipeline types in pkg/pipeline.
package detector

import (
	"fmt"
	"log"
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
	if isSystemNamespace(ev.Workload.Meta.Namespace) {
		return nil
	}

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

func newFileAlert(event processor.FileEvent, res workload.ResolveResult, comm, filename string, level alert.Level, rule, msg string) *alert.Alert {
	return &alert.Alert{
		Level: level, Rule: rule, Message: msg,
		Pid: event.Pid, Ppid: event.Ppid, Uid: int32(event.Uid),
		Comm: comm, Workload: res, Filename: filename,
	}
}

func newProcessAlert(event processor.ProcessEvent, res workload.ResolveResult, comm string, level alert.Level, rule, msg string) *alert.Alert {
	return &alert.Alert{
		Level: level, Rule: rule, Message: msg,
		Pid: event.Pid, Ppid: event.Ppid, Uid: event.Uid,
		Comm: comm, Workload: res,
	}
}

// ── Process rules ─────────────────────────────────────────────────────────────

func checkProcessRules(event processor.ProcessEvent, res workload.ResolveResult) *alert.Alert {
	comm := processor.CString(event.Comm[:])

	if isWhitelisted(comm) {
		return nil
	}

	if res.State == workload.StateUnknown {
		base := filepath.Base(comm)
		for _, w := range unknownNsCommsWhitelist {
			if base == w {
				return nil
			}
		}
		return newProcessAlert(event, res, comm, alert.Critical, "unknown_namespace_process", "Process in unrecognized namespace — possible container escape")
	}

	if res.State == workload.StateHost {
		return nil
	}

	if matchesSuffix(comm, shellBinaries) {
		return newProcessAlert(event, res, comm, alert.Critical, "shell_spawn_container", "Shell spawned from container — possible RCE")
	}

	if matchesSuffix(comm, networkBinaries) {
		return newProcessAlert(event, res, comm, alert.High, "network_tool_container", "Network tool executed from container — possible exfiltration")
	}

	return nil
}

// ── File access rules ─────────────────────────────────────────────────────────

func checkFileRules(event processor.FileEvent, res workload.ResolveResult) *alert.Alert {
	filename := processor.CString(event.Filename[:])
	comm := processor.CString(event.Comm[:])
	log.Printf("DBG file-detect: comm=%q mntNsID=%d state=%s file=%q", comm, event.MntNsId, res.State, filename)

	for _, w := range fileCommWhitelist {
		if comm == w {
			return nil
		}
	}

	if res.State == workload.StateHost {
		for _, prefix := range containerFSPrefixes {
			if strings.HasPrefix(filename, prefix) {
				return newFileAlert(event, res, comm, filename, alert.Critical, "host_reads_container_fs", "Host process accessed container filesystem: "+filename)
			}
		}
		return nil
	}

	for _, prefix := range criticalFilePrefixes {
		if strings.HasPrefix(filename, prefix) {
			return newFileAlert(event, res, comm, filename, alert.Critical, "sensitive_file_access", "Container accessed SSH credential file: "+filename)
		}
	}

	for _, prefix := range highFilePrefixes {
		if strings.HasPrefix(filename, prefix) {
			return newFileAlert(event, res, comm, filename, alert.High, "sensitive_file_access", "Container accessed sensitive file: "+filename)
		}
	}

	for _, suffix := range highFileSuffixes {
		if strings.HasSuffix(filename, suffix) {
			if suffix == ".pem" && isPemExcluded(filename) {
				continue
			}
			return newFileAlert(event, res, comm, filename, alert.High, "sensitive_file_access", "Container accessed sensitive file: "+filename)
		}
	}

	for _, prefix := range mediumFilePrefixes {
		if strings.HasPrefix(filename, prefix) {
			return newFileAlert(event, res, comm, filename, alert.Medium, "sensitive_file_access", "Container accessed system file: "+filename)
		}
	}

	return nil
}

// ── Network rules ─────────────────────────────────────────────────────────────

func checkNetworkRules(event processor.NetEvent, res workload.ResolveResult, ip net.IP, port uint16) *alert.Alert {
	if res.State == workload.StateHost {
		return nil
	}

	if isPrivateIP(ip) {
		return nil
	}

	comm := processor.CString(event.Comm[:])
	ipStr := ip.String()
	id := res.Identity

	for _, allowed := range externalAllowedServices {
		if id.Service == allowed {
			return nil
		}
	}

	return &alert.Alert{
		Level:    alert.High,
		Rule:     "unauthorized_external_connect",
		Message:  fmt.Sprintf("Container made unauthorized external connection to %s:%d", ipStr, port),
		Pid:      event.Pid,
		Ppid:     event.Ppid,
		Uid:      int32(event.Uid),
		Comm:     comm,
		Workload: res,
		DstIP:    ipStr,
		DstPort:  port,
	}
}
