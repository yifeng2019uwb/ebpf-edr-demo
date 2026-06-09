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

	// Host processes are trusted — skip all rules.
	if res.State == workload.StateHost {
		return nil
	}

	// T1036 — masquerading: checked BEFORE whitelist so an attacker cannot hide
	// malware named after a legit process (e.g. /tmp/sshd bypasses the "sshd" whitelist).
	// Skipped for host processes above — only suspicious in container context.
	for _, prefix := range t1036MasqueradingPaths {
		if strings.HasPrefix(comm, prefix) {
			return newProcessAlert(event, res, comm, alert.High, RuleT1036Masquerading, "Process running from suspicious path: "+comm)
		}
	}

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
		return newProcessAlert(event, res, comm, alert.Critical, RuleT1611EscapeToHostNs, "Process in unrecognized namespace — possible container escape")
	}

	if matchesSuffix(comm, shellBinaries) {
		return newProcessAlert(event, res, comm, alert.Critical, RuleT1059UnixShellExecution, "Shell spawned from container — possible RCE")
	}

	if matchesSuffix(comm, networkBinaries) {
		return newProcessAlert(event, res, comm, alert.High, RuleT1105IngressToolTransfer, "Network tool executed from container — possible exfiltration or tool staging")
	}

	// T1613 — container management tool inside container: attacker doing reconnaissance
	if matchesSuffix(comm, t1613ContainerMgmtTools) {
		return newProcessAlert(event, res, comm, alert.High, RuleT1613ContainerDiscovery, "Container management tool executed inside container — possible discovery")
	}

	return nil
}

// ── File access rules ─────────────────────────────────────────────────────────

func checkFileRules(event processor.FileEvent, res workload.ResolveResult) *alert.Alert {
	filename := processor.CString(event.Filename[:])
	comm := processor.CString(event.Comm[:])

	for _, w := range fileCommWhitelist {
		if comm == w {
			return nil
		}
	}

	// T1611 — host process reading container overlay filesystem
	if res.State == workload.StateHost {
		for _, prefix := range containerFSPrefixes {
			if strings.HasPrefix(filename, prefix) {
				return newFileAlert(event, res, comm, filename, alert.Critical, RuleT1611EscapeToHostFs, "Host process accessed container filesystem: "+filename)
			}
		}
		return nil
	}

	// T1611 — container reading host init process (/proc/1/)
	for _, prefix := range t1611ProcEscapePrefixes {
		if strings.HasPrefix(filename, prefix) {
			return newFileAlert(event, res, comm, filename, alert.High, RuleT1611EscapeToHostProc, "Container accessed host process namespace: "+filename)
		}
	}

	// T1552.004 — SSH key directories (CRITICAL — checked before suffix match)
	for _, prefix := range t1552PrivateKeyDirPrefixes {
		if strings.HasPrefix(filename, prefix) {
			return newFileAlert(event, res, comm, filename, alert.Critical, RuleT1552PrivateKeys, "Container accessed SSH credential directory: "+filename)
		}
	}

	// T1003.008 — OS credential dumping (/etc/shadow)
	for _, path := range t1003CredentialDumpPaths {
		if strings.HasPrefix(filename, path) {
			return newFileAlert(event, res, comm, filename, alert.High, RuleT1003OsCredentialDumping, "Container accessed OS credential file: "+filename)
		}
	}

	// T1552.001 — credentials in secret mounts (/run/secrets/)
	for _, prefix := range t1552CredentialFilePrefixes {
		if strings.HasPrefix(filename, prefix) {
			return newFileAlert(event, res, comm, filename, alert.High, RuleT1552CredentialsInFiles, "Container accessed secret mount: "+filename)
		}
	}

	// T1552.004 — private key files by extension (HIGH — after directory check above)
	for _, suffix := range t1552PrivateKeySuffixes {
		if strings.HasSuffix(filename, suffix) {
			if suffix == ".pem" && isPemExcluded(filename) {
				continue
			}
			return newFileAlert(event, res, comm, filename, alert.High, RuleT1552PrivateKeys, "Container accessed private key file: "+filename)
		}
	}

	// T1552.001 — credentials in env files (.env)
	for _, suffix := range t1552CredentialFileSuffixes {
		if strings.HasSuffix(filename, suffix) {
			return newFileAlert(event, res, comm, filename, alert.High, RuleT1552CredentialsInFiles, "Container accessed credential file: "+filename)
		}
	}

	// T1082 — system information discovery (/etc/passwd, /etc/group)
	for _, prefix := range t1082SystemInfoPrefixes {
		if strings.HasPrefix(filename, prefix) {
			return newFileAlert(event, res, comm, filename, alert.Medium, RuleT1082SystemInfoDiscovery, "Container accessed system file: "+filename)
		}
	}

	// T1053.003 — scheduled task/cron: container touching cron config indicates persistence attempt
	for _, prefix := range t1053CronPrefixes {
		if strings.HasPrefix(filename, prefix) {
			return newFileAlert(event, res, comm, filename, alert.High, RuleT1053ScheduledTaskCron, "Container accessed cron configuration: "+filename)
		}
	}

	// T1070.003 — clear command history: container touching shell history files
	for _, suffix := range t1070HistoryFileSuffixes {
		if strings.HasSuffix(filename, suffix) {
			return newFileAlert(event, res, comm, filename, alert.Medium, RuleT1070ClearCommandHistory, "Container accessed command history file: "+filename)
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

	for _, p := range externalAllowedDstPorts {
		if port == p {
			return nil
		}
	}

	for _, allowed := range externalAllowedServices {
		if id.Service == allowed {
			return nil
		}
	}

	return &alert.Alert{
		Level:    alert.High,
		Rule:     RuleT1041ExfiltrationOverC2,
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
