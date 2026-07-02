// Package detector implements detection logic for the EDR agent.
// YAMLDetector uses rules loaded from YAML (pkg/rules/loader.go) instead of hardcoded policy.
package detector

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"ebpf-edr-demo/internal/alert"
	"ebpf-edr-demo/internal/processor"
	"ebpf-edr-demo/pkg/pipeline"
	"ebpf-edr-demo/pkg/rules"
	"ebpf-edr-demo/pkg/workload"
)

// Known process names that indicate initialization context (shell scripts, init systems)
var initializationProcs = map[string]bool{
	"sh":       true, // POSIX shell
	"bash":     true,
	"dash":     true, // Debian default shell
	"ksh":      true, // Korn shell
	"zsh":      true,
	"init":     true, // System init
	"systemd":  true,
	"runit":    true,
	"s6-init":  true,
}

// YAMLDetector implements pipeline.Detector using rules loaded from YAML.
type YAMLDetector struct {
	rules *rules.RulesDB
	env   string // detected environment: "k8s", "docker", "bare-metal", etc.
}

// NewYAMLDetector creates a detector with no environment awareness.
// Use NewYAMLDetectorWithEnv for environment-specific whitelisting.
func NewYAMLDetector(db *rules.RulesDB) *YAMLDetector {
	return &YAMLDetector{rules: db, env: ""}
}

// NewYAMLDetectorWithEnv creates a detector aware of the deployment environment.
// env: detected environment ("k8s", "docker", "bare-metal", "unknown")
// Environment affects whitelist matching for processes in unknown namespaces.
func NewYAMLDetectorWithEnv(db *rules.RulesDB, env string) *YAMLDetector {
	return &YAMLDetector{rules: db, env: env}
}

// Detect applies rules to the enriched event and returns first matching alert (or nil).
// Design: Return on first match, not all matches — sufficient for current project scope.
// Note: Rule check order matters (CRITICAL → HIGH → MEDIUM → LOW).
// Ensure YAML rules ordered by severity so critical threats are caught first.
func (d *YAMLDetector) Detect(ev pipeline.EnrichedEvent) *alert.Alert {
	// Single debug trace to verify events flowing through pipeline
	if ev.Type == pipeline.FileEventType {
		fmt.Printf("DEBUG: file event file=%s\n", processor.CString(ev.File.Filename[:]))
	}

	if d.rules.IsIgnoredNamespace(ev.Workload.Meta.Namespace) {
		return nil
	}

	var a *alert.Alert

	switch ev.Type {
	case pipeline.ProcessEventType:
		a = d.checkProcessRules(*ev.Process, ev.Workload)

	case pipeline.FileEventType:
		a = d.checkFileRules(*ev.File, ev.Workload)

	case pipeline.NetEventType:
		ip := processor.NetIP(ev.Net.DstIp)
		port := processor.NetPort(ev.Net.DstPort)
		a = d.checkNetworkRules(*ev.Net, ev.Workload, ip, port)
	}

	return a
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (d *YAMLDetector) getListStrings(name string) []string {
	items := d.rules.GetList(name)
	if items == nil {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

func (d *YAMLDetector) matchesSuffix(comm string, listName string) bool {
	list := d.getListStrings(listName)
	for _, s := range list {
		if strings.HasSuffix(comm, s) {
			return true
		}
	}
	return false
}

func (d *YAMLDetector) isProcEscapeAllowed(filename string) bool {
	allowed := d.getListStrings("proc_escape_allowed")
	for _, path := range allowed {
		if filename == path {
			return true
		}
	}
	return false
}

func (d *YAMLDetector) isPemExcluded(filename string) bool {
	excluded := d.getListStrings("pem_exclude_paths")
	for _, path := range excluded {
		if strings.Contains(filename, path) {
			return true
		}
	}
	return false
}

func (d *YAMLDetector) isWhitelisted(comm string) bool {
	base := filepath.Base(comm)
	whitelist := d.getListStrings("whitelisted_processes")
	for _, w := range whitelist {
		if base == w {
			return true
		}
	}
	return false
}

func (d *YAMLDetector) isPrivateIP(ip net.IP) bool {
	// Parse private_ranges list from YAML
	ranges := d.getListStrings("private_ranges")
	for _, cidr := range ranges {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func getParentComm(ppid int32) string {
	// Read parent's executable name from /proc/[ppid]/comm
	// Used to detect initialization context (shell scripts, init processes)
	path := fmt.Sprintf("/proc/%d/comm", ppid)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func isInitializationProcess(comm string) bool {
	base := filepath.Base(comm)
	return initializationProcs[base]
}

// ── Process rules ─────────────────────────────────────────────────────────────

func (d *YAMLDetector) checkProcessRules(event processor.ProcessEvent, res workload.ResolveResult) *alert.Alert {
	// Host processes are trusted — skip all rules without extracting comm.
	if res.State == workload.StateHost {
		return nil
	}

	comm := processor.CString(event.Comm[:])

	// T1036 — masquerading: checked BEFORE whitelist
	t1036Paths := d.getListStrings("suspicious_exec_paths")
	for _, prefix := range t1036Paths {
		if strings.HasPrefix(comm, prefix) {
			return newProcessAlert(event, res, comm, alert.High, RuleT1036Masquerading, "Process running from suspicious path: "+comm)
		}
	}

	if d.isWhitelisted(comm) {
		return nil
	}

	if res.State == workload.StateUnknown {
		// Check if parent process is an initialization context (shell script, init, etc.)
		// If so, this process is likely part of container startup, not an escape attempt
		parentComm := getParentComm(event.Ppid)
		if isInitializationProcess(parentComm) {
			return nil
		}

		base := filepath.Base(comm)

		// Load whitelists from YAML rules
		universalTools := d.getListStrings("universal_system_tools")
		k8sInfra := d.getListStrings("k8s_infrastructure_procs")
		systemTools := d.getListStrings("system_container_detection_tools")
		procFdPatterns := d.getListStrings("proc_fd_patterns")

		// Check if process is whitelisted (using environment-aware logic)
		// eBPF artifacts: /proc/*/fd/* patterns (symlink resolution artifacts)
		for _, pattern := range procFdPatterns {
			// Use filepath.Match for glob patterns (* matches any sequence)
			if matched, _ := filepath.Match(pattern, comm); matched {
				return nil
			}
		}

		for _, w := range universalTools {
			if base == w {
				return nil
			}
		}

		// Environment-specific: K8s infrastructure only safe in K8s
		if d.env == "k8s" || d.env == "digitalocean" {
			for _, w := range k8sInfra {
				if base == w {
					return nil
				}
			}
		}

		// Medium confidence: system detection tools (any environment)
		for _, w := range systemTools {
			if base == w {
				return newProcessAlert(event, res, comm, alert.Medium, RuleT1611EscapeToHostNs, "System tool in unrecognized namespace — potential reconnaissance")
			}
		}

		// Unknown process in unknown namespace: likely escape attempt
		return newProcessAlert(event, res, comm, alert.Critical, RuleT1611EscapeToHostNs, "Process in unrecognized namespace — possible container escape")
	}

	if d.matchesSuffix(comm, "shell_processes") {
		return newProcessAlert(event, res, comm, alert.Critical, RuleT1059UnixShellExecution, "Shell spawned from container — possible RCE")
	}

	if d.matchesSuffix(comm, "network_tools") {
		return newProcessAlert(event, res, comm, alert.High, RuleT1105IngressToolTransfer, "Network tool executed from container — possible exfiltration or tool staging")
	}

	if d.matchesSuffix(comm, "container_mgmt_tools") {
		return newProcessAlert(event, res, comm, alert.High, RuleT1613ContainerDiscovery, "Container management tool executed inside container — possible discovery")
	}

	return nil
}

// ── File access rules ─────────────────────────────────────────────────────────

func (d *YAMLDetector) checkFileRules(event processor.FileEvent, res workload.ResolveResult) *alert.Alert {
	filename := processor.CString(event.Filename[:])
	comm := processor.CString(event.Comm[:])

	fileCommWhitelist := d.getListStrings("whitelisted_file_access_procs")
	for _, w := range fileCommWhitelist {
		if comm == w {
			return nil
		}
	}

	// T1611 — host process reading container overlay filesystem
	if res.State == workload.StateHost {
		containerFSPaths := d.getListStrings("container_fs_paths")
		for _, prefix := range containerFSPaths {
			if strings.HasPrefix(filename, prefix) {
				return newFileAlert(event, res, comm, filename, alert.Critical, RuleT1611EscapeToHostFs, "Host process accessed container filesystem: "+filename)
			}
		}
		return nil
	}

	// T1611 — container reading host init process (/proc/1/)
	procEscapePaths := d.getListStrings("proc_escape_paths")
	for _, prefix := range procEscapePaths {
		if strings.HasPrefix(filename, prefix) && !d.isProcEscapeAllowed(filename) {
			return newFileAlert(event, res, comm, filename, alert.High, RuleT1611EscapeToHostProc, "Container accessed host process namespace: "+filename)
		}
	}

	// T1552.004 — SSH key directories (CRITICAL)
	sshKeyDirs := d.getListStrings("ssh_key_dirs")
	for _, prefix := range sshKeyDirs {
		if strings.HasPrefix(filename, prefix) {
			return newFileAlert(event, res, comm, filename, alert.Critical, RuleT1552PrivateKeys, "Container accessed SSH credential directory: "+filename)
		}
	}

	// T1003.008 — OS credential dumping (/etc/shadow)
	shadowPaths := d.getListStrings("credential_dump_paths")
	for _, path := range shadowPaths {
		if strings.HasPrefix(filename, path) {
			return newFileAlert(event, res, comm, filename, alert.Critical, RuleT1003OsCredentialDumping, "Container accessed OS credential file: "+filename)
		}
	}

	// T1552.001 — credentials in secret mounts (/run/secrets/)
	credFileDirs := d.getListStrings("credential_file_dirs")
	for _, prefix := range credFileDirs {
		if strings.HasPrefix(filename, prefix) {
			return newFileAlert(event, res, comm, filename, alert.High, RuleT1552CredentialsInFiles, "Container accessed secret mount: "+filename)
		}
	}

	// T1552.004 — private key files by extension
	sshKeySuffixes := d.getListStrings("ssh_key_suffixes")
	for _, suffix := range sshKeySuffixes {
		if strings.HasSuffix(filename, suffix) {
			if suffix == ".pem" && d.isPemExcluded(filename) {
				continue
			}
			return newFileAlert(event, res, comm, filename, alert.High, RuleT1552PrivateKeys, "Container accessed private key file: "+filename)
		}
	}

	// T1552.001 — credentials in env files (.env)
	credSuffixes := d.getListStrings("credential_file_suffixes")
	for _, suffix := range credSuffixes {
		if strings.HasSuffix(filename, suffix) {
			return newFileAlert(event, res, comm, filename, alert.High, RuleT1552CredentialsInFiles, "Container accessed credential file: "+filename)
		}
	}

	// T1082 — system information discovery (/etc/passwd, /etc/group)
	systemFiles := d.getListStrings("system_info_paths")
	for _, prefix := range systemFiles {
		if strings.HasPrefix(filename, prefix) {
			return newFileAlert(event, res, comm, filename, alert.Medium, RuleT1082SystemInfoDiscovery, "Container accessed system file: "+filename)
		}
	}

	// T1053.003 — scheduled task/cron
	cronPaths := d.getListStrings("cron_paths")
	for _, prefix := range cronPaths {
		if strings.HasPrefix(filename, prefix) {
			return newFileAlert(event, res, comm, filename, alert.High, RuleT1053ScheduledTaskCron, "Container accessed cron configuration: "+filename)
		}
	}

	// T1070.003 — clear command history
	historySuffixes := d.getListStrings("shell_history_suffixes")
	for _, suffix := range historySuffixes {
		if strings.HasSuffix(filename, suffix) {
			return newFileAlert(event, res, comm, filename, alert.Medium, RuleT1070ClearCommandHistory, "Container accessed command history file: "+filename)
		}
	}

	return nil
}

// ── Network rules ─────────────────────────────────────────────────────────────

func (d *YAMLDetector) checkNetworkRules(event processor.NetEvent, res workload.ResolveResult, ip net.IP, port uint16) *alert.Alert {
	if res.State == workload.StateHost {
		return nil
	}

	if d.isPrivateIP(ip) {
		return nil
	}

	comm := processor.CString(event.Comm[:])
	ipStr := ip.String()
	id := res.Identity

	// Check allowed ports
	for _, p := range d.rules.Network.AllowedPorts {
		if port == p {
			return nil
		}
	}

	// Check allowed services
	for _, allowed := range d.rules.Network.AllowedServices {
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

// ── Alert Constructors ────────────────────────────────────────────────────────

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
