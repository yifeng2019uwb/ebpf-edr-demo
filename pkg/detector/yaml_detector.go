// Package detector implements detection logic for the EDR agent.
// YAMLDetector uses rules loaded from YAML (pkg/rules/loader.go) instead of hardcoded policy.
package detector

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ebpf-edr-demo/internal/alert"
	"ebpf-edr-demo/internal/processor"
	"ebpf-edr-demo/pkg/pipeline"
	"ebpf-edr-demo/pkg/rules"
	"ebpf-edr-demo/pkg/workload"
)

// YAMLDetector implements pipeline.Detector using rules loaded from YAML.
type YAMLDetector struct {
	rules         *rules.RulesDB
	runtime       workload.Runtime  // workload runtime: RuntimeK8s or RuntimeDocker
	safeInfraPIDs map[uint32]string // Layer 1 infrastructure PIDs (passed from resolver)
}

// NewYAMLDetector creates a detector with no runtime awareness.
// Use NewYAMLDetectorWithRuntime for runtime-specific whitelisting.
func NewYAMLDetector(db *rules.RulesDB) *YAMLDetector {
	return &YAMLDetector{rules: db, runtime: ""}
}

// NewYAMLDetectorWithRuntime creates a detector aware of the workload runtime.
// Runtime affects whitelist matching for processes in unknown namespaces.
func NewYAMLDetectorWithRuntime(db *rules.RulesDB, runtime workload.Runtime) *YAMLDetector {
	return &YAMLDetector{rules: db, runtime: runtime}
}

// SetInfrastructurePIDs sets the Layer 1 infrastructure PIDs for pre-filter validation.
// Called by enricher after resolver startup.
func (d *YAMLDetector) SetInfrastructurePIDs(safeInfraPIDs map[uint32]string) {
	d.safeInfraPIDs = safeInfraPIDs
}

// Detect applies rules to the enriched event and returns first matching alert (or nil).
// Design: Return on first match, not all matches — sufficient for current project scope.
// Note: Rule check order matters (CRITICAL → HIGH → MEDIUM → LOW).
// Ensure YAML rules ordered by severity so critical threats are caught first.
func (d *YAMLDetector) Detect(ev pipeline.EnrichedEvent) *alert.Alert {
	if d.rules.IsIgnoredNamespace(ev.Workload.Meta.Namespace) {
		return nil
	}

	// Layer 2 pre-filter: Drop events matching global_exceptions (context-aware whitelist)
	if d.isGloballyExcepted(ev) {
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
	// Check customer_applications (whitelisted apps that should not trigger alerts)
	apps := d.getListStrings("customer_applications")
	for _, w := range apps {
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

func (d *YAMLDetector) isParentInfrastructure(ppid int32) bool {
	// Check if parent PID is in infrastructure PIDs (Layer 1 discovery)
	if d.safeInfraPIDs == nil {
		return false
	}
	_, found := d.safeInfraPIDs[uint32(ppid)]
	return found
}

// getParentPID reads /proc/<pid>/status and returns its parent PID (PPid).
// Returns -1 if the PID is gone or the status file can't be parsed.
func getParentPID(pid int32) int32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return -1
	}
	// /proc/<pid>/status is a text file, one "Key:\tValue" pair per line, e.g.:
	//   Name:   bash
	//   State:  S (sleeping)
	//   Pid:    12345
	//   PPid:   270674
	// We want the PPid line. strings.Fields splits on whitespace/tabs, so for
	// "PPid:\t270674" that gives fields = ["PPid:", "270674"] — fields[1] is the value.
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if ppid, err := strconv.ParseInt(fields[1], 10, 32); err == nil {
					return int32(ppid)
				}
			}
			break
		}
	}
	return -1
}

// isContainerContext enforces that container-specific context is only true for verified containers.
// If state is unknown, we cannot trust container identification, so is_container must be false.
// This prevents rules with container-specific conditions from firing on unresolved processes.
func isContainerContext(res workload.ResolveResult) bool {
	if res.State == workload.StateUnknown {
		return false
	}
	return res.Identity.Runtime == workload.RuntimeDocker || res.Identity.Runtime == workload.RuntimeK8s
}

// isGloballyExcepted checks if event matches any Layer 2 pre-filter exception.
// Gate 1: Validate parent_context (init or infrastructure)
// Gate 2: If no file_prefixes, match on process only (don't require file match)
// Gate 3: Use filepath.Base for suffix matching
func (d *YAMLDetector) isGloballyExcepted(ev pipeline.EnrichedEvent) bool {
	// Extract event data based on type
	var comm string
	var ppid int32
	var filename string

	switch ev.Type {
	case pipeline.ProcessEventType:
		comm = processor.CString(ev.Process.Comm[:])
		ppid = ev.Process.Ppid
	case pipeline.FileEventType:
		comm = processor.CString(ev.File.Comm[:])
		ppid = ev.File.Ppid
		filename = filepath.Clean(processor.CString(ev.File.Filename[:]))
	case pipeline.NetEventType:
		comm = processor.CString(ev.Net.Comm[:])
		ppid = ev.Net.Ppid
	default:
		return false
	}

	baseComm := filepath.Base(comm)

	// Check each global exception
	for _, ex := range d.rules.GlobalExceptions {
		// Match: Process name in process_in list
		if len(ex.ProcessIn) > 0 {
			matched := false
			for _, p := range ex.ProcessIn {
				if baseComm == p {
					matched = true
					break
				}
			}
			if !matched {
				continue // Process doesn't match, skip this exception
			}
		}

		// Match: Parent context (Gate 1)
		if ex.ParentContext != "" {
			switch ex.ParentContext {
			case "init":
				// Must have ppid == 1 (init/systemd)
				if ppid != 1 {
					continue
				}
			case "infrastructure":
				// Must have ppid in safeInfraPIDs
				if d.safeInfraPIDs == nil {
					continue // Infrastructure PIDs not set, skip
				}
				if _, found := d.safeInfraPIDs[uint32(ppid)]; !found {
					continue
				}
			default:
				continue // Unknown parent context
			}
		}

		// Match: File path prefixes (Gate 2 & 3)
		// If no file_prefixes specified, match on process only (Gate 2)
		if len(ex.FilePrefixes) == 0 {
			// No file prefixes specified, process match is sufficient
			return true
		}

		// File prefixes specified: only enforce for file events
		if filename == "" {
			// Not a file event, but file_prefixes specified - skip this exception
			continue
		}

		// Check if filename matches any prefix (Gate 3: use base for suffix matching)
		matchedFile := false
		for _, prefix := range ex.FilePrefixes {
			// Use filepath.Base for suffix-style matching (e.g., ".bash_history")
			if strings.HasPrefix(prefix, ".") {
				// Suffix pattern: match against base filename
				if strings.HasSuffix(filepath.Base(filename), prefix) {
					matchedFile = true
					break
				}
			} else {
				// Path prefix: match against full path
				if strings.HasPrefix(filename, prefix) {
					matchedFile = true
					break
				}
			}
		}

		if !matchedFile {
			continue // File doesn't match, skip this exception
		}

		// All criteria matched, drop event
		return true
	}

	return false
}

// ── Process rules ─────────────────────────────────────────────────────────────

func (d *YAMLDetector) checkProcessRules(event processor.ProcessEvent, res workload.ResolveResult) *alert.Alert {
	comm := processor.CString(event.Comm[:])

	// System services spawned by init (ppid=1) are trusted infrastructure
	if event.Ppid == 1 {
		return nil
	}

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
		// Initialization context (ppid=1, shell scripts) handled by global_exceptions pre-filter.
		// Remaining StateUnknown processes are checked below.

		// Structural fix: If parent is known infrastructure daemon, suppress alert
		// (it's legitimate docker lifecycle operation, not escape attempt)
		// This avoids maintaining an endless blocklist of utility names
		if d.isParentInfrastructure(event.Ppid) {
			log.Printf("DEBUG: Suppressing state=unknown process %s (ppid %d in infrastructure)", comm, event.Ppid)
			return nil
		}

		base := filepath.Base(comm)

		// Load whitelists from YAML rules
		universalTools := d.getListStrings("universal_system_tools")
		k8sInfra := d.getListStrings("k8s_infrastructure_procs")
		systemTools := d.getListStrings("system_container_detection_tools")
		procFdPatterns := d.getListStrings("proc_fd_patterns")
		runtimeExecs := d.getListStrings("container_runtime_execs")
		netMgmtTools := d.getListStrings("network_management_tools")
		dockerLifecycleTools := d.getListStrings("docker_lifecycle_tools")

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

		// K8s infrastructure only safe in K8s
		if d.runtime == workload.RuntimeK8s {
			for _, w := range k8sInfra {
				if base == w {
					return nil
				}
			}
		}

		// Check whitelisted_processes (infrastructure + customer apps)
		if d.isWhitelisted(comm) {
			return nil
		}

		// Stage 1: Core container runtime tools — always drop when state=unknown
		// These ARE infrastructure, can never be attacker-spawned
		for _, w := range runtimeExecs {
			if base == w {
				log.Printf("DEBUG: Stage 1 - Core runtime tool always dropped: %s (pid %d)", base, event.Pid)
				return nil
			}
		}

		// Stage 2: Dynamic lifecycle utilities — only drop if spawned by verified infrastructure
		// Transient tools (grep, sleep, wget, curl, etc.) used during docker operations
		// Only suppress if parent process is a known infrastructure daemon
		isTransientTool := false
		for _, w := range netMgmtTools {
			if base == w {
				isTransientTool = true
				break
			}
		}
		if !isTransientTool {
			for _, w := range dockerLifecycleTools {
				if base == w {
					isTransientTool = true
					break
				}
			}
		}

		if isTransientTool {
			// Read parent process name from /proc/ppid/comm to verify infrastructure context
			pcommPath := fmt.Sprintf("/proc/%d/comm", event.Ppid)
			if pcommData, err := os.ReadFile(pcommPath); err == nil {
				parentComm := strings.TrimSpace(string(pcommData))

				// Suppress if parent is a known infrastructure daemon
				if parentComm == "dockerd" || parentComm == "containerd" || parentComm == "snap" {
					log.Printf("DEBUG: Stage 2 - Transient tool dropped (parent is infrastructure): %s (ppid %d parent=%s)", base, event.Ppid, parentComm)
					return nil
				}

				// Also check if parent is a core runtime executable (runc, containerd-shim, docker-proxy)
				for _, w := range runtimeExecs {
					if parentComm == w {
						log.Printf("DEBUG: Stage 2 - Transient tool dropped (parent is core runtime): %s (ppid %d parent=%s)", base, event.Ppid, parentComm)
						return nil
					}
				}

				// Parent is a mid-layer shell (e.g. a health-check script run by containerd-shim).
				// Check the shell's own parent (grandparent) against Layer 1 infrastructure PIDs.
				if parentComm == "bash" || parentComm == "sh" || parentComm == "dash" || parentComm == "zsh" {
					grandppid := getParentPID(event.Ppid)
					if grandppid > 0 && d.isParentInfrastructure(grandppid) {
						log.Printf("DEBUG: Stage 2 - Transient tool dropped (shell parent's grandparent is infrastructure): %s (ppid %d parent=%s grandppid %d)", base, event.Ppid, parentComm, grandppid)
						return nil
					}
					log.Printf("DEBUG: Stage 2 - Transient tool NOT dropped (shell parent's grandparent not infrastructure): %s (ppid %d parent=%s grandppid %d)", base, event.Ppid, parentComm, grandppid)
				} else {
					// Parent process is not verified infrastructure — alert (secure fail)
					log.Printf("DEBUG: Stage 2 - Transient tool NOT dropped (parent not verified): %s (ppid %d parent=%s)", base, event.Ppid, parentComm)
				}
			} else {
				// Parent PID already exited (can't verify) — secure fail, alert
				log.Printf("DEBUG: Stage 2 - Transient tool NOT dropped (parent PID gone): %s (ppid %d, err=%v)", base, event.Ppid, err)
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

	// Container context gating: only apply container-specific rules if state is VERIFIED (not unknown)
	isVerifiedContainer := isContainerContext(res)

	if isVerifiedContainer && d.matchesSuffix(comm, "shell_processes") {
		return newProcessAlert(event, res, comm, alert.Critical, RuleT1059UnixShellExecution, "Shell spawned from container — possible RCE")
	}

	if isVerifiedContainer && d.matchesSuffix(comm, "network_tools") {
		return newProcessAlert(event, res, comm, alert.High, RuleT1105IngressToolTransfer, "Network tool executed from container — possible exfiltration or tool staging")
	}

	if isVerifiedContainer && d.matchesSuffix(comm, "container_mgmt_tools") {
		return newProcessAlert(event, res, comm, alert.High, RuleT1613ContainerDiscovery, "Container management tool executed inside container — possible discovery")
	}

	return nil
}

// ── File access rules ─────────────────────────────────────────────────────────

func (d *YAMLDetector) checkFileRules(event processor.FileEvent, res workload.ResolveResult) *alert.Alert {
	filename := processor.CString(event.Filename[:])
	comm := processor.CString(event.Comm[:])

	// System services spawned by init (ppid=1) are trusted infrastructure
	if event.Ppid == 1 {
		return nil
	}

	fileCommWhitelist := d.getListStrings("whitelisted_file_access_procs")
	base := filepath.Base(comm)
	for _, w := range fileCommWhitelist {
		if base == w || comm == w {
			return nil
		}
	}

	// Check whitelisted_processes (infrastructure + customer apps)
	if d.isWhitelisted(comm) {
		return nil
	}

	// Container context gating: only apply container-specific rules if state is VERIFIED (not unknown)
	// This prevents state=unknown processes from triggering container-only detections
	isVerifiedContainer := isContainerContext(res)

	// T1611 — host process reading container overlay filesystem
	// if res.Identity.Runtime == workload.RuntimeHost {
	// 	containerFSPaths := d.getListStrings("container_fs_paths")
	// 	for _, prefix := range containerFSPaths {
	// 		if strings.HasPrefix(filename, prefix) {
	// 			return newFileAlert(event, res, comm, filename, alert.Critical, RuleT1611EscapeToHostFs, "Host process accessed container filesystem: "+filename)
	// 		}
	// 	}
	// 	return nil
	// }

	// T1611 — container reading host init process (/proc/1/)
	// Only alert if we can verify this is a container process (state != unknown)
	if isVerifiedContainer {
		procEscapePaths := d.getListStrings("proc_escape_paths")
		for _, prefix := range procEscapePaths {
			if strings.HasPrefix(filename, prefix) && !d.isProcEscapeAllowed(filename) {
				return newFileAlert(event, res, comm, filename, alert.High, RuleT1611EscapeToHostProc, "Container accessed host process namespace: "+filename)
			}
		}
	}

	// T1552.004 — SSH key directories (CRITICAL)
	// Only alert if we can verify this is a container process (state != unknown)
	if isVerifiedContainer && !d.isWhitelisted(comm) {
		sshKeyDirs := d.getListStrings("ssh_key_dirs")
		for _, prefix := range sshKeyDirs {
			if strings.HasPrefix(filename, prefix) {
				return newFileAlert(event, res, comm, filename, alert.Critical, RuleT1552PrivateKeys, "Container accessed SSH credential directory: "+filename)
			}
		}
	}

	// T1003.008 — OS credential dumping (/etc/shadow)
	// Only alert if we can verify this is a container process (state != unknown)
	if isVerifiedContainer && !d.isWhitelisted(comm) {
		shadowPaths := d.getListStrings("credential_dump_paths")
		for _, path := range shadowPaths {
			if strings.HasPrefix(filename, path) {
				return newFileAlert(event, res, comm, filename, alert.Critical, RuleT1003OsCredentialDumping, "Container accessed OS credential file: "+filename)
			}
		}
	}

	// T1552.001 — credentials in secret mounts (/run/secrets/)
	// Only alert if we can verify this is a container process
	if isVerifiedContainer && !d.isWhitelisted(comm) {
		credFileDirs := d.getListStrings("credential_file_dirs")
		for _, prefix := range credFileDirs {
			if strings.HasPrefix(filename, prefix) {
				return newFileAlert(event, res, comm, filename, alert.High, RuleT1552CredentialsInFiles, "Container accessed secret mount: "+filename)
			}
		}
	}

	// T1552.004 — private key files by extension
	// Only alert if we can verify this is a container process
	if isVerifiedContainer && !d.isWhitelisted(comm) {
		sshKeySuffixes := d.getListStrings("ssh_key_suffixes")
		for _, suffix := range sshKeySuffixes {
			if strings.HasSuffix(filename, suffix) {
				if suffix == ".pem" && d.isPemExcluded(filename) {
					continue
				}
				return newFileAlert(event, res, comm, filename, alert.High, RuleT1552PrivateKeys, "Container accessed private key file: "+filename)
			}
		}
	}

	// T1552.001 — credentials in env files (.env)
	// Only alert if we can verify this is a container process
	if isVerifiedContainer && !d.isWhitelisted(comm) {
		credSuffixes := d.getListStrings("credential_file_suffixes")
		for _, suffix := range credSuffixes {
			if strings.HasSuffix(filename, suffix) {
				return newFileAlert(event, res, comm, filename, alert.High, RuleT1552CredentialsInFiles, "Container accessed credential file: "+filename)
			}
		}
	}

	// T1082 — system information discovery (/etc/passwd, /etc/group)
	// Only alert if we can verify this is a container process
	if isVerifiedContainer {
		systemFiles := d.getListStrings("system_info_paths")
		for _, prefix := range systemFiles {
			if strings.HasPrefix(filename, prefix) {
				return newFileAlert(event, res, comm, filename, alert.Medium, RuleT1082SystemInfoDiscovery, "Container accessed system file: "+filename)
			}
		}
	}

	// T1053.003 — scheduled task/cron
	// Only alert if we can verify this is a container process
	if isVerifiedContainer {
		cronPaths := d.getListStrings("cron_paths")
		for _, prefix := range cronPaths {
			if strings.HasPrefix(filename, prefix) {
				return newFileAlert(event, res, comm, filename, alert.High, RuleT1053ScheduledTaskCron, "Container accessed cron configuration: "+filename)
			}
		}
	}

	// T1070.003 — clear command history
	// Only alert if we can verify this is a container process
	if isVerifiedContainer {
		historySuffixes := d.getListStrings("shell_history_suffixes")
		for _, suffix := range historySuffixes {
			if strings.HasSuffix(filename, suffix) {
				return newFileAlert(event, res, comm, filename, alert.Medium, RuleT1070ClearCommandHistory, "Container accessed command history file: "+filename)
			}
		}
	}

	return nil
}

// ── Network rules ─────────────────────────────────────────────────────────────

func (d *YAMLDetector) checkNetworkRules(event processor.NetEvent, res workload.ResolveResult, ip net.IP, port uint16) *alert.Alert {

	if d.isPrivateIP(ip) {
		return nil
	}

	comm := processor.CString(event.Comm[:])
	ipStr := ip.String()
	id := res.Identity

	// Container context gating: only apply container-specific rules if state is VERIFIED (not unknown)
	isVerifiedContainer := isContainerContext(res)
	if !isVerifiedContainer {
		return nil
	}

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
