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

// ancestryWalkMaxDepth bounds how far isParentTrusted climbs the ancestry chain.
// The walk only continues through shells, so real chains (sshd → bash → script →
// util) are shallow; the cap is a safety valve against PID-reuse cycles.
const ancestryWalkMaxDepth = 10

// YAMLDetector implements pipeline.Detector using rules loaded from YAML.
type YAMLDetector struct {
	rules              *rules.RulesDB
	runtime            workload.Runtime  // workload runtime: RuntimeK8s or RuntimeDocker
	safeInfraPIDs      map[uint32]string // Layer 1 infrastructure PIDs (passed from resolver)
	ancestry           *AncestryCache    // live pid → exec record, for parent verification
	trustedParentNames map[string]bool   // precomputed from trusted_parent_names (hot path)
	suspiciousPrefixes []string          // precomputed from suspicious_exec_paths (writable-location denylist)
	shellNames         map[string]bool   // precomputed from shell_processes (hot path)
}

// NewYAMLDetector creates a detector with no runtime awareness.
// Use NewYAMLDetectorWithRuntime for runtime-specific whitelisting.
func NewYAMLDetector(db *rules.RulesDB) *YAMLDetector {
	return NewYAMLDetectorWithRuntime(db, "")
}

// NewYAMLDetectorWithRuntime creates a detector aware of the workload runtime.
// Runtime affects whitelist matching for processes in unknown namespaces.
func NewYAMLDetectorWithRuntime(db *rules.RulesDB, runtime workload.Runtime) *YAMLDetector {
	d := &YAMLDetector{rules: db, runtime: runtime}
	// Rules are immutable after load; precompute the hot-path lookups once.
	d.trustedParentNames = make(map[string]bool)
	for _, item := range db.GetList("trusted_parent_names") {
		if s, ok := item.(string); ok {
			d.trustedParentNames[s] = true
		}
	}
	d.shellNames = make(map[string]bool)
	for _, item := range db.GetList("shell_processes") {
		if s, ok := item.(string); ok {
			d.shellNames[s] = true
		}
	}
	// Anti-spoof path validation (env-agnostic): rather than allowlisting per-distro
	// system dirs, we denylist attacker-writable locations. Precompute the list once.
	d.suspiciousPrefixes = d.getListStrings("suspicious_exec_paths")
	return d
}

// SetInfrastructurePIDs sets the Layer 1 infrastructure PIDs for pre-filter validation.
// Called by enricher after resolver startup.
func (d *YAMLDetector) SetInfrastructurePIDs(safeInfraPIDs map[uint32]string) {
	d.safeInfraPIDs = safeInfraPIDs
}

// SetAncestryCache attaches the live process ancestry cache used for
// parent verification. Without it, parent checks fall back to the static
// Layer 1 PIDs only.
func (d *YAMLDetector) SetAncestryCache(c *AncestryCache) {
	d.ancestry = c
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

func (d *YAMLDetector) isParentInfrastructure(ppid int32) bool {
	// Check if parent PID is in infrastructure PIDs (Layer 1 discovery)
	if d.safeInfraPIDs == nil {
		return false
	}
	_, found := d.safeInfraPIDs[uint32(ppid)]
	return found
}

// resolveParent returns a pid's exec record, preferring the live ancestry cache
// (race-free, exec-time data) and falling back to a direct /proc read for the
// fork-without-exec gap (DESIGN §3.4). The fallback reads /proc/<pid>/exe (the full
// binary path) rather than /proc/<pid>/comm (a bare 15-char name) so the trusted-prefix
// anti-spoof check still applies. It only succeeds while the parent is alive, so a
// dead + uncached parent stays unresolvable (routed as noise, DESIGN §3.6).
func (d *YAMLDetector) resolveParent(pid uint32) (AncestryEntry, bool) {
	if d.ancestry != nil {
		if e, ok := d.ancestry.Lookup(pid); ok {
			return e, true
		}
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return AncestryEntry{}, false
	}
	return AncestryEntry{Ppid: procPPid(pid), ExecPath: exe}, true
}

// isParentTrusted reports whether ppid's ancestry roots in verified infrastructure.
// It walks up the chain (Falco proc.aname-style — a trusted *ancestor*, not just the
// direct parent), returning trusted as soon as any ancestor is:
//  1. in safeInfraPIDs (persistent daemon discovered at startup), or
//  2. a trusted exec path — base name in trusted_parent_names AND path under a Layer 1
//     trusted prefix (blocks /tmp/dockerd spoofing).
//
// It only keeps climbing through shells: a non-shell, non-trusted ancestor is a hard
// stop (that binary is where arbitrary code could have taken over — we do not credit a
// trusted grandparent through it). This catches deep host-session chains
// (sshd → bash → script → grep) while a chain rooted in a non-infra parent still fails.
//
// Ancestor identity comes from the ancestry cache (exec-time data, survives the parent
// exiting), with a /proc/<pid>/exe fallback on cache miss (resolveParent). A broken
// chain (dead + uncached ancestor) is unresolvable → caller routes it to §3.6 noise.
// Safety is a property of who spawned the process, not what it is called.
// Design: docs/DESIGN-PROCESS-ANCESTRY-CACHE.md §3.5
func (d *YAMLDetector) isParentTrusted(ppid int32) bool {
	pid := uint32(ppid)
	for range ancestryWalkMaxDepth {
		if d.isParentInfrastructure(int32(pid)) {
			return true
		}
		entry, ok := d.resolveParent(pid)
		if !ok {
			return false // chain broke — unresolvable ancestor
		}
		if d.isTrustedParentExec(entry.ExecPath) {
			return true
		}
		// Only climb through shells; a non-shell, non-trusted ancestor is not infra-rooted.
		if !d.shellNames[filepath.Base(entry.ExecPath)] {
			return false
		}
		if entry.Ppid == 0 || entry.Ppid == pid {
			return false // reached the top / self-cycle
		}
		pid = entry.Ppid
	}
	return false
}

// isTrustedParentExec reports whether an exec-time path names a trusted parent:
// base name in trusted_parent_names AND full path under a Layer 1 trusted prefix.
func (d *YAMLDetector) isTrustedParentExec(execPath string) bool {
	if !d.trustedParentNames[filepath.Base(execPath)] {
		return false
	}
	return d.hasTrustedInfraPrefix(execPath)
}

// hasTrustedInfraPrefix reports whether an exec path is in a trusted (non-writable)
// location. Env-agnostic by design: instead of allowlisting per-distro system dirs
// (/usr/bin vs /var/lib/minikube/bin vs /opt/... — different on every runtime), it
// rejects only attacker-writable locations (suspicious_exec_paths: /tmp, /dev/shm,
// /var/tmp, /run/user). A real daemon lives somewhere normal on every distro; a
// spoofed /tmp/dockerd does not. Same anti-spoof intent, zero per-env maintenance.
func (d *YAMLDetector) hasTrustedInfraPrefix(execPath string) bool {
	if !strings.HasPrefix(execPath, "/") {
		return false // must be an absolute path
	}
	for _, p := range d.suspiciousPrefixes {
		if strings.HasPrefix(execPath, p) {
			return false
		}
	}
	return true
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
				// Verified via static Layer 1 PIDs or the live ancestry cache
				// (covers post-startup daemon instances and shell-mediated spawns)
				if !d.isParentTrusted(ppid) {
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

		// FIX: If it's a process event, we don't validate file prefixes.
		// The process/parent match above is sufficient to whitelist the execution itself.
		if ev.Type == pipeline.ProcessEventType {
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
		// Initialization context (ppid=1, shell scripts) is handled by the
		// global_exceptions pre-filter; remaining state=unknown processes are here.

		// Primary suppression: a verified-infrastructure parent chain (static Layer 1
		// PID, or a post-startup daemon / shell-mediated spawn resolved via the ancestry
		// cache or /proc fallback) means legitimate lifecycle activity, not an escape.
		// Parent-based and name-agnostic — safety is who spawned the process, not what
		// it is called (closes the "attacker renames their tool to curl" gap).
		if d.isParentTrusted(event.Ppid) {
			// log.Printf("DEBUG: Suppressing state=unknown process %s (ppid %d has trusted ancestry)", comm, event.Ppid)
			return nil
		}

		// eBPF capture artifacts, not real executions: /proc/*/fd/* symlink reads and
		// the `fd` universal tool. Not a security decision, so still matched by name.
		for _, pattern := range d.getListStrings("proc_fd_patterns") {
			if matched, _ := filepath.Match(pattern, comm); matched {
				return nil
			}
		}
		base := filepath.Base(comm)
		for _, w := range d.getListStrings("universal_system_tools") {
			if base == w {
				return nil
			}
		}

		// Phase 3 (§3.6): the namespace never resolved AND the ancestry chain could not
		// be verified as infrastructure. Falco-aligned — absence of identity is a
		// visibility gap, not an escape. Emit LOW telemetry (still reaches the log /
		// dashboard / Supabase as a validation breadcrumb) instead of a CRITICAL false
		// positive. Print the full context so unresolved cases stay visible for tuning.
		// log.Printf("DEBUG: unresolved state=unknown %s (pid %d ppid %d uid %d): ancestry not infra-rooted — routed to LOW telemetry",
		// 	comm, event.Pid, event.Ppid, event.Uid)
		return newProcessAlert(event, res, comm, alert.Low, RuleEDRTelemetryUnresolvedNamespace, "EDR visibility gap: process in unresolved namespace")
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
