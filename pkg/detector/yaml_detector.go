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
	runtime            workload.Runtime    // workload runtime: RuntimeK8s or RuntimeDocker
	safeInfraPIDs      map[uint32]string   // Layer 1 infrastructure PIDs (passed from resolver)
	ancestry           *AncestryCache      // live pid → exec record, for parent verification
	trustedParentNames map[string]bool     // precomputed from trusted_parent_names (hot path)
	suspiciousPrefixes []string            // precomputed from suspicious_exec_paths (writable-location denylist)
	shellNames         map[string]bool     // precomputed from shell_processes (hot path)
	processDetections  []compiledDetection // structured process rules (rules/process.yaml, ordered)
	fileDetections     []compiledDetection // structured file rules (rules/file.yaml, ordered)
	netDetections      []compiledDetection // structured network rules (rules/network.yaml, ordered)
}

// matchInput carries the event attributes a structured detection can match on.
// Unset fields are the zero value (filename "" for process events, dstIP nil
// for non-network events), and their primitives then never match.
type matchInput struct {
	comm     string
	filename string
	dstIP    net.IP
	dstPort  uint16
	service  string
	hasTty   bool   // process events only — controlling terminal attached
	args     string // process events only — argv[1:], raw bytes (fixed NUL-padded slots;
	// deliberately not CString-trimmed — a raw Contains search still finds a
	// substring in any slot, embedded NULs don't affect it)
}

// compiledMatch is a MatchSpec with its list references resolved to lookup
// structures (rules are immutable after load, so this is done once — including
// CIDR parsing, which the old per-event isPrivateIP re-did on every packet).
// All non-empty primitives must match (AND); an empty match matches nothing.
type compiledMatch struct {
	commSuffixes []string        // comm_suffix_in
	commBases    map[string]bool // comm_base_in
	commPrefixes []string        // comm_prefix_in
	filePrefixes []string        // file_prefix_in
	fileSuffixes []string        // file_suffix_in
	fileExacts   map[string]bool // file_exact_in
	fileContains []string        // file_contains_in
	dstIPNotIn   []*net.IPNet    // dst_ip_not_in (match = IP outside every range)
	dstPorts     map[uint16]bool // dst_port_in
	services     map[string]bool // service_in
	requireTty   bool            // tty_required
	argsContains []string        // args_contains_in
}

func (m *compiledMatch) empty() bool {
	return len(m.commSuffixes) == 0 && len(m.commBases) == 0 && len(m.commPrefixes) == 0 &&
		len(m.filePrefixes) == 0 && len(m.fileSuffixes) == 0 && len(m.fileExacts) == 0 &&
		len(m.fileContains) == 0 && len(m.dstIPNotIn) == 0 && len(m.dstPorts) == 0 &&
		len(m.services) == 0 && !m.requireTty && len(m.argsContains) == 0
}

// matches reports whether the event satisfies every specified primitive.
func (m *compiledMatch) matches(in matchInput) bool {
	if m.empty() {
		return false
	}
	if len(m.commSuffixes) > 0 && !hasAnySuffix(in.comm, m.commSuffixes) {
		return false
	}
	if len(m.commBases) > 0 && !m.commBases[filepath.Base(in.comm)] {
		return false
	}
	if len(m.commPrefixes) > 0 && !hasAnyPrefix(in.comm, m.commPrefixes) {
		return false
	}
	if len(m.filePrefixes) > 0 && !hasAnyPrefix(in.filename, m.filePrefixes) {
		return false
	}
	if len(m.fileSuffixes) > 0 && !hasAnySuffix(in.filename, m.fileSuffixes) {
		return false
	}
	if len(m.fileExacts) > 0 && !m.fileExacts[in.filename] {
		return false
	}
	if len(m.fileContains) > 0 && !containsAny(in.filename, m.fileContains) {
		return false
	}
	if len(m.dstIPNotIn) > 0 {
		if in.dstIP == nil {
			return false // no destination IP → cannot be verified external
		}
		for _, n := range m.dstIPNotIn {
			if n.Contains(in.dstIP) {
				return false // inside a listed range → not external
			}
		}
	}
	if len(m.dstPorts) > 0 && !m.dstPorts[in.dstPort] {
		return false
	}
	if len(m.services) > 0 && !m.services[in.service] {
		return false
	}
	if m.requireTty && !in.hasTty {
		return false
	}
	if len(m.argsContains) > 0 && !containsAny(in.args, m.argsContains) {
		return false
	}
	return true
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func hasAnySuffix(s string, suffixes []string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, pre := range prefixes {
		if strings.HasPrefix(s, pre) {
			return true
		}
	}
	return false
}

// compiledDetection is a DetectionRule ready for the hot path.
type compiledDetection struct {
	name             string
	level            alert.Level
	requireContainer bool
	match            compiledMatch
	exceptions       []compiledMatch // OR-ed: any spec matching suppresses the rule
	message          string
	response         alert.Action // requested response (rules/*.yaml response:); ActionNone = alert only
}

// excepted reports whether any exception spec matches the event.
func (c *compiledDetection) excepted(in matchInput) bool {
	for i := range c.exceptions {
		if c.exceptions[i].matches(in) {
			return true
		}
	}
	return false
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
	d.processDetections = d.compileDetections(db.ProcessDetections)
	d.fileDetections = d.compileDetections(db.FileDetections)
	d.netDetections = d.compileDetections(db.NetworkDetections)
	return d
}

// compileDetections resolves each detection's list references to lookup
// structures once. References were validated at load time (loader fail-fast),
// so missing lists cannot occur here.
func (d *YAMLDetector) compileDetections(dets []rules.DetectionRule) []compiledDetection {
	compiled := make([]compiledDetection, 0, len(dets))
	for _, det := range dets {
		exceptions := make([]compiledMatch, 0, len(det.Exceptions))
		for _, ex := range det.Exceptions {
			exceptions = append(exceptions, d.compileMatch(ex))
		}
		response := det.Response
		if response == "" {
			response = alert.ActionNone
		}
		compiled = append(compiled, compiledDetection{
			name:             det.Name,
			level:            det.Severity,
			requireContainer: det.RequireContainer,
			match:            d.compileMatch(det.Match),
			exceptions:       exceptions,
			message:          det.Message,
			response:         response,
		})
	}
	return compiled
}

func (d *YAMLDetector) compileMatch(spec rules.MatchSpec) compiledMatch {
	var m compiledMatch
	if spec.CommSuffixIn != "" {
		m.commSuffixes = d.getListStrings(spec.CommSuffixIn)
	}
	if spec.CommBaseIn != "" {
		m.commBases = make(map[string]bool)
		for _, s := range d.getListStrings(spec.CommBaseIn) {
			m.commBases[s] = true
		}
	}
	if spec.CommPrefixIn != "" {
		m.commPrefixes = d.getListStrings(spec.CommPrefixIn)
	}
	if spec.FilePrefixIn != "" {
		m.filePrefixes = d.getListStrings(spec.FilePrefixIn)
	}
	if spec.FileSuffixIn != "" {
		m.fileSuffixes = d.getListStrings(spec.FileSuffixIn)
	}
	if spec.FileExactIn != "" {
		m.fileExacts = make(map[string]bool)
		for _, s := range d.getListStrings(spec.FileExactIn) {
			m.fileExacts[s] = true
		}
	}
	if spec.FileContainsIn != "" {
		m.fileContains = d.getListStrings(spec.FileContainsIn)
	}
	if spec.DstIPNotIn != "" {
		for _, cidr := range d.getListStrings(spec.DstIPNotIn) {
			if _, n, err := net.ParseCIDR(cidr); err == nil {
				m.dstIPNotIn = append(m.dstIPNotIn, n)
			}
		}
	}
	if spec.DstPortIn != "" {
		m.dstPorts = make(map[uint16]bool)
		for _, item := range d.rules.GetList(spec.DstPortIn) {
			if p, ok := item.(int); ok && p >= 0 && p <= 65535 {
				m.dstPorts[uint16(p)] = true
			}
		}
	}
	if spec.ServiceIn != "" {
		m.services = make(map[string]bool)
		for _, s := range d.getListStrings(spec.ServiceIn) {
			m.services[s] = true
		}
	}
	m.requireTty = spec.TtyRequired
	if spec.ArgsContainsIn != "" {
		m.argsContains = d.getListStrings(spec.ArgsContainsIn)
	}
	return m
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
		comm = processor.CString(ev.Process.ExecPath[:])
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
				// parent_context: infrastructure quiets HOST/node infra noise (sshd
				// sessions, runtime health helpers). It must NOT suppress verified-container
				// events: a shell or curl INSIDE a container is the detection signal
				// (T1059/T1105/T1041), even though its parent is containerd-shim (trusted).
				// So this exception only applies off-container.
				if isContainerContext(ev.Workload) {
					continue // container event → host-infra exception does not apply
				}
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
	comm := processor.CString(event.ExecPath[:])

	// System services spawned by init (ppid=1) are trusted infrastructure
	if event.Ppid == 1 {
		return nil
	}

	// Structured detections from rules/process.yaml, evaluated in file order
	// (CRITICAL → LOW). Container-gated rules only fire for verified containers
	// (state resolved, runtime docker/k8s); require_container: false rules
	// (T1036) also cover host and state=unknown processes.
	isVerifiedContainer := isContainerContext(res)
	in := matchInput{comm: comm, hasTty: event.HasTty != 0, args: string(event.Args[:])}
	for i := range d.processDetections {
		det := &d.processDetections[i]
		if det.requireContainer && !isVerifiedContainer {
			continue
		}
		if !det.match.matches(in) {
			continue
		}
		if det.excepted(in) {
			continue
		}
		a := newProcessAlert(event, res, comm, det.level, det.name, det.message)
		a.ResponseAction = det.response
		return a
	}

	if res.State == workload.StateUnknown {
		// Whitelisted apps (customer_applications) in unresolved namespaces are
		// known-benign — not telemetry noise (preserves the pre-refactor early
		// whitelist return for state=unknown).
		if d.isWhitelisted(comm) {
			return nil
		}
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
		// visibility gap, not an escape. Emit at LOW: still persisted (file + Supabase
		// for the anomaly service) but the Redis sink drops LOW so it stays off the live
		// dashboard — avoids LOW-level alert fatigue.
		return newProcessAlert(event, res, comm, alert.Low, RuleEDRTelemetryUnresolvedNamespace, "EDR visibility gap: process in unresolved namespace")
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

	// Special runc states during container initialization (runc:[2:INIT], ...)
	fileCommWhitelist := d.getListStrings("whitelisted_file_access_procs")
	base := filepath.Base(comm)
	for _, w := range fileCommWhitelist {
		if base == w || comm == w {
			return nil
		}
	}

	// T1611 host-reads-container-overlay is intentionally NOT implemented here:
	// disabled pending its allowlist (deferred validate.sh T7 work). When wired,
	// it becomes a require_container: false entry in rules/file.yaml.

	// Structured detections from rules/file.yaml, evaluated in file order
	// (CRITICAL → LOW). All current file rules are container-gated; the old
	// global customer_applications whitelist is now a per-rule exception.
	isVerifiedContainer := isContainerContext(res)
	in := matchInput{comm: comm, filename: filename, service: res.Identity.Service}
	for i := range d.fileDetections {
		det := &d.fileDetections[i]
		if det.requireContainer && !isVerifiedContainer {
			continue
		}
		if !det.match.matches(in) {
			continue
		}
		if det.excepted(in) {
			continue
		}
		a := newFileAlert(event, res, comm, filename, det.level, det.name, det.message)
		a.ResponseAction = det.response
		return a
	}

	return nil
}

// ── Network rules ─────────────────────────────────────────────────────────────

func (d *YAMLDetector) checkNetworkRules(event processor.NetEvent, res workload.ResolveResult, ip net.IP, port uint16) *alert.Alert {
	comm := processor.CString(event.Comm[:])

	// Structured detections from rules/network.yaml, evaluated in file order
	// (CRITICAL → LOW). T1041's match (dst_ip_not_in: private_ranges) replaces
	// the old isPrivateIP early return; allowed ports/services are exceptions.
	isVerifiedContainer := isContainerContext(res)
	in := matchInput{comm: comm, dstIP: ip, dstPort: port, service: res.Identity.Service}
	for i := range d.netDetections {
		det := &d.netDetections[i]
		if det.requireContainer && !isVerifiedContainer {
			continue
		}
		if !det.match.matches(in) {
			continue
		}
		if det.excepted(in) {
			continue
		}
		a := newNetAlert(event, res, comm, ip.String(), port, det.level, det.name, det.message)
		a.ResponseAction = det.response
		return a
	}

	return nil
}

// ── Alert Constructors ────────────────────────────────────────────────────────

// Constructors default ResponseAction to ActionNone; rule-fire sites overwrite
// it with the fired detection's response:, and the responder (main.go) replaces
// it with the action actually executed before the alert is sent to sinks.

func newFileAlert(event processor.FileEvent, res workload.ResolveResult, comm, filename string, level alert.Level, rule, msg string) *alert.Alert {
	return &alert.Alert{
		Level: level, Rule: rule, Message: msg,
		Pid: event.Pid, Ppid: event.Ppid, Uid: int32(event.Uid),
		Comm: comm, Workload: res, Filename: filename,
		Cgroup: processor.CString(event.Cgroup[:]), Fmode: event.Fmode, Ret: event.Ret,
		EventTime:      event.EventTime,
		ResponseAction: alert.ActionNone,
	}
}

func newProcessAlert(event processor.ProcessEvent, res workload.ResolveResult, comm string, level alert.Level, rule, msg string) *alert.Alert {
	return &alert.Alert{
		Level: level, Rule: rule, Message: msg,
		Pid: event.Pid, Ppid: event.Ppid, Uid: event.Uid,
		Comm: comm, Workload: res,
		Cgroup: processor.CString(event.Cgroup[:]), EventTime: event.EventTime,
		ResponseAction: alert.ActionNone,
	}
}

func newNetAlert(event processor.NetEvent, res workload.ResolveResult, comm, dstIP string, dstPort uint16, level alert.Level, rule, msg string) *alert.Alert {
	return &alert.Alert{
		Level: level, Rule: rule, Message: msg,
		Pid: event.Pid, Ppid: event.Ppid, Uid: int32(event.Uid),
		Comm: comm, Workload: res, DstIP: dstIP, DstPort: dstPort,
		EventTime:      event.EventTime,
		ResponseAction: alert.ActionNone,
	}
}
