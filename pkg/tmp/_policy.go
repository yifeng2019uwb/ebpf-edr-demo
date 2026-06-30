// Package detector implements EDR detection rules and the policy data they run against.
// This file contains DATA only — no detection logic.
// To add a new whitelisted process, sensitive path, or network rule, change this file.
// rules.go should not need to change.
package detector

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ── Process policy ────────────────────────────────────────────────────────────

// whitelistComm — known good processes, never alert on process rules.
// Matched via filepath.Base(comm) — basename only, path prefix stripped before comparison.
var whitelistComm = []string{
	"sshd",       // SSH access from laptop
	"runc",       // Docker container runtime
	"dockerd",    // Docker daemon
	"containerd", // container runtime
	"getconf",    // GCP guest agent
}

// ── Unknown Namespace Process Whitelists ──────────────────────────────────────
// Processes detected in unknown namespaces (state=unknown) but NOT escape attempts.
// Split by PURPOSE and ENVIRONMENT to avoid accidentally skipping real alerts.
// Strategy: Unknown namespace + not whitelisted for environment = CRITICAL alert

// universalSystemTools — Safe to skip in ANY environment.
// These are eBPF capture artifacts or universal system utilities.
var universalSystemTools = []string{
	"fd",  // /proc/self/fd/ symlink resolved as process name — eBPF capture artifact
}

// k8sNodeInfraProcs — Kubernetes infrastructure at node level (K8S ENVIRONMENT ONLY).
// These legitimately run outside pod namespaces in K8s clusters.
// In non-K8s environments (Docker), these in unknown namespace = suspicious.
// NOTE: "pause" is GKE-specific, not universal — it's in gke_infrastructure_procs in YAML.
var k8sNodeInfraProcs = []string{
	"iptables",                 // kube-proxy enforces network policies
	"iptables-legacy",          // older iptables variant on some nodes
	"iptables-restore",         // bulk iptables rule restore
	"ip6tables",                // IPv6 iptables
	"conntrack",                // connection tracking daemon
	"ip",                       // iproute2 — route/addr management
	"kube-proxy",               // Kubernetes cluster network proxy
	"systemd-sysctl",           // node sysctl configuration
	"bridge-network-interface", // udev network bridge setup
}

// systemContainerDetectionTools — Admin tools that probe namespace boundaries.
// MEDIUM CONFIDENCE: legitimate in any environment, but monitor for abuse.
// In unknown namespace: alert as LOW (suspicious but known tool), not CRITICAL.
// Could indicate attacker doing reconnaissance.
var systemContainerDetectionTools = []string{
	"ps",               // process listing — system tools check if running in container
	"apparmor_parser",  // AppArmor config — reads namespace info during profile load
}

// shellBinaries — binary path suffixes that indicate an interactive shell.
// Any match inside a container triggers CRITICAL shell_spawn_container.
var shellBinaries = []string{
	"/bash", "/sh", "/zsh", "/dash",
}

// networkBinaries — binary path suffixes for raw network recon tools.
// Any match inside a container triggers HIGH network_tool_container.
// curl intentionally excluded — destination-aware detection in lsm-connect.
var networkBinaries = []string{
	"/nc", "/ncat", "/wget",
}

// ── T1036 — Masquerading ──────────────────────────────────────────────────────
// Paths where legitimate system binaries should never run from.
// Checked BEFORE the process whitelist — attacker may name malware after a legit process (e.g. /tmp/sshd).
var t1036MasqueradingPaths = []string{
	"/tmp/",      // world-writable temp directory
	"/dev/shm/",  // shared memory — common dropper target
	"/var/tmp/",  // persistent temp — survives reboots
	"/run/user/", // user runtime dir — unexpected for system binaries
}

// ── T1613 — Container and Resource Discovery ──────────────────────────────────
// Container management tools executed from inside a container indicate an attacker
// doing reconnaissance. Legitimate services never need to call these tools.
var t1613ContainerMgmtTools = []string{
	"/kubectl", "/docker", "/crictl", "/ctr", "/podman",
}

// ── T1053.003 — Scheduled Task/Job: Cron ─────────────────────────────────────
// Container access to cron config files indicates persistence attempt.
// Containers should never read or write cron directories.
var t1053CronPrefixes = []string{
	"/etc/cron.d/",
	"/etc/cron.hourly/",
	"/etc/cron.daily/",
	"/etc/cron.weekly/",
	"/etc/cron.monthly/",
	"/var/spool/cron/",
	"/etc/crontab",
}

// ── T1070.003 — Clear Command History ────────────────────────────────────────
// Shell history files — container access suggests an attacker covering tracks.
var t1070HistoryFileSuffixes = []string{
	".bash_history",
	".zsh_history",
	".ash_history",
	".sh_history",
}

// ── File policy ───────────────────────────────────────────────────────────────

// fileCommWhitelist — processes that legitimately read system files as part of
// normal startup or operation. Suppresses MEDIUM/HIGH noise from known-good tools.
// Matched by exact comm string — NOT basename — because entries like "runc:[2:INIT]"
// contain colons that filepath.Base would mangle.
var fileCommWhitelist = []string{
	"runc:[2:INIT]", // reads /etc/passwd to resolve user IDs during container init
	"runc:[1:CHILD]",
	"runc",
	"curl",            // calls getpwuid() to find home directory before looking up ~/.curlrc
	"id",              // reads /etc/passwd and /etc/group by design — that is its only purpose
	"systemd-logind",  // session manager reads /etc/passwd, /proc/1/ during login events — runs in private mount ns
	"bash",            // getpwuid() at startup reads /etc/passwd for prompt/PS1 — shell_spawn CRITICAL already fires
	"containerd-shim", // K8s container shim — manages container stdio and lifecycle files under /run/containerd/
	"containerd",      // containerd daemon — accesses /run/containerd/ task and I/O dirs on GKE
	"dockerd",         // Docker daemon reads overlay2 on every docker exec / container lifecycle event
}

// containerFSPrefixes — host filesystem paths that hold container layer data.
// A host process (StateHost) reading these paths indicates container escape (T1611).
var containerFSPrefixes = []string{
	"/var/lib/docker/overlay2/", // Docker overlay filesystem layers
	"/run/containerd/",          // containerd runtime task directories (K8s + containerd)
}

// ── T1611 — Escape to Host (via /proc) ───────────────────────────────────────
// Container process reading the host init process — escape attempt indicator.
var t1611ProcEscapePrefixes = []string{
	"/proc/1/", // host PID 1 (init/systemd) — not reachable from inside a container normally
}

// t1611ProcEscapeAllowed — read-only stat files under /proc/1/ that monitoring
// tools (redis, prometheus node-exporter) legitimately read. These expose no
// writable state and are not a container escape vector.
// Real escape paths (/proc/1/mem, /proc/1/fd/, /proc/1/root/, /proc/1/exe)
// are NOT excluded — they remain detectable.
var t1611ProcEscapeAllowed = []string{
	"/proc/1/stat",       // process statistics — monitoring tools check this
	"/proc/1/status",     // process status info — monitoring tools check this
	"/proc/1/cmdline",    // process command line — monitoring tools check this
	"/proc/1/mountinfo",  // mount namespace info — ischroot and container detection tools use this
}

// ── T1552.004 — Unsecured Credentials: Private Keys ──────────────────────────
// SSH key directories → CRITICAL. Key files by extension → HIGH.
var t1552PrivateKeyDirPrefixes = []string{
	"/root/.ssh/", // SSH private keys and authorized_keys
	"/home/.ssh/", // user SSH keys
}

var t1552PrivateKeySuffixes = []string{
	".key",       // private keys
	".pem",       // private keys and certificates — CA bundles excluded via pemExcludePaths
	"id_rsa",     // SSH private key
	"id_ed25519", // SSH private key
}

// pemExcludePaths — .pem paths that are CA certificate bundles, not private keys.
// Python's certifi library and similar tools load these on every HTTPS request.
var pemExcludePaths = []string{
	"/site-packages/", // Python package CA bundles (certifi, requests, etc.)
	"/certifi/",       // certifi library specifically
}

// ── T1552.001 — Unsecured Credentials: Credentials in Files ──────────────────
var t1552CredentialFilePrefixes = []string{
	"/run/secrets/", // Docker secrets mount
}

var t1552CredentialFileSuffixes = []string{
	".env", // environment variable files containing secrets
}

// ── T1003.008 — OS Credential Dumping ────────────────────────────────────────
var t1003CredentialDumpPaths = []string{
	"/etc/shadow", // password hashes — no legitimate app reads this at runtime
}

// ── T1082 — System Information Discovery ─────────────────────────────────────
// World-readable system files — unexpected from application code (MEDIUM).
var t1082SystemInfoPrefixes = []string{
	"/etc/passwd", // user accounts
	"/etc/group",  // group memberships
}

// ── Network policy ────────────────────────────────────────────────────────────

// externalAllowedDstPorts — destination ports always allowed for all services.
// Used for shared backend infrastructure that every service legitimately connects to.
var externalAllowedDstPorts = []uint16{
	6543, // Supabase pgbouncer — all health-ai services use Supabase as their database
}

// externalAllowedServices — services permitted to make external network connections.
// Uses normalized service names (matching WorkloadIdentity.Service) so the same
// policy works for both Docker ("inventory-service") and K8s ("inventory-service").
// Allowed services produce no alert — "allowed" means expected, no signal value.
// Previously emitted LOW rule=external_connect_allowed; removed because it fired
// on every DNS lookup and CoinGecko call, adding noise without actionable signal.
var externalAllowedServices = []string{
	"inventory-service", // calls CoinGecko for live market data
	"inventory_service", // Docker version of same service — matches by normalized name, not exact
}

// ── Known startup noise — intentionally not suppressed ────────────────────────
//
// LocalStack (service=localstack) generates alerts on every pod startup:
//   - CRITICAL shell_spawn_container — localstack runs internal shell scripts during init;
//     this is normal for localstack but indistinguishable from RCE by our rules.
//   - HIGH sensitive_file_access — reads /var/lib/localstack/cache/server.test.pem(.key)
//     for its own HTTPS endpoint; these are localstack's own test certificates.
//   - HIGH unauthorized_external_connect — connects to real AWS endpoints on startup
//     (18.196.231.58, 63.182.162.112) for license check or telemetry. This is a real
//     finding: localstack phones home to AWS even in local/emulator mode.
//
// Decision: localstack is internal infrastructure (DynamoDB emulator), not a real
// microservice. We do NOT suppress these alerts. Reasons:
//   1. If localstack were compromised, shell spawn and external connect are exactly
//      the signals we would want to catch — suppressing them hides real threats.
//   2. The AWS phone-home is a legitimate finding worth knowing about.
//   3. These alerts only fire at startup, not during normal operation.
// Accept as known startup noise. In a production policy, localstack would not exist.

// systemNamespaces — GKE infrastructure namespaces suppressed entirely.
// These generate constant high-frequency noise (kube-proxy iptables, prometheus
// /proc reads, kubelet polling) that has no actionable signal for this project.
var systemNamespaces = map[string]bool{
	"kube-system":     true,
	"gmp-system":      true,
	"gke-managed-cim": true,
}

func isSystemNamespace(ns string) bool {
	return systemNamespaces[ns]
}

// privateNets — RFC 1918 + link-local ranges that are always allowed.
var privateNets []*net.IPNet

func init() {
	// Initialize RFC 1918 private networks — applicable everywhere.
	// These do NOT require environment detection.
	for _, cidr := range []string{
		"10.0.0.0/8",     // RFC 1918 — private class A
		"172.16.0.0/12",  // RFC 1918 — private class B (includes Docker bridge 172.17.x)
		"192.168.0.0/16", // RFC 1918 — private class C
		"169.254.0.0/16", // link-local (APIPA)
	} {
		_, n, _ := net.ParseCIDR(cidr)
		privateNets = append(privateNets, n)
	}

	// SERVICE_CIDR environment variable — manual override (no network calls needed).
	// Set this only when auto-detection is not available (non-GKE, local Docker).
	if cidr := strings.TrimSpace(os.Getenv("SERVICE_CIDR")); cidr != "" {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			privateNets = append(privateNets, n)
			return
		}
	}

	// GKE-specific CIDRs: DEFER to addGKEServiceCIDR() — call only when GKE detected.
	// Reason: gkeServiceCIDR() makes HTTP requests to metadata server (2s timeout).
	// Avoid unnecessary latency on non-GKE environments (Docker, bare-metal).
}

// AddGKEServiceCIDR loads GKE-specific service CIDR from metadata server.
// Call this only after detecting GKE environment.
// GKE service CIDRs are outside RFC 1918 (e.g. 34.118.x.x); inter-service calls
// via ClusterIP would otherwise be flagged as unauthorized external connections.
func AddGKEServiceCIDR() {
	if cidr := gkeServiceCIDR(); cidr != "" {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			privateNets = append(privateNets, n)
		}
	}
}

// gkeServiceCIDR reads SERVICE_CLUSTER_IP_RANGE from the GCP instance metadata server.
// Returns empty string on any error (non-GKE environment, metadata unreachable, etc.).
func gkeServiceCIDR() string {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest("GET",
		"http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		// Not on GKE or metadata server unreachable — normal for Docker/local runs.
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "SERVICE_CLUSTER_IP_RANGE:") {
			cidr := strings.TrimSpace(strings.TrimPrefix(line, "SERVICE_CLUSTER_IP_RANGE:"))
			log.Printf("gkeServiceCIDR: auto-detected service CIDR %s from GCP metadata", cidr)
			return cidr
		}
	}
	return ""
}
