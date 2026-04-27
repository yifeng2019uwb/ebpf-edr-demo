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

// ── Thresholds ────────────────────────────────────────────────────────────────

// nsRefreshInterval is how often the namespace cache is rebuilt to pick up
// containers that started or stopped since the last scan.
const nsRefreshInterval = 30 * time.Second

// ── Process policy ────────────────────────────────────────────────────────────

// whitelistComm — known good processes, never alert on process rules.
var whitelistComm = []string{
	"sshd",       // SSH access from laptop
	"runc",       // Docker container runtime
	"dockerd",    // Docker daemon
	"containerd", // container runtime
	"ip",         // OpenClaw heartbeat
	"getconf",    // GCP guest agent
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

// ── File policy ───────────────────────────────────────────────────────────────

// fileCommWhitelist — processes that legitimately read system files as part of
// normal startup or operation. Suppresses MEDIUM/HIGH noise from known-good tools.
var fileCommWhitelist = []string{
	"runc:[2:INIT]",  // reads /etc/passwd to resolve user IDs during container init
	"runc:[1:CHILD]",
	"runc",
	"curl",           // calls getpwuid() to find home directory before looking up ~/.curlrc
	"id",             // reads /etc/passwd and /etc/group by design — that is its only purpose
	"systemd-logind", // session manager reads /etc/passwd, /proc/1/ during login events — runs in private mount ns
	"bash",           // getpwuid() at startup reads /etc/passwd for prompt/PS1 — shell_spawn CRITICAL already fires
}

// Sensitive file paths — severity reflects actual risk.
//
// CRITICAL — credential material, direct privilege escalation
// HIGH     — secrets, private keys, container escape indicators
// MEDIUM   — world-readable system files: suspicious from app code
var criticalFilePrefixes = []string{
	"/root/.ssh/", // SSH private keys and authorized_keys
	"/home/.ssh/", // user SSH keys
}

var highFilePrefixes = []string{
	"/etc/shadow",   // password hashes — no legitimate app reads this at runtime
	"/run/secrets/", // Docker secrets mount
	"/proc/1/",      // host init process — container escape indicator
}

var highFileSuffixes = []string{
	".key",       // private keys
	".pem",       // private keys and certificates — CA bundles excluded via pemExcludePaths
	"id_rsa",     // SSH private key
	"id_ed25519", // SSH private key
	".env",       // environment secrets
}

// pemExcludePaths — .pem paths that are CA certificate bundles, not private keys.
// Python's certifi library and similar tools load these on every HTTPS request.
var pemExcludePaths = []string{
	"/site-packages/", // Python package CA bundles (certifi, requests, etc.)
	"/certifi/",       // certifi library specifically
}

var mediumFilePrefixes = []string{
	"/etc/passwd", // user accounts — world-readable but unexpected from app code
	"/etc/group",  // group memberships
}

// ── Network policy ────────────────────────────────────────────────────────────

// externalAllowedServices — services permitted to make external network connections.
// Uses normalized service names (matching WorkloadIdentity.Service) so the same
// policy works for both Docker ("inventory-service") and K8s ("inventory-service").
// Allowed services produce no alert — "allowed" means expected, no signal value.
// Previously emitted LOW rule=external_connect_allowed; removed because it fired
// on every DNS lookup and CoinGecko call, adding noise without actionable signal.
var externalAllowedServices = []string{
	"inventory-service", // calls CoinGecko for live market data
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
	"kube-system":      true,
	"gmp-system":       true,
	"gke-managed-cim":  true,
}

func isSystemNamespace(ns string) bool {
	return ns != "" && systemNamespaces[ns]
}

// privateNets — RFC 1918 + link-local ranges that are always allowed.
var privateNets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",     // RFC 1918 — private class A
		"172.16.0.0/12",  // RFC 1918 — private class B (includes Docker bridge 172.17.x)
		"192.168.0.0/16", // RFC 1918 — private class C
		"169.254.0.0/16", // link-local (APIPA)
	} {
		_, n, _ := net.ParseCIDR(cidr)
		privateNets = append(privateNets, n)
	}

	// SERVICE_CIDR — manual override; takes precedence over GCP metadata.
	// Set this env var only when auto-detection is not available (non-GKE, local Docker).
	if cidr := strings.TrimSpace(os.Getenv("SERVICE_CIDR")); cidr != "" {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			privateNets = append(privateNets, n)
			return
		}
	}

	// Auto-detect service CIDR from GCP metadata server (GKE nodes only).
	// GKE service CIDRs are outside RFC 1918 (e.g. 34.118.x.x); inter-service calls
	// via ClusterIP would otherwise be flagged as unauthorized external connections.
	// On non-GKE nodes the metadata server is unreachable and we skip silently.
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
