// Package detector implements EDR detection rules and the policy data they run against.
// This file contains DATA only — no detection logic.
// To add a new whitelisted process, sensitive path, or network rule, change this file.
// rules.go should not need to change.
package detector

import (
	"net"
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

// allowedMarketAPI is the only external domain any service may connect to.
const allowedMarketAPI = "api.coingecko.com"

// externalAllowedServices — services permitted to make external network connections.
// Uses normalized service names (matching WorkloadIdentity.Service) so the same
// policy works for both Docker ("inventory-service") and K8s ("inventory-service").
var externalAllowedServices = []string{
	"inventory-service", // calls CoinGecko for live market data
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
}
