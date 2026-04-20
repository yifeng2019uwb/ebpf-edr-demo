//go:build linux

// policy.go — all allow/block lists and thresholds for the EDR agent.
//
// This file contains DATA only — no detection logic.
// To add a new whitelisted process, sensitive path, or network rule,
// change this file. rules.go should not need to change.

package main

import (
	"net"
	"time"
)

// ── Thresholds ────────────────────────────────────────────────────────────────

// shortLivedThresholdMs is the maximum process duration (in milliseconds) that,
// combined with a non-zero exit code, is considered suspicious.
const shortLivedThresholdMs = 100

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

// ── Exit policy ───────────────────────────────────────────────────────────────

// exitWhitelist — processes that legitimately exit quickly with non-zero codes.
// Suppresses LOW short_lived_failure noise for known-good tools.
var exitWhitelist = []string{
	"gpasswd",      // Docker modifies groups during container startup
	"cmp",          // file comparison — non-zero means files differ, not an error
	"https",        // GCP guest agent helper
	"runc",         // container runtime — exits non-zero during docker exec setup
	"runc:[1:CHILD]", // runc child process — transient, exits immediately
	"runc:[2:INIT]",  // runc init process — transient, exits immediately
}

// ── File policy ───────────────────────────────────────────────────────────────

// fileCommWhitelist — processes that legitimately read system files as part of
// normal startup or operation. Suppresses MEDIUM/HIGH noise from known-good tools.
var fileCommWhitelist = []string{
	"runc:[2:INIT]", // reads /etc/passwd to resolve user IDs during container init
	"runc:[1:CHILD]",
	"runc",
	"curl", // calls getpwuid() to find home directory before looking up ~/.curlrc
	"id",   // reads /etc/passwd and /etc/group by design — that is its only purpose
}

// Sensitive file paths — severity reflects actual risk.
//
// CRITICAL — credential material, direct privilege escalation
// HIGH     — secrets, private keys, container escape indicators
// MEDIUM   — world-readable system files: suspicious from app code
//
// NOTE: /root/.curlrc and similar config probes are suppressed naturally by the
// sys_exit_openat hook — files that don't exist return ENOENT (ret < 0) and are
// dropped before reaching Go. Only successful opens reach checkFileRules.
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
// Any .pem file whose path contains one of these substrings is suppressed.
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
// Enforced in lsm-connect network rules — only containers in externalAllowedContainers
// may make external connections, and their destination is logged for audit.
const allowedMarketAPI = "api.coingecko.com"

// externalAllowedContainers — containers permitted to make external network connections.
// All other containers connecting outside private IP ranges will trigger HIGH alert.
// Add entries here when a new service needs external API access.
var externalAllowedContainers = []string{
	"order-processor-inventory_service", // calls CoinGecko for live market data
}

// privateNets — RFC 1918 + link-local ranges that are always allowed.
// Initialized once at startup. Loopback (127.x.x.x) is filtered in BPF already.
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
