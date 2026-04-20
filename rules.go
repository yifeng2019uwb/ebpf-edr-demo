//go:build linux

package main

import (
	"path/filepath"
	"strings"
)

// ─────────────────────────────────────────────
// Whitelist — known good processes, never alert
// ─────────────────────────────────────────────

var whitelistComm = []string{
	"sshd",       // your SSH access from laptop
	"runc",       // Docker container runtime
	"dockerd",    // Docker daemon
	"containerd", // container runtime
	"ip",         // OpenClaw heartbeat
	"getconf",    // GCP guest agent
}

// ─────────────────────────────────────────────
// Detection lists
// ─────────────────────────────────────────────

var shellBinaries = []string{
	"/bash", "/sh", "/zsh", "/dash",
}

var networkBinaries = []string{
	"/nc", "/ncat", "/wget",
	// curl intentionally excluded — destination-aware detection handled in lsm-connect
}

// ─────────────────────────────────────────────
// Network policy
// ─────────────────────────────────────────────

// allowedMarketAPI is the only external domain inventory_service may connect to.
// NOTE: curl detection belongs in lsm-connect, not here.
// execsnoop sees the binary name but not the destination — it cannot distinguish
// "curl http://localhost/health" (health check) from "curl https://evil.com" (attack).
// lsm-connect hooks the network connection and enforces this constant at the IP level.
const allowedMarketAPI = "api.coingecko.com"

// ─────────────────────────────────────────────
// Helper functions
// ─────────────────────────────────────────────

func matchesSuffix(comm string, list []string) bool {
	for _, s := range list {
		if strings.HasSuffix(comm, s) {
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

// ─────────────────────────────────────────────
// Process rules
// ─────────────────────────────────────────────

func checkProcessRules(event ProcessEvent, container string) *Alert {
	comm := cstring(event.Comm[:])

	if isWhitelisted(comm) {
		return nil
	}

	// never alert on host processes — only watch containers
	if container == "host" {
		return nil
	}

	// Alert: shell spawned inside a container — possible RCE
	if matchesSuffix(comm, shellBinaries) {
		return &Alert{
			Level:     "CRITICAL",
			Rule:      "shell_spawn_container",
			Message:   "Shell spawned from container — possible RCE",
			Pid:       event.Pid,
			Ppid:      event.Ppid,
			Uid:       event.Uid,
			Comm:      comm,
			Container: container,
		}
	}

	// Alert: raw network tools (nc, ncat, wget) from containers
	if matchesSuffix(comm, networkBinaries) {
		return &Alert{
			Level:     "HIGH",
			Rule:      "network_tool_container",
			Message:   "Network tool executed from container — possible exfiltration",
			Pid:       event.Pid,
			Ppid:      event.Ppid,
			Uid:       event.Uid,
			Comm:      comm,
			Container: container,
		}
	}

	return nil
}

// ─────────────────────────────────────────────
// Exit rules
// ─────────────────────────────────────────────

// System tools that legitimately exit quickly with non-zero codes — not suspicious
var exitWhitelist = []string{
	"gpasswd", // Docker modifies groups during container startup
	"cmp",     // file comparison — non-zero means files differ, not an error
	"https",   // GCP guest agent helper
}

func checkExitRules(event ExitEvent) *Alert {
	comm := cstring(event.Comm[:])

	for _, w := range exitWhitelist {
		if comm == w {
			return nil
		}
	}

	// Alert: process exited with non-zero code AND very short duration
	// Possible: crash, killed process, failed exploit attempt
	durationMs := event.DurationNs / 1_000_000
	if event.ExitCode != 0 && durationMs < 100 {
		return &Alert{
			Level:     "LOW",
			Rule:      "short_lived_failure",
			Message:   "Process exited quickly with error — possible failed exploit",
			Pid:       int32(event.Pid),
			Comm:      comm,
			Container: "unknown", // exit events don't carry mnt_ns — fix: pid→container cache
		}
	}

	return nil
}

// ─────────────────────────────────────────────
// File access rules
// ─────────────────────────────────────────────

// Container runtime processes that legitimately read /etc/passwd during startup.
// runc reads passwd to resolve user IDs before exec — fires on every container start.
var fileCommWhitelist = []string{
	"runc:[2:INIT]",
	"runc:[1:CHILD]",
	"runc",
}

// Sensitive file paths — severity reflects actual risk.
//
// CRITICAL — credential material, direct privilege escalation
// HIGH     — secrets, private keys, container escape indicators
// MEDIUM   — world-readable system files: suspicious from some processes, normal for others
//
// NOTE: /root/.curlrc and similar config probes are suppressed naturally by the
// sys_exit_openat hook — files that don't exist return ENOENT (ret < 0) and are dropped
// before reaching Go. Only successful opens reach checkFileRules.
var criticalFilePrefixes = []string{
	"/root/.ssh/",    // SSH private keys and authorized_keys
	"/home/.ssh/",    // user SSH keys
}

var highFilePrefixes = []string{
	"/etc/shadow",    // password hashes — no legitimate app reads this at runtime
	"/run/secrets/",  // Docker secrets mount
	"/proc/1/",       // host init process — container escape indicator
}

var highFileSuffixes = []string{
	".key",       // private keys
	".pem",       // certificates / private keys
	"id_rsa",     // SSH private key
	"id_ed25519", // SSH private key
	".env",       // environment secrets
}

var mediumFilePrefixes = []string{
	"/etc/passwd", // user accounts — world-readable but unexpected from app code
	"/etc/group",  // group memberships
}

func checkFileRules(event FileEvent, container string) *Alert {
	if container == "host" || container == "" {
		return nil
	}

	filename := cstring(event.Filename[:])
	comm := cstring(event.Comm[:])

	// skip container runtime — reads /etc/passwd during container init
	for _, w := range fileCommWhitelist {
		if comm == w {
			return nil
		}
	}

	for _, prefix := range criticalFilePrefixes {
		if strings.HasPrefix(filename, prefix) {
			return &Alert{
				Level:     "CRITICAL",
				Rule:      "sensitive_file_access",
				Message:   "Container accessed SSH credential file: " + filename,
				Pid:       event.Pid,
				Ppid:      event.Ppid,
				Uid:       int32(event.Uid),
				Comm:      comm,
				Container: container,
			}
		}
	}

	for _, prefix := range highFilePrefixes {
		if strings.HasPrefix(filename, prefix) {
			return &Alert{
				Level:     "HIGH",
				Rule:      "sensitive_file_access",
				Message:   "Container accessed sensitive file: " + filename,
				Pid:       event.Pid,
				Ppid:      event.Ppid,
				Uid:       int32(event.Uid),
				Comm:      comm,
				Container: container,
			}
		}
	}

	for _, suffix := range highFileSuffixes {
		if strings.HasSuffix(filename, suffix) {
			return &Alert{
				Level:     "HIGH",
				Rule:      "sensitive_file_access",
				Message:   "Container accessed sensitive file: " + filename,
				Pid:       event.Pid,
				Ppid:      event.Ppid,
				Uid:       int32(event.Uid),
				Comm:      comm,
				Container: container,
			}
		}
	}

	for _, prefix := range mediumFilePrefixes {
		if strings.HasPrefix(filename, prefix) {
			return &Alert{
				Level:     "MEDIUM",
				Rule:      "sensitive_file_access",
				Message:   "Container accessed system file: " + filename,
				Pid:       event.Pid,
				Ppid:      event.Ppid,
				Uid:       int32(event.Uid),
				Comm:      comm,
				Container: container,
			}
		}
	}

	return nil
}
