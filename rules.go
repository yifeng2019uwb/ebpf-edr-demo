//go:build linux

package main

import (
	"bytes"
	"path/filepath"
	"strings"
)

// ─────────────────────────────────────────────
// Whitelist — known good processes, never alert
// ─────────────────────────────────────────────

// Processes always allowed regardless of context
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
	// NOTE: curl excluded here — handled separately with context
}

// ─────────────────────────────────────────────
// Network policy — per container
// ─────────────────────────────────────────────

// Containers allowed to make external HTTP/curl calls (process-level check)
// Add more here if a new service needs external API access
var curlAllowedContainers = []string{
	"order-processor-inventory_service", // calls CoinGecko for market data
}

// allowedMarketAPI is the only external domain inventory_service may connect to.
// Enforced at network level in lsm-connect rules (not here — execsnoop has no URL).
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
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

	// Never alert on whitelisted processes
	if isWhitelisted(comm) {
		return nil
	}

	// Never alert on host processes — only watch containers
	if container == "host" {
		return nil
	}

	// Alert: shell spawned from container (any uid — shells in containers are unexpected)
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

	// Alert: network tools from containers
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

	// Alert: curl from container
	// some services are allowed to call external APIs — see curlAllowedContainers
	if strings.HasSuffix(comm, "/curl") {
		for _, allowed := range curlAllowedContainers {
			if container == allowed {
				return nil // expected — this container is allowed to use curl
			}
		}
		return &Alert{
			Level:     "MEDIUM",
			Rule:      "curl_from_container",
			Message:   "curl executed from container — verify if expected",
			Pid:       event.Pid,
			Ppid:      event.Ppid,
			Uid:       event.Uid,
			Comm:      comm,
			Container: container,
		}
	}

	return nil // clean
}

// ─────────────────────────────────────────────
// Exit rules
// ─────────────────────────────────────────────

func checkExitRules(event ExitEvent) *Alert {
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

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
			Container: "unknown", // exit events don't carry mnt_ns yet
		}
	}

	return nil
}

