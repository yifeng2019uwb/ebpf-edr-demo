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

// Only inventory service is allowed to call external APIs
const inventoryContainer = "order-processor-inventory_service"

// Only this domain is allowed for inventory service
const allowedMarketAPI = "api.coingecko.com"

// Internal Docker bridge prefix — always allowed
const dockerBridgePrefix = "172."

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

func checkProcessRules(event ProcessEvent) *Alert {
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

	// Never alert on whitelisted processes
	if isWhitelisted(comm) {
		return nil
	}

	// Allow shells spawned by your user (uid=1000) — that's you via SSH
	if matchesSuffix(comm, shellBinaries) && event.Uid == 1000 {
		return nil
	}

	// Alert: shell spawned from container (uid=0, unexpected)
	if matchesSuffix(comm, shellBinaries) && event.Uid == 0 {
		return &Alert{
			Level:   "CRITICAL",
			Rule:    "shell_spawn_container",
			Message: "Shell spawned from container — possible RCE",
			Pid:     event.Pid,
			Ppid:    event.Ppid,
			Uid:     event.Uid,
			Comm:    comm,
		}
	}

	// Alert: network tools from containers
	if matchesSuffix(comm, networkBinaries) && event.Uid == 0 {
		return &Alert{
			Level:   "HIGH",
			Rule:    "network_tool_container",
			Message: "Network tool executed from container — possible exfiltration",
			Pid:     event.Pid,
			Ppid:    event.Ppid,
			Uid:     event.Uid,
			Comm:    comm,
		}
	}

	// Alert: curl from container — check context
	if strings.HasSuffix(comm, "/curl") && event.Uid == 0 {
		// curl from containers needs container correlation
		// Phase 2: check if container is inventory_service
		// For now — alert on all curl from uid=0 except known health checks
		// Health checks come from runc directly (ppid = runc pid)
		// TODO: add container name check in Phase 2
		return &Alert{
			Level:   "MEDIUM",
			Rule:    "curl_from_container",
			Message: "curl executed from container — verify if expected",
			Pid:     event.Pid,
			Ppid:    event.Ppid,
			Uid:     event.Uid,
			Comm:    comm,
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
			Level:   "LOW",
			Rule:    "short_lived_failure",
			Message: "Process exited quickly with error — possible failed exploit",
			Pid:     int32(event.Pid),
			Comm:    comm,
		}
	}

	return nil
}

// ─────────────────────────────────────────────
// Network rules (Phase 2 — container correlation needed)
// For now: placeholder showing the policy intent
// ─────────────────────────────────────────────

// networkPolicy describes intended rules per container
// Full enforcement requires container name from cgroup (Phase 2)
var networkPolicy = map[string][]string{
	// inventory_service — only allowed to call CoinGecko
	inventoryContainer: {allowedMarketAPI},

	// all other services — no external connections allowed
	"order-processor-auth_service":      {},
	"order-processor-order_service":     {},
	"order-processor-user_service":      {},
	"order-processor-gateway":           {},
	"order-processor-insights_service":  {},
}