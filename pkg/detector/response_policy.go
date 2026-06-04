package detector

import "ebpf-edr-demo/internal/alert"

// ResponseAction identifies the automated response taken when an alert fires.
type ResponseAction string

const (
	ActionNone        ResponseAction = "none"
	ActionKillProcess ResponseAction = "kill_process"
	ActionBlockIP     ResponseAction = "block_ip" // blocks dst IP via LPMTrie in lsm-connect.bpf.c (outbound only)
	// Phase 2: ActionQuarantineFile ResponseAction = "quarantine_file" — move file to /quarantine/, chmod 000
)

type responseRule struct {
	rule     string
	minLevel alert.Level
	action   ResponseAction
}

// responseRules maps rule+severity → automated response.
// Rules not listed default to ActionNone.
//
// Process rules
var responseRules = []responseRule{
	// T1059 — alert only: shells run constantly in builds, kubectl exec, health checks
	// T1105 — alert only: wget/curl used by package managers and health checks

	// T1611 — escape to host via unknown namespace: excluded — Podman health check false positive
	//   Phase 2: fix containerIDFromDockerCgroup to parse Podman cgroup format, then enable kill
	// {rule: RuleT1611EscapeToHostNs, minLevel: alert.Critical, action: ActionKillProcess},

	// File rules
	// T1611 — host reads container filesystem: kill — no legitimate app accesses host overlay
	{rule: RuleT1611EscapeToHostFs, minLevel: alert.Critical, action: ActionKillProcess},

	// T1611 — container reads /proc/1/: alert only — GKE monitoring sidecars hit this (known FP)

	// T1552.004 — private key access: kill — no container should read SSH keys
	{rule: RuleT1552PrivateKeys, minLevel: alert.High, action: ActionKillProcess},

	// T1552.001 — alert only: apps legitimately read their own .env at startup

	// T1003.008 — OS credential dumping (/etc/shadow): kill — never legitimate inside a container
	{rule: RuleT1003OsCredentialDumping, minLevel: alert.High, action: ActionKillProcess},

	// T1082 — system info discovery (/etc/passwd, /etc/group): no action — MEDIUM, too noisy

	// Network rules
	// T1041 — block dst IP in LPMTrie before TCP handshake (outbound only).
	// First connection fires the alert and adds IP to map; subsequent connects to same IP are denied.
	// Requires kernel side: blocked_ips map in lsm-connect.bpf.c + go generate on Linux.
	{rule: RuleT1041ExfiltrationOverC2, minLevel: alert.High, action: ActionBlockIP},
}

// ResponseFor returns the response action for the given rule and alert level.
func ResponseFor(rule string, level alert.Level) ResponseAction {
	for _, r := range responseRules {
		if r.rule == rule && levelGTE(level, r.minLevel) {
			return r.action
		}
	}
	return ActionNone
}

func levelGTE(a, b alert.Level) bool {
	return levelOrd(a) >= levelOrd(b)
}

func levelOrd(l alert.Level) int {
	switch l {
	case alert.Critical:
		return 3
	case alert.High:
		return 2
	case alert.Medium:
		return 1
	}
	return 0
}
