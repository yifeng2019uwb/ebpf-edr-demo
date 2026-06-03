package detector

import "ebpf-edr-demo/internal/alert"

// ResponseAction identifies the automated response taken when an alert fires.
type ResponseAction string

const (
	ActionNone        ResponseAction = "none"
	ActionKillProcess ResponseAction = "kill_process"
	// Phase 2: ActionBlockIP        ResponseAction = "block_ip"         — block dst IP via eBPF map enforced in lsm-connect.bpf.c
	// Phase 2: ActionQuarantineFile ResponseAction = "quarantine_file"  — move file to /quarantine/, chmod 000
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
	// T1059 — shell or scripting interpreter in container: kill immediately (RCE)
	{rule: RuleT1059UnixShellExecution, minLevel: alert.Critical, action: ActionKillProcess},

	// T1105 — network staging tool in container: kill before data transfer completes
	{rule: RuleT1105IngressToolTransfer, minLevel: alert.High, action: ActionKillProcess},

	// T1611 — escape to host via unknown namespace: excluded — Podman health check false positive
	//   Phase 2: fix containerIDFromDockerCgroup to parse Podman cgroup format, then enable kill
	// {rule: RuleT1611EscapeToHostNs, minLevel: alert.Critical, action: ActionKillProcess},

	// File rules
	// T1611 — host reads container filesystem: kill the host-side process attempting escape
	{rule: RuleT1611EscapeToHostFs, minLevel: alert.Critical, action: ActionKillProcess},

	// T1611 — container reads /proc/1/: kill the container process probing host namespace
	{rule: RuleT1611EscapeToHostProc, minLevel: alert.High, action: ActionKillProcess},

	// T1552.004 — private key access: kill on both CRITICAL (SSH dirs) and HIGH (key files)
	{rule: RuleT1552PrivateKeys, minLevel: alert.High, action: ActionKillProcess},

	// T1552.001 — credentials in files: kill on .env and /run/secrets/ access
	{rule: RuleT1552CredentialsInFiles, minLevel: alert.High, action: ActionKillProcess},

	// T1003.008 — OS credential dumping (/etc/shadow): kill
	{rule: RuleT1003OsCredentialDumping, minLevel: alert.High, action: ActionKillProcess},

	// T1082 — system info discovery (/etc/passwd, /etc/group): no action — MEDIUM, too noisy

	// Network rules
	// T1041 — exfiltration over C2: excluded — kill after connect is too late
	//   Phase 2: block before connect by returning -EPERM in lsm_socket_connect (lsm-connect.bpf.c)
	// {rule: RuleT1041ExfiltrationOverC2, minLevel: alert.High, action: ActionBlockIP},
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
