package detector

// Detection rule identifiers — single source of truth for all rules.
// Organized by eBPF event source (process / file / network).
// Each rule name is prefixed with its primary MITRE ATT&CK technique ID.
// Planned rules are defined here as design spec — not yet referenced in rules.go.
//
// Coverage status:
//   ✅ implemented  🔲 planned — not yet implemented

// ── Process events (execsnoop — tracepoint sys_enter_execve) ──────────────────
//
// Sees: comm, pid, ppid, uid, mnt_ns_id on every execve().
// Can detect: shell execution, staging tools, scripting runtimes, binary masquerading,
//             unknown namespace processes, container recon tools.

const (
	// T1059.004 · T1609 — Command & Scripting: Unix Shell / Container Administration Command
	RuleT1059UnixShellExecution = "T1059_unix_shell_execution"

	// T1105 · T1095 — Ingress Tool Transfer / Non-Application Layer Protocol
	RuleT1105IngressToolTransfer = "T1105_ingress_tool_transfer" // nc, wget

	// T1611 — Escape to Host: process running in unrecognised mount namespace
	RuleT1611EscapeToHostNs = "T1611_escape_to_host_ns" // (Podman FP — Phase 2 fix)

	// T1059 — Command & Scripting Interpreter: scripting runtime spawned in container
	RuleT1059ScriptingInterpreter = "T1059_scripting_interpreter" // 🔲 python -c, perl -e

	// T1613 — Container and Resource Discovery
	RuleT1613ContainerDiscovery = "T1613_container_resource_discovery" // kubectl/docker inside container

	// T1036 — Masquerading: binary running from unexpected path (e.g. /tmp)
	RuleT1036Masquerading = "T1036_masquerading" //
)

// ── File events (opensnoop — tracepoint sys_enter_openat / sys_exit_openat) ──
//
// Sees: filename, comm, pid, ppid, uid, mnt_ns_id on every openat().
// Can detect: credential theft, container escape via /proc, host reading container FS,
//             system recon, persistence via cron, defense evasion via history clearing.

const (
	// T1611 — Escape to Host: host process reading container overlay filesystem
	RuleT1611EscapeToHostFs = "T1611_escape_to_host_fs"

	// T1611 — Escape to Host: container process reading host /proc/1/
	RuleT1611EscapeToHostProc = "T1611_escape_to_host_proc"

	// T1552.004 — Unsecured Credentials: Private Keys (SSH dirs → CRITICAL, key files → HIGH)
	RuleT1552PrivateKeys = "T1552_004_private_keys"

	// T1552.001 — Unsecured Credentials: Credentials in Files (.env, /run/secrets/)
	RuleT1552CredentialsInFiles = "T1552_001_credentials_in_files"

	// T1003.008 — OS Credential Dumping: /etc/shadow
	RuleT1003OsCredentialDumping = "T1003_008_os_credential_dumping"

	// T1082 — System Information Discovery: /etc/passwd, /etc/group (MEDIUM — low signal)
	RuleT1082SystemInfoDiscovery = "T1082_system_info_discovery"

	// T1053.003 — Scheduled Task/Job: Cron (/var/spool/cron, /etc/cron.d/ writes)
	RuleT1053ScheduledTaskCron = "T1053_003_scheduled_task_cron"

	// T1070.003 — Indicator Removal: Clear Command History (.bash_history)
	RuleT1070ClearCommandHistory = "T1070_003_clear_command_history"
)

// ── Network events (lsm-connect — lsm/socket_connect) ────────────────────────
//
// Sees: dst_ip, dst_port, comm, pid, ppid, uid, mnt_ns_id on every connect().
// Can detect: unauthorised external connections, exfiltration channels.
// Phase 2: add LPMTrie blocked_ips map to enforce blocking at LSM hook level.

const (
	// T1041 · T1048 — Exfiltration Over C2 Channel / Exfiltration Over Alt Protocol
	RuleT1041ExfiltrationOverC2 = "T1041_exfiltration_over_c2"

	// T1046 — Network Service Scanning: burst connections (stateful — significant complexity)
	RuleT1046NetworkServiceScan = "T1046_network_service_scanning"
)
