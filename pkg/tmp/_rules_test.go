package detector

import (
	"net"
	"testing"

	"ebpf-edr-demo/internal/alert"
	"ebpf-edr-demo/internal/processor"
	"ebpf-edr-demo/pkg/pipeline"
	"ebpf-edr-demo/pkg/workload"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func commBytes(s string) [processor.TaskCommLen]byte {
	var b [processor.TaskCommLen]byte
	copy(b[:], s)
	return b
}

func filenameBytes(s string) [256]byte {
	var b [256]byte
	copy(b[:], s)
	return b
}

func resolvedResult(service string) workload.ResolveResult {
	return workload.ResolveResult{
		Identity: workload.WorkloadIdentity{Runtime: "docker", Service: service},
		State:    workload.StateResolved,
	}
}

// ── Detect() ─────────────────────────────────────────────────────────────────

func TestDetect_SystemNamespaceSuppressed(t *testing.T) {
	d := NewRuleDetector()

	for _, ns := range []string{"kube-system", "gmp-system", "gke-managed-cim"} {
		t.Run(ns, func(t *testing.T) {
			ev := pipeline.EnrichedEvent{
				Type: pipeline.ProcessEventType,
				Process: &processor.ProcessEvent{
					Comm: commBytes("/bin/bash"),
				},
				Workload: workload.ResolveResult{
					State: workload.StateResolved,
					Meta:  workload.WorkloadMeta{Namespace: ns},
				},
			}

			alerts := d.Detect(ev)
			if alerts != nil {
				t.Fatalf("expected no alerts for system namespace %q, got alert", ns)
			}
		})
	}
}

func TestDetect_ReturnsAlertForShellSpawn(t *testing.T) {
	d := NewRuleDetector()

	ev := pipeline.EnrichedEvent{
		Type:    pipeline.ProcessEventType,
		Process: &processor.ProcessEvent{Comm: commBytes("/bin/bash")},
		Workload: workload.ResolveResult{
			Identity: workload.WorkloadIdentity{Runtime: "docker", Service: "auth-service"},
			State:    workload.StateResolved,
		},
	}

	alerts := d.Detect(ev)
	if alerts == nil {
		t.Fatalf("expected 1 alert, got nil")
	}
	if alerts.Rule != RuleT1059UnixShellExecution {
		t.Fatalf("Rule = %q, want %s", alerts.Rule, RuleT1059UnixShellExecution)
	}
}

func TestDetect_NoAlertForNormalProcess(t *testing.T) {
	d := NewRuleDetector()

	ev := pipeline.EnrichedEvent{
		Type:    pipeline.ProcessEventType,
		Process: &processor.ProcessEvent{Comm: commBytes("/usr/bin/python3")},
		Workload: workload.ResolveResult{
			Identity: workload.WorkloadIdentity{Runtime: "docker", Service: "auth-service"},
			State:    workload.StateResolved,
		},
	}

	alerts := d.Detect(ev)
	if alerts != nil {
		t.Fatalf("expected no alerts for normal process, got alert")
	}
}

func TestDetect_FileEvent(t *testing.T) {
	d := NewRuleDetector()

	ev := pipeline.EnrichedEvent{
		Type: pipeline.FileEventType,
		File: &processor.FileEvent{
			Comm:     commBytes("python3"),
			Filename: filenameBytes("/etc/shadow"),
		},
		Workload: workload.ResolveResult{
			Identity: workload.WorkloadIdentity{Runtime: "docker", Service: "auth-service"},
			State:    workload.StateResolved,
		},
	}

	alerts := d.Detect(ev)
	if alerts == nil {
		t.Fatalf("expected 1 alert, got alert))
	}
	if alerts.Rule != RuleT1003OsCredentialDumping {
		t.Fatalf("Rule = %q, want %s", alerts.Rule, RuleT1003OsCredentialDumping)
	}
}

func TestDetect_NetEvent(t *testing.T) {
	d := NewRuleDetector()

	ev := pipeline.EnrichedEvent{
		Type: pipeline.NetEventType,
		Net: &processor.NetEvent{
			Comm:    commBytes("python3"),
			DstIp:  0x08080808, // 8.8.8.8
			DstPort: 0x5000,    // port 80 in network byte order
		},
		Workload: workload.ResolveResult{
			Identity: workload.WorkloadIdentity{Runtime: "docker", Service: "auth-service"},
			State:    workload.StateResolved,
		},
	}

	alerts := d.Detect(ev)
	if alerts == nil {
		t.Fatalf("expected 1 alert, got alert))
	}
	if alerts.Rule != RuleT1041ExfiltrationOverC2 {
		t.Fatalf("Rule = %q, want %s", alerts.Rule, RuleT1041ExfiltrationOverC2)
	}
}

// ── Process rules ─────────────────────────────────────────────────────────────

func TestCheckProcessRules_ShellSpawn(t *testing.T) {
	d := NewRuleDetector()
	shells := []string{"/bin/bash", "/bin/sh", "/usr/bin/zsh", "/bin/dash"}

	for _, comm := range shells {
		t.Run(comm, func(t *testing.T) {
			ev := processor.ProcessEvent{Comm: commBytes(comm)}
			a := d.checkProcessRules(ev, resolvedResult("auth-service"))

			if a == nil {
				t.Fatalf("expected CRITICAL alert, got nil")
			}
			if a.Rule != RuleT1059UnixShellExecution {
				t.Fatalf("Rule = %q, want %s", a.Rule, RuleT1059UnixShellExecution)
			}
			if a.Level != alert.Critical {
				t.Fatalf("Level = %q, want CRITICAL", a.Level)
			}
		})
	}
}

func TestCheckProcessRules_NetworkTool(t *testing.T) {
	d := NewRuleDetector()
	tools := []string{"/bin/nc", "/usr/bin/ncat", "/usr/bin/wget"}

	for _, comm := range tools {
		t.Run(comm, func(t *testing.T) {
			ev := processor.ProcessEvent{Comm: commBytes(comm)}
			a := d.checkProcessRules(ev, resolvedResult("auth-service"))

			if a == nil {
				t.Fatalf("expected HIGH alert, got nil")
			}
			if a.Rule != RuleT1105IngressToolTransfer {
				t.Fatalf("Rule = %q, want %s", a.Rule, RuleT1105IngressToolTransfer)
			}
			if a.Level != alert.High {
				t.Fatalf("Level = %q, want HIGH", a.Level)
			}
		})
	}
}

func TestCheckProcessRules_CurlNotNetworkTool(t *testing.T) {
	d := NewRuleDetector()
	// curl is excluded from process rules — detected via lsm-connect instead
	ev := processor.ProcessEvent{Comm: commBytes("/usr/bin/curl")}
	a := d.checkProcessRules(ev, resolvedResult("auth-service"))

	if a != nil {
		t.Fatalf("expected nil for curl (excluded from process rules), got rule=%q", a.Rule)
	}
}

func TestCheckProcessRules_WhitelistedComm(t *testing.T) {
	d := NewRuleDetector()
	whitelisted := []string{"sshd", "/usr/sbin/sshd", "runc", "dockerd", "containerd", "getconf"}

	for _, comm := range whitelisted {
		t.Run(comm, func(t *testing.T) {
			ev := processor.ProcessEvent{Comm: commBytes(comm)}
			a := d.checkProcessRules(ev, resolvedResult("auth-service"))

			if a != nil {
				t.Fatalf("expected nil for whitelisted %q, got rule=%q", comm, a.Rule)
			}
		})
	}
}

func TestCheckProcessRules_StateHost(t *testing.T) {
	d := NewRuleDetector()
	ev := processor.ProcessEvent{Comm: commBytes("/bin/bash")}
	res := workload.ResolveResult{State: workload.StateHost}

	a := d.checkProcessRules(ev, res)

	if a != nil {
		t.Fatalf("expected nil for StateHost, got rule=%q", a.Rule)
	}
}

func TestCheckProcessRules_StateUnknown(t *testing.T) {
	d := NewRuleDetector()
	ev := processor.ProcessEvent{Comm: commBytes("someprocess")}
	res := workload.ResolveResult{State: workload.StateUnknown}

	a := d.checkProcessRules(ev, res)

	if a == nil {
		t.Fatalf("expected CRITICAL for StateUnknown, got nil")
	}
	if a.Rule != RuleT1611EscapeToHostNs {
		t.Fatalf("Rule = %q, want %s", a.Rule, RuleT1611EscapeToHostNs)
	}
	if a.Level != alert.Critical {
		t.Fatalf("Level = %q, want CRITICAL", a.Level)
	}
}

func TestCheckProcessRules_NormalProcess(t *testing.T) {
	d := NewRuleDetector()
	ev := processor.ProcessEvent{Comm: commBytes("/usr/bin/python3")}
	a := d.checkProcessRules(ev, resolvedResult("auth-service"))

	if a != nil {
		t.Fatalf("expected nil for normal process, got rule=%q", a.Rule)
	}
}

// ── File rules ────────────────────────────────────────────────────────────────

func TestCheckFileRules_CriticalFiles(t *testing.T) {
	d := NewRuleDetector()
	files := []string{
		"/root/.ssh/id_rsa",
		"/root/.ssh/authorized_keys",
		"/home/.ssh/id_ed25519",
	}

	for _, filename := range files {
		t.Run(filename, func(t *testing.T) {
			ev := processor.FileEvent{Comm: commBytes("python3"), Filename: filenameBytes(filename)}
			a := d.checkFileRules(ev, resolvedResult("auth-service"))

			if a == nil {
				t.Fatalf("expected CRITICAL, got nil")
			}
			if a.Level != alert.Critical {
				t.Fatalf("Level = %q, want CRITICAL", a.Level)
			}
			if a.Rule != RuleT1552PrivateKeys {
				t.Fatalf("Rule = %q, want %s", a.Rule, RuleT1552PrivateKeys)
			}
		})
	}
}

func TestCheckFileRules_HighFiles(t *testing.T) {
	d := NewRuleDetector()
	files := []string{
		"/etc/shadow",
		"/run/secrets/db-password",
		"/proc/1/maps",
		"/app/server.key",
		"/app/id_rsa",
		"/app/config.env",
		"/app/server.pem",
	}

	for _, filename := range files {
		t.Run(filename, func(t *testing.T) {
			ev := processor.FileEvent{Comm: commBytes("python3"), Filename: filenameBytes(filename)}
			a := d.checkFileRules(ev, resolvedResult("auth-service"))

			if a == nil {
				t.Fatalf("expected HIGH, got nil for %q", filename)
			}
			if a.Level != alert.High {
				t.Fatalf("Level = %q, want HIGH for %q", a.Level, filename)
			}
		})
	}
}

func TestCheckFileRules_PemExcludedPaths(t *testing.T) {
	d := NewRuleDetector()
	// CA bundle .pem files must NOT alert — they are loaded on every HTTPS request
	excluded := []string{
		"/usr/local/lib/python3.9/site-packages/certifi/cacert.pem",
		"/usr/lib/python3/dist-packages/certifi/cacert.pem",
		"/usr/local/lib/python3/site-packages/requests/cacert.pem",
	}

	for _, filename := range excluded {
		t.Run(filename, func(t *testing.T) {
			ev := processor.FileEvent{Comm: commBytes("python3"), Filename: filenameBytes(filename)}
			a := d.checkFileRules(ev, resolvedResult("auth-service"))

			if a != nil {
				t.Fatalf("expected nil for excluded .pem path, got rule=%q", a.Rule)
			}
		})
	}
}

func TestCheckFileRules_MediumFiles(t *testing.T) {
	d := NewRuleDetector()
	files := []string{"/etc/passwd", "/etc/group"}

	for _, filename := range files {
		t.Run(filename, func(t *testing.T) {
			ev := processor.FileEvent{Comm: commBytes("python3"), Filename: filenameBytes(filename)}
			a := d.checkFileRules(ev, resolvedResult("auth-service"))

			if a == nil {
				t.Fatalf("expected MEDIUM, got nil")
			}
			if a.Level != alert.Medium {
				t.Fatalf("Level = %q, want MEDIUM", a.Level)
			}
		})
	}
}

func TestCheckFileRules_WhitelistedCommSkipsAllFiles(t *testing.T) {
	d := NewRuleDetector()
	// fileCommWhitelist is checked before any path rule — matched by exact comm string
	whitelisted := []string{
		"runc",
		"runc:[2:INIT]",
		"runc:[1:CHILD]",
		"curl",
		"id",
		"bash",
		"containerd-shim",
	}

	for _, comm := range whitelisted {
		t.Run(comm, func(t *testing.T) {
			ev := processor.FileEvent{
				Comm:     commBytes(comm),
				Filename: filenameBytes("/etc/passwd"),
			}
			a := d.checkFileRules(ev, resolvedResult("auth-service"))

			if a != nil {
				t.Fatalf("expected nil for whitelisted comm %q, got rule=%q", comm, a.Rule)
			}
		})
	}
}

func TestCheckFileRules_WhitelistedCommAlsoSkipsCriticalFiles(t *testing.T) {
	d := NewRuleDetector()
	// whitelist check is BEFORE StateHost branch — must also suppress on container events
	ev := processor.FileEvent{
		Comm:     commBytes("runc:[2:INIT]"),
		Filename: filenameBytes("/root/.ssh/id_rsa"),
	}
	a := d.checkFileRules(ev, resolvedResult("auth-service"))

	if a != nil {
		t.Fatalf("expected nil for whitelisted comm on critical file, got rule=%q", a.Rule)
	}
}

func TestCheckFileRules_HostReadsContainerFS(t *testing.T) {
	d := NewRuleDetector()
	files := []string{
		"/var/lib/docker/overlay2/abc123/merged/etc/passwd",
		"/run/containerd/io.containerd.runtime.v2.task/k8s.io/abc/rootfs/etc/shadow",
	}

	for _, filename := range files {
		t.Run(filename, func(t *testing.T) {
			ev := processor.FileEvent{
				Comm:     commBytes("cat"),
				Filename: filenameBytes(filename),
			}
			res := workload.ResolveResult{State: workload.StateHost}
			a := d.checkFileRules(ev, res)

			if a == nil {
				t.Fatalf("expected CRITICAL host_reads_container_fs, got nil")
			}
			if a.Rule != RuleT1611EscapeToHostFs {
				t.Fatalf("Rule = %q, want %s", a.Rule, RuleT1611EscapeToHostFs)
			}
			if a.Level != alert.Critical {
				t.Fatalf("Level = %q, want CRITICAL", a.Level)
			}
		})
	}
}

func TestCheckFileRules_HostNormalFile(t *testing.T) {
	d := NewRuleDetector()
	ev := processor.FileEvent{
		Comm:     commBytes("cat"),
		Filename: filenameBytes("/etc/hostname"),
	}
	res := workload.ResolveResult{State: workload.StateHost}
	a := d.checkFileRules(ev, res)

	if a != nil {
		t.Fatalf("expected nil for host reading normal file, got rule=%q", a.Rule)
	}
}

func TestCheckFileRules_NormalFile(t *testing.T) {
	d := NewRuleDetector()
	ev := processor.FileEvent{
		Comm:     commBytes("python3"),
		Filename: filenameBytes("/app/main.py"),
	}
	a := d.checkFileRules(ev, resolvedResult("auth-service"))

	if a != nil {
		t.Fatalf("expected nil for normal file, got rule=%q", a.Rule)
	}
}

// ── Network rules ─────────────────────────────────────────────────────────────

func TestCheckNetworkRules_PrivateIP(t *testing.T) {
	d := NewRuleDetector()
	privateIPs := []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.0.1"}

	for _, ipStr := range privateIPs {
		t.Run(ipStr, func(t *testing.T) {
			ev := processor.NetEvent{Comm: commBytes("python3")}
			a := d.checkNetworkRules(ev, resolvedResult("auth-service"), net.ParseIP(ipStr), 80)

			if a != nil {
				t.Fatalf("expected nil for private IP %s, got alert", ipStr)
			}
		})
	}
}

func TestCheckNetworkRules_PublicIPUnauthorized(t *testing.T) {
	d := NewRuleDetector()
	ev := processor.NetEvent{Comm: commBytes("python3")}
	ip := net.ParseIP("8.8.8.8")

	a := d.checkNetworkRules(ev, resolvedResult("auth-service"), ip, 443)

	if a == nil {
		t.Fatalf("expected HIGH for unauthorized external connect, got nil")
	}
	if a.Rule != RuleT1041ExfiltrationOverC2 {
		t.Fatalf("Rule = %q, want %s", a.Rule, RuleT1041ExfiltrationOverC2)
	}
	if a.Level != alert.High {
		t.Fatalf("Level = %q, want HIGH", a.Level)
	}
	if a.DstIP != "8.8.8.8" {
		t.Fatalf("DstIP = %q, want 8.8.8.8", a.DstIP)
	}
	if a.DstPort != 443 {
		t.Fatalf("DstPort = %d, want 443", a.DstPort)
	}
}

func TestCheckNetworkRules_AllowedService(t *testing.T) {
	d := NewRuleDetector()
	// inventory-service is in externalAllowedServices — no alert for any public IP
	ev := processor.NetEvent{Comm: commBytes("python3")}

	a := d.checkNetworkRules(ev, resolvedResult("inventory-service"), net.ParseIP("104.18.0.1"), 443)

	if a != nil {
		t.Fatalf("expected nil for allowed service, got rule=%q", a.Rule)
	}
}

func TestCheckNetworkRules_StateHost(t *testing.T) {
	d := NewRuleDetector()
	ev := processor.NetEvent{Comm: commBytes("curl")}
	res := workload.ResolveResult{State: workload.StateHost}

	a := d.checkNetworkRules(ev, res, net.ParseIP("8.8.8.8"), 80)

	if a != nil {
		t.Fatalf("expected nil for StateHost, got rule=%q", a.Rule)
	}
}

// ── T1036 — Masquerading ──────────────────────────────────────────────────────

func TestCheckProcessRules_Masquerading(t *testing.T) {
	d := NewRuleDetector()
	suspicious := []string{"/tmp/sshd", "/dev/shm/backdoor", "/var/tmp/python3", "/run/user/1000/evil"}

	for _, comm := range suspicious {
		t.Run(comm, func(t *testing.T) {
			ev := processor.ProcessEvent{Comm: commBytes(comm)}
			a := d.checkProcessRules(ev, resolvedResult("auth-service"))

			if a == nil {
				t.Fatalf("expected HIGH alert for masquerading, got nil")
			}
			if a.Rule != RuleT1036Masquerading {
				t.Fatalf("Rule = %q, want %s", a.Rule, RuleT1036Masquerading)
			}
			if a.Level != alert.High {
				t.Fatalf("Level = %q, want HIGH", a.Level)
			}
		})
	}
}

func TestCheckProcessRules_MasqueradingBeforeWhitelist(t *testing.T) {
	d := NewRuleDetector()
	// /tmp/sshd should fire even though "sshd" is in whitelistComm
	ev := processor.ProcessEvent{Comm: commBytes("/tmp/sshd")}
	a := d.checkProcessRules(ev, resolvedResult("auth-service"))

	if a == nil {
		t.Fatalf("expected alert for /tmp/sshd — masquerade check must run before whitelist")
	}
	if a.Rule != RuleT1036Masquerading {
		t.Fatalf("Rule = %q, want %s", a.Rule, RuleT1036Masquerading)
	}
}

func TestCheckProcessRules_NormalPath(t *testing.T) {
	d := NewRuleDetector()
	// binary in a normal system path must not trigger masquerading
	ev := processor.ProcessEvent{Comm: commBytes("/usr/bin/python3")}
	a := d.checkProcessRules(ev, resolvedResult("auth-service"))

	if a != nil && a.Rule == RuleT1036Masquerading {
		t.Fatalf("unexpected masquerading alert for %q", "/usr/bin/python3")
	}
}

// ── T1613 — Container and Resource Discovery ──────────────────────────────────

func TestCheckProcessRules_ContainerDiscovery(t *testing.T) {
	d := NewRuleDetector()
	tools := []string{"/usr/bin/kubectl", "/usr/bin/docker", "/usr/local/bin/crictl", "/usr/bin/podman"}

	for _, comm := range tools {
		t.Run(comm, func(t *testing.T) {
			ev := processor.ProcessEvent{Comm: commBytes(comm)}
			a := d.checkProcessRules(ev, resolvedResult("auth-service"))

			if a == nil {
				t.Fatalf("expected HIGH alert for container discovery tool, got nil")
			}
			if a.Rule != RuleT1613ContainerDiscovery {
				t.Fatalf("Rule = %q, want %s", a.Rule, RuleT1613ContainerDiscovery)
			}
			if a.Level != alert.High {
				t.Fatalf("Level = %q, want HIGH", a.Level)
			}
		})
	}
}

// ── T1053.003 — Scheduled Task/Cron ──────────────────────────────────────────

func TestCheckFileRules_CronAccess(t *testing.T) {
	d := NewRuleDetector()
	cronFiles := []string{
		"/etc/cron.d/malicious",
		"/etc/cron.daily/backdoor",
		"/var/spool/cron/root",
		"/etc/crontab",
	}

	for _, filename := range cronFiles {
		t.Run(filename, func(t *testing.T) {
			ev := processor.FileEvent{Comm: commBytes("sh"), Filename: filenameBytes(filename)}
			a := d.checkFileRules(ev, resolvedResult("auth-service"))

			if a == nil {
				t.Fatalf("expected HIGH alert for cron access, got nil")
			}
			if a.Rule != RuleT1053ScheduledTaskCron {
				t.Fatalf("Rule = %q, want %s", a.Rule, RuleT1053ScheduledTaskCron)
			}
			if a.Level != alert.High {
				t.Fatalf("Level = %q, want HIGH", a.Level)
			}
		})
	}
}

// ── T1070.003 — Clear Command History ────────────────────────────────────────

func TestCheckFileRules_CommandHistoryAccess(t *testing.T) {
	d := NewRuleDetector()
	historyFiles := []string{
		"/root/.bash_history",
		"/home/user/.bash_history",
		"/root/.zsh_history",
		"/root/.ash_history",
	}

	for _, filename := range historyFiles {
		t.Run(filename, func(t *testing.T) {
			ev := processor.FileEvent{Comm: commBytes("sh"), Filename: filenameBytes(filename)}
			a := d.checkFileRules(ev, resolvedResult("auth-service"))

			if a == nil {
				t.Fatalf("expected MEDIUM alert for history access, got nil")
			}
			if a.Rule != RuleT1070ClearCommandHistory {
				t.Fatalf("Rule = %q, want %s", a.Rule, RuleT1070ClearCommandHistory)
			}
			if a.Level != alert.Medium {
				t.Fatalf("Level = %q, want MEDIUM", a.Level)
			}
		})
	}
}
