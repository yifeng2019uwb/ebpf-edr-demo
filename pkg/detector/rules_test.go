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
			if len(alerts) != 0 {
				t.Fatalf("expected no alerts for system namespace %q, got %d", ns, len(alerts))
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
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Rule != "shell_spawn_container" {
		t.Fatalf("Rule = %q, want shell_spawn_container", alerts[0].Rule)
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
	if len(alerts) != 0 {
		t.Fatalf("expected no alerts for normal process, got %d", len(alerts))
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
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Rule != "sensitive_file_access" {
		t.Fatalf("Rule = %q, want sensitive_file_access", alerts[0].Rule)
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
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].Rule != "unauthorized_external_connect" {
		t.Fatalf("Rule = %q, want unauthorized_external_connect", alerts[0].Rule)
	}
}

// ── Process rules ─────────────────────────────────────────────────────────────

func TestCheckProcessRules_ShellSpawn(t *testing.T) {
	shells := []string{"/bin/bash", "/bin/sh", "/usr/bin/zsh", "/bin/dash"}

	for _, comm := range shells {
		t.Run(comm, func(t *testing.T) {
			ev := processor.ProcessEvent{Comm: commBytes(comm)}
			a := checkProcessRules(ev, resolvedResult("auth-service"))

			if a == nil {
				t.Fatalf("expected CRITICAL alert, got nil")
			}
			if a.Rule != "shell_spawn_container" {
				t.Fatalf("Rule = %q, want shell_spawn_container", a.Rule)
			}
			if a.Level != alert.Critical {
				t.Fatalf("Level = %q, want CRITICAL", a.Level)
			}
		})
	}
}

func TestCheckProcessRules_NetworkTool(t *testing.T) {
	tools := []string{"/bin/nc", "/usr/bin/ncat", "/usr/bin/wget"}

	for _, comm := range tools {
		t.Run(comm, func(t *testing.T) {
			ev := processor.ProcessEvent{Comm: commBytes(comm)}
			a := checkProcessRules(ev, resolvedResult("auth-service"))

			if a == nil {
				t.Fatalf("expected HIGH alert, got nil")
			}
			if a.Rule != "network_tool_container" {
				t.Fatalf("Rule = %q, want network_tool_container", a.Rule)
			}
			if a.Level != alert.High {
				t.Fatalf("Level = %q, want HIGH", a.Level)
			}
		})
	}
}

func TestCheckProcessRules_CurlNotNetworkTool(t *testing.T) {
	// curl is excluded from process rules — detected via lsm-connect instead
	ev := processor.ProcessEvent{Comm: commBytes("/usr/bin/curl")}
	a := checkProcessRules(ev, resolvedResult("auth-service"))

	if a != nil {
		t.Fatalf("expected nil for curl (excluded from process rules), got rule=%q", a.Rule)
	}
}

func TestCheckProcessRules_WhitelistedComm(t *testing.T) {
	whitelisted := []string{"sshd", "/usr/sbin/sshd", "runc", "dockerd", "containerd", "getconf"}

	for _, comm := range whitelisted {
		t.Run(comm, func(t *testing.T) {
			ev := processor.ProcessEvent{Comm: commBytes(comm)}
			a := checkProcessRules(ev, resolvedResult("auth-service"))

			if a != nil {
				t.Fatalf("expected nil for whitelisted %q, got rule=%q", comm, a.Rule)
			}
		})
	}
}

func TestCheckProcessRules_StateHost(t *testing.T) {
	ev := processor.ProcessEvent{Comm: commBytes("/bin/bash")}
	res := workload.ResolveResult{State: workload.StateHost}

	a := checkProcessRules(ev, res)

	if a != nil {
		t.Fatalf("expected nil for StateHost, got rule=%q", a.Rule)
	}
}

func TestCheckProcessRules_StateUnknown(t *testing.T) {
	ev := processor.ProcessEvent{Comm: commBytes("someprocess")}
	res := workload.ResolveResult{State: workload.StateUnknown}

	a := checkProcessRules(ev, res)

	if a == nil {
		t.Fatalf("expected CRITICAL for StateUnknown, got nil")
	}
	if a.Rule != "unknown_namespace_process" {
		t.Fatalf("Rule = %q, want unknown_namespace_process", a.Rule)
	}
	if a.Level != alert.Critical {
		t.Fatalf("Level = %q, want CRITICAL", a.Level)
	}
}

func TestCheckProcessRules_NormalProcess(t *testing.T) {
	ev := processor.ProcessEvent{Comm: commBytes("/usr/bin/python3")}
	a := checkProcessRules(ev, resolvedResult("auth-service"))

	if a != nil {
		t.Fatalf("expected nil for normal process, got rule=%q", a.Rule)
	}
}

// ── File rules ────────────────────────────────────────────────────────────────

func TestCheckFileRules_CriticalFiles(t *testing.T) {
	files := []string{
		"/root/.ssh/id_rsa",
		"/root/.ssh/authorized_keys",
		"/home/.ssh/id_ed25519",
	}

	for _, filename := range files {
		t.Run(filename, func(t *testing.T) {
			ev := processor.FileEvent{Comm: commBytes("python3"), Filename: filenameBytes(filename)}
			a := checkFileRules(ev, resolvedResult("auth-service"))

			if a == nil {
				t.Fatalf("expected CRITICAL, got nil")
			}
			if a.Level != alert.Critical {
				t.Fatalf("Level = %q, want CRITICAL", a.Level)
			}
			if a.Rule != "sensitive_file_access" {
				t.Fatalf("Rule = %q, want sensitive_file_access", a.Rule)
			}
		})
	}
}

func TestCheckFileRules_HighFiles(t *testing.T) {
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
			a := checkFileRules(ev, resolvedResult("auth-service"))

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
	// CA bundle .pem files must NOT alert — they are loaded on every HTTPS request
	excluded := []string{
		"/usr/local/lib/python3.9/site-packages/certifi/cacert.pem",
		"/usr/lib/python3/dist-packages/certifi/cacert.pem",
		"/usr/local/lib/python3/site-packages/requests/cacert.pem",
	}

	for _, filename := range excluded {
		t.Run(filename, func(t *testing.T) {
			ev := processor.FileEvent{Comm: commBytes("python3"), Filename: filenameBytes(filename)}
			a := checkFileRules(ev, resolvedResult("auth-service"))

			if a != nil {
				t.Fatalf("expected nil for excluded .pem path, got rule=%q", a.Rule)
			}
		})
	}
}

func TestCheckFileRules_MediumFiles(t *testing.T) {
	files := []string{"/etc/passwd", "/etc/group"}

	for _, filename := range files {
		t.Run(filename, func(t *testing.T) {
			ev := processor.FileEvent{Comm: commBytes("python3"), Filename: filenameBytes(filename)}
			a := checkFileRules(ev, resolvedResult("auth-service"))

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
			a := checkFileRules(ev, resolvedResult("auth-service"))

			if a != nil {
				t.Fatalf("expected nil for whitelisted comm %q, got rule=%q", comm, a.Rule)
			}
		})
	}
}

func TestCheckFileRules_WhitelistedCommAlsoSkipsCriticalFiles(t *testing.T) {
	// whitelist check is BEFORE StateHost branch — must also suppress on container events
	ev := processor.FileEvent{
		Comm:     commBytes("runc:[2:INIT]"),
		Filename: filenameBytes("/root/.ssh/id_rsa"),
	}
	a := checkFileRules(ev, resolvedResult("auth-service"))

	if a != nil {
		t.Fatalf("expected nil for whitelisted comm on critical file, got rule=%q", a.Rule)
	}
}

func TestCheckFileRules_HostReadsContainerFS(t *testing.T) {
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
			a := checkFileRules(ev, res)

			if a == nil {
				t.Fatalf("expected CRITICAL host_reads_container_fs, got nil")
			}
			if a.Rule != "host_reads_container_fs" {
				t.Fatalf("Rule = %q, want host_reads_container_fs", a.Rule)
			}
			if a.Level != alert.Critical {
				t.Fatalf("Level = %q, want CRITICAL", a.Level)
			}
		})
	}
}

func TestCheckFileRules_HostNormalFile(t *testing.T) {
	ev := processor.FileEvent{
		Comm:     commBytes("cat"),
		Filename: filenameBytes("/etc/hostname"),
	}
	res := workload.ResolveResult{State: workload.StateHost}
	a := checkFileRules(ev, res)

	if a != nil {
		t.Fatalf("expected nil for host reading normal file, got rule=%q", a.Rule)
	}
}

func TestCheckFileRules_NormalFile(t *testing.T) {
	ev := processor.FileEvent{
		Comm:     commBytes("python3"),
		Filename: filenameBytes("/app/main.py"),
	}
	a := checkFileRules(ev, resolvedResult("auth-service"))

	if a != nil {
		t.Fatalf("expected nil for normal file, got rule=%q", a.Rule)
	}
}

// ── Network rules ─────────────────────────────────────────────────────────────

func TestCheckNetworkRules_PrivateIP(t *testing.T) {
	privateIPs := []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.0.1"}

	for _, ipStr := range privateIPs {
		t.Run(ipStr, func(t *testing.T) {
			ev := processor.NetEvent{Comm: commBytes("python3")}
			a := checkNetworkRules(ev, resolvedResult("auth-service"), net.ParseIP(ipStr), 80)

			if a != nil {
				t.Fatalf("expected nil for private IP %s, got alert", ipStr)
			}
		})
	}
}

func TestCheckNetworkRules_PublicIPUnauthorized(t *testing.T) {
	ev := processor.NetEvent{Comm: commBytes("python3")}
	ip := net.ParseIP("8.8.8.8")

	a := checkNetworkRules(ev, resolvedResult("auth-service"), ip, 443)

	if a == nil {
		t.Fatalf("expected HIGH for unauthorized external connect, got nil")
	}
	if a.Rule != "unauthorized_external_connect" {
		t.Fatalf("Rule = %q, want unauthorized_external_connect", a.Rule)
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
	// inventory-service is in externalAllowedServices — no alert for any public IP
	ev := processor.NetEvent{Comm: commBytes("python3")}

	a := checkNetworkRules(ev, resolvedResult("inventory-service"), net.ParseIP("104.18.0.1"), 443)

	if a != nil {
		t.Fatalf("expected nil for allowed service, got rule=%q", a.Rule)
	}
}

func TestCheckNetworkRules_StateHost(t *testing.T) {
	ev := processor.NetEvent{Comm: commBytes("curl")}
	res := workload.ResolveResult{State: workload.StateHost}

	a := checkNetworkRules(ev, res, net.ParseIP("8.8.8.8"), 80)

	if a != nil {
		t.Fatalf("expected nil for StateHost, got rule=%q", a.Rule)
	}
}
