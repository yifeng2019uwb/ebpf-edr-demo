package detector

import (
	"os"
	"path/filepath"
	"testing"

	"ebpf-edr-demo/internal/alert"
	"ebpf-edr-demo/internal/processor"
	"ebpf-edr-demo/pkg/rules"
	"ebpf-edr-demo/pkg/workload"
)

// Fixture rules crafted to exercise the structured-matcher semantics
// (production lists have no overlap between match and exception lists,
// so the exception path needs its own fixture: safe-tool is both a
// network_tool and a customer_application).
const testDefaultYAML = `rules:
  lists:
    - name: shell_processes
      items: [bash, sh]
    - name: network_tools
      items: [nc, safe-tool]
    - name: container_mgmt_tools
      items: [kubectl]
    - name: suspicious_exec_paths
      items: [/tmp/, /dev/shm/]
    - name: customer_applications
      items: [safe-tool]
    - name: ssh_key_dirs
      items: [/root/.ssh/]
    - name: ssh_key_suffixes
      items: [.pem, id_rsa]
    - name: pem_exclude_paths
      items: [/certifi/]
    - name: credential_dump_paths
      items: [/etc/shadow]
    - name: proc_escape_paths
      items: [/proc/1/]
    - name: proc_escape_allowed
      items: [/proc/1/stat]
    - name: recon_file_readers
      items: [cat, grep]
    - name: system_info_paths
      items: [/etc/passwd, /etc/group]
    - name: whitelisted_file_access_procs
      items: ["runc:[2:INIT]", "runc:[1:CHILD]"]
    - name: private_ranges
      items: [10.0.0.0/8, 127.0.0.0/8]
    - name: allowed_ports
      items: [53]
    - name: allowed_services
      items: [inventory-service]
`

const testProcessYAML = `detections:
  - name: T1059_unix_shell_execution
    severity: CRITICAL
    require_container: true
    match: {comm_suffix_in: shell_processes}
    exceptions: [{comm_base_in: customer_applications}]
    message: "shell in container"
  - name: T1105_ingress_tool_transfer
    severity: HIGH
    require_container: true
    match: {comm_suffix_in: network_tools}
    exceptions: [{comm_base_in: customer_applications}]
    message: "network tool in container"
  - name: T1613_container_resource_discovery
    severity: HIGH
    require_container: true
    match: {comm_suffix_in: container_mgmt_tools}
    message: "mgmt tool in container"
  - name: T1036_masquerading
    severity: HIGH
    require_container: false
    match: {comm_prefix_in: suspicious_exec_paths}
    message: "suspicious path"
`

const testFileYAML = `detections:
  - name: T1552_004_private_keys
    severity: CRITICAL
    require_container: true
    match: {file_prefix_in: ssh_key_dirs}
    exceptions: [{comm_base_in: customer_applications}]
    message: "ssh dir"
  - name: T1003_008_os_credential_dumping
    severity: CRITICAL
    require_container: true
    match: {file_prefix_in: credential_dump_paths}
    message: "shadow"
  - name: T1611_escape_to_host_proc
    severity: HIGH
    require_container: true
    match: {file_prefix_in: proc_escape_paths}
    exceptions: [{file_exact_in: proc_escape_allowed}]
    message: "proc escape"
  - name: T1552_004_private_keys
    severity: HIGH
    require_container: true
    match: {file_suffix_in: ssh_key_suffixes}
    exceptions: [{file_contains_in: pem_exclude_paths}, {comm_base_in: customer_applications}]
    message: "key file"
  - name: T1082_system_info_discovery
    severity: MEDIUM
    require_container: true
    match: {comm_base_in: recon_file_readers, file_prefix_in: system_info_paths}
    message: "system file recon"
`

const testNetworkYAML = `detections:
  - name: T1041_exfiltration_over_c2
    severity: HIGH
    require_container: true
    match: {dst_ip_not_in: private_ranges}
    exceptions: [{dst_port_in: allowed_ports}, {service_in: allowed_services}]
    message: "external connection"
`

func newTestDetector(t *testing.T) *YAMLDetector {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "common.yaml"), []byte(testDefaultYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "process.yaml"), []byte(testProcessYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file.yaml"), []byte(testFileYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "network.yaml"), []byte(testNetworkYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := rules.LoadRules(filepath.Join(dir, "common.yaml"))
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	return NewYAMLDetectorWithRuntime(db, workload.RuntimeDocker)
}

func processEvent(comm string, ppid int32) processor.ProcessEvent {
	var ev processor.ProcessEvent
	ev.Pid = 100
	ev.Ppid = ppid
	copy(ev.Comm[:], comm)
	return ev
}

func fileEvent(comm, filename string, ppid int32) processor.FileEvent {
	var ev processor.FileEvent
	ev.Pid = 100
	ev.Ppid = ppid
	copy(ev.Comm[:], comm)
	copy(ev.Filename[:], filename)
	return ev
}

var (
	verifiedContainer = workload.ResolveResult{
		State:    workload.StateResolved,
		Identity: workload.WorkloadIdentity{Runtime: workload.RuntimeDocker, Service: "user_service"},
	}
	verifiedHost = workload.ResolveResult{
		State:    workload.StateResolved,
		Identity: workload.WorkloadIdentity{Runtime: workload.RuntimeHost, Service: "host-process"},
	}
	unknownState = workload.ResolveResult{State: workload.StateUnknown}
)

// unresolvablePpid: no such pid, so the ancestry walk fails closed
// (resolveParent's /proc read fails → chain broke → not trusted).
const unresolvablePpid = 4_000_000

func TestCheckProcessRules(t *testing.T) {
	d := newTestDetector(t)

	cases := []struct {
		name     string
		comm     string
		res      workload.ResolveResult
		wantRule string // "" = no alert
		wantLvl  alert.Level
	}{
		{"shell in container", "/bin/bash", verifiedContainer, "T1059_unix_shell_execution", alert.Critical},
		{"network tool in container", "/usr/bin/nc", verifiedContainer, "T1105_ingress_tool_transfer", alert.High},
		{"mgmt tool in container", "/usr/bin/kubectl", verifiedContainer, "T1613_container_resource_discovery", alert.High},
		// Order: /tmp/bash matches both T1059 (CRITICAL) and T1036 (HIGH);
		// file order (CRITICAL first) must win.
		{"tmp shell in container fires T1059", "/tmp/bash", verifiedContainer, "T1059_unix_shell_execution", alert.Critical},
		// Exceptions: safe-tool is in network_tools AND customer_applications.
		{"customer app excepted", "/usr/bin/safe-tool", verifiedContainer, "", ""},
		// require_container: false — T1036 fires for host and unknown state.
		{"masquerading on host", "/tmp/evil", verifiedHost, "T1036_masquerading", alert.High},
		{"masquerading unknown state", "/tmp/evil", unknownState, "T1036_masquerading", alert.High},
		// Container-gated rules must NOT fire off-container.
		{"shell on host is not T1059", "/bin/bash", verifiedHost, "", ""},
		// Unknown state + unverifiable ancestry → LOW telemetry, not CRITICAL.
		{"unknown state telemetry", "/usr/bin/mystery", unknownState, RuleEDRTelemetryUnresolvedNamespace, alert.Low},
		{"benign process in container", "/usr/local/bin/python3", verifiedContainer, "", ""},
		{"init-spawned skipped", "/bin/bash", verifiedContainer, "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ppid := int32(unresolvablePpid)
			if tc.name == "init-spawned skipped" {
				ppid = 1
			}
			a := d.checkProcessRules(processEvent(tc.comm, ppid), tc.res)
			if tc.wantRule == "" {
				if a != nil {
					t.Fatalf("expected no alert, got %s (%s)", a.Rule, a.Level)
				}
				return
			}
			if a == nil {
				t.Fatalf("expected %s, got no alert", tc.wantRule)
			}
			if a.Rule != tc.wantRule || a.Level != tc.wantLvl {
				t.Errorf("got %s/%s, want %s/%s", a.Rule, a.Level, tc.wantRule, tc.wantLvl)
			}
		})
	}
}

func TestCheckFileRules(t *testing.T) {
	d := newTestDetector(t)

	cases := []struct {
		name     string
		comm     string
		filename string
		res      workload.ResolveResult
		wantRule string // "" = no alert
		wantLvl  alert.Level
	}{
		// Order: /root/.ssh/id_rsa matches both the dirs entry (CRITICAL) and
		// the suffix entry (HIGH); file order (CRITICAL first) must win.
		{"ssh dir", "/usr/bin/python3", "/root/.ssh/id_rsa", verifiedContainer, "T1552_004_private_keys", alert.Critical},
		{"shadow", "/usr/bin/python3", "/etc/shadow", verifiedContainer, "T1003_008_os_credential_dumping", alert.Critical},
		{"proc escape", "/usr/bin/python3", "/proc/1/environ", verifiedContainer, "T1611_escape_to_host_proc", alert.High},
		// file_exact_in exception: allowed read-only /proc/1/ files.
		{"proc escape allowed", "/usr/bin/python3", "/proc/1/stat", verifiedContainer, "", ""},
		// Key file outside ssh dirs → suffix entry (HIGH).
		{"key file suffix", "/usr/bin/python3", "/app/id_rsa", verifiedContainer, "T1552_004_private_keys", alert.High},
		// file_contains_in exception: CA bundles.
		{"pem CA bundle excluded", "/usr/bin/python3", "/lib/certifi/cacert.pem", verifiedContainer, "", ""},
		// comm_base_in exception on a file rule.
		{"customer app excepted", "/usr/bin/safe-tool", "/root/.ssh/id_rsa", verifiedContainer, "", ""},
		// T1082 reader gate: recon tool reading /etc/passwd fires; the app's own read does not.
		{"passwd via cat", "/bin/cat", "/etc/passwd", verifiedContainer, "T1082_system_info_discovery", alert.Medium},
		{"passwd via app", "/usr/bin/python3", "/etc/passwd", verifiedContainer, "", ""},
		// Container gating: file rules never fire off-container or for unknown state.
		{"shadow on host", "/usr/bin/python3", "/etc/shadow", verifiedHost, "", ""},
		{"shadow unknown state", "/usr/bin/python3", "/etc/shadow", unknownState, "", ""},
		// runc init states are whitelisted before any rule (Go pipeline).
		{"runc init state", "runc:[2:INIT]", "/etc/shadow", verifiedContainer, "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := d.checkFileRules(fileEvent(tc.comm, tc.filename, unresolvablePpid), tc.res)
			if tc.wantRule == "" {
				if a != nil {
					t.Fatalf("expected no alert, got %s (%s)", a.Rule, a.Level)
				}
				return
			}
			if a == nil {
				t.Fatalf("expected %s, got no alert", tc.wantRule)
			}
			if a.Rule != tc.wantRule || a.Level != tc.wantLvl {
				t.Errorf("got %s/%s, want %s/%s", a.Rule, a.Level, tc.wantRule, tc.wantLvl)
			}
		})
	}
}
