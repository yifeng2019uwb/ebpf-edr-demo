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
`

const testProcessYAML = `detections:
  - name: T1059_unix_shell_execution
    severity: CRITICAL
    require_container: true
    match: {comm_suffix_in: shell_processes}
    exceptions: {comm_base_in: customer_applications}
    message: "shell in container"
  - name: T1105_ingress_tool_transfer
    severity: HIGH
    require_container: true
    match: {comm_suffix_in: network_tools}
    exceptions: {comm_base_in: customer_applications}
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

func newTestDetector(t *testing.T) *YAMLDetector {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "default.yaml"), []byte(testDefaultYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "process.yaml"), []byte(testProcessYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := rules.LoadRules(filepath.Join(dir, "default.yaml"))
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
