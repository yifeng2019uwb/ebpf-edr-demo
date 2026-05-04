package alert

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebpf-edr-demo/pkg/workload"
)

// newTestHandler creates a Handler writing to a temp file, bypassing NewHandler's
// hardcoded paths. Used only in tests.
func newTestHandler(t *testing.T) (*Handler, string) {
	t.Helper()
	dir := t.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, "alert.log"), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("creating test alert file: %v", err)
	}
	return &Handler{file: f}, filepath.Join(dir, "alert.log")
}

func readAlertFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading alert file: %v", err)
	}
	return string(b)
}

func TestHandlerSend_WritesFormattedLine(t *testing.T) {
	h, path := newTestHandler(t)

	h.Send(Alert{
		Level:   Critical,
		Rule:    "shell_spawn_container",
		Message: "Shell spawned from container",
		Pid:     1234,
		Ppid:    1,
		Uid:     0,
		Comm:    "bash",
		Workload: workload.ResolveResult{
			Identity: workload.WorkloadIdentity{Runtime: "docker", Service: "auth-service"},
			Meta:     workload.WorkloadMeta{Pod: "auth-service", Namespace: "default"},
			State:    workload.StateResolved,
		},
	})
	h.Close()

	line := readAlertFile(t, path)

	for _, want := range []string{
		"ALERT",
		"level=CRITICAL",
		"rule=shell_spawn_container",
		"runtime=docker",
		"service=auth-service",
		"namespace=default",
		"comm=bash",
		"pid=1234",
		"msg=Shell spawned from container",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("alert line missing %q\ngot: %s", want, line)
		}
	}
}

func TestHandlerSend_FilenameInExtra(t *testing.T) {
	h, path := newTestHandler(t)

	h.Send(Alert{
		Level:    High,
		Rule:     "sensitive_file_access",
		Message:  "Container accessed SSH key",
		Comm:     "cat",
		Filename: "/root/.ssh/id_rsa",
		Workload: workload.ResolveResult{State: workload.StateResolved},
	})
	h.Close()

	line := readAlertFile(t, path)
	if !strings.Contains(line, "filename=/root/.ssh/id_rsa") {
		t.Fatalf("expected filename in alert line, got: %s", line)
	}
}

func TestHandlerSend_DstIPInExtra(t *testing.T) {
	h, path := newTestHandler(t)

	h.Send(Alert{
		Level:   High,
		Rule:    "unauthorized_external_connect",
		Message: "Unauthorized external connection",
		Comm:    "python3",
		DstIP:   "8.8.8.8",
		DstPort: 443,
		Workload: workload.ResolveResult{State: workload.StateResolved},
	})
	h.Close()

	line := readAlertFile(t, path)
	if !strings.Contains(line, "dst=8.8.8.8:443") {
		t.Fatalf("expected dst in alert line, got: %s", line)
	}
}

func TestHandlerSend_FilenameTakesPriorityOverDstIP(t *testing.T) {
	// When both Filename and DstIP are set, Filename wins (first branch in Send)
	h, path := newTestHandler(t)

	h.Send(Alert{
		Level:    High,
		Rule:     "sensitive_file_access",
		Comm:     "cat",
		Filename: "/etc/shadow",
		DstIP:    "8.8.8.8",
		DstPort:  80,
		Workload: workload.ResolveResult{State: workload.StateResolved},
	})
	h.Close()

	line := readAlertFile(t, path)
	if !strings.Contains(line, "filename=/etc/shadow") {
		t.Fatalf("expected filename in alert, got: %s", line)
	}
	if strings.Contains(line, "dst=") {
		t.Fatalf("expected no dst when filename is set, got: %s", line)
	}
}

func TestHandlerClose_DoesNotPanic(t *testing.T) {
	h, _ := newTestHandler(t)
	h.Close()
}

func TestNewHandler_CreatesDirectoryAndFile(t *testing.T) {
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working dir: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer os.Chdir(orig)

	h, err := NewHandler()
	if err != nil {
		t.Fatalf("NewHandler() error: %v", err)
	}
	defer h.Close()

	if _, err := os.Stat(alertDir); err != nil {
		t.Fatalf("alert directory not created: %v", err)
	}
	if _, err := os.Stat(alertPath); err != nil {
		t.Fatalf("alert file not created: %v", err)
	}
}

func TestHandlerSend_WriteErrorDoesNotPanic(t *testing.T) {
	// Close the file before Send to trigger the WriteString error path
	h, _ := newTestHandler(t)
	h.Close()

	h.Send(Alert{
		Level:    High,
		Rule:     "sensitive_file_access",
		Comm:     "cat",
		Workload: workload.ResolveResult{State: workload.StateResolved},
	})
}

func TestNewHandler_CloudLoggingDisabledWhenProjectUnset(t *testing.T) {
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working dir: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer os.Chdir(orig)

	t.Setenv("GOOGLE_CLOUD_PROJECT", "")

	h, err := NewHandler()
	if err != nil {
		t.Fatalf("NewHandler() error: %v", err)
	}
	defer h.Close()

	if h.cloudLogger != nil {
		t.Fatal("expected cloudLogger nil when GOOGLE_CLOUD_PROJECT not set")
	}
}

func TestAlertPayload_JSONFields(t *testing.T) {
	p := alertPayload{
		SchemaVersion: 1,
		Ts:            "2026-05-04T00:00:00Z",
		Level:         "CRITICAL",
		Rule:          "shell_spawn_container",
		Cluster:       "my-cluster",
		Service:       "auth-service",
		Namespace:     "default",
		Comm:          "bash",
	}

	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)

	for _, want := range []string{
		`"schema_version":1`,
		`"ts":"2026-05-04T00:00:00Z"`,
		`"level":"CRITICAL"`,
		`"rule":"shell_spawn_container"`,
		`"cluster":"my-cluster"`,
		`"service":"auth-service"`,
		`"namespace":"default"`,
		`"comm":"bash"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in JSON\ngot: %s", want, s)
		}
	}

	// omitempty fields absent when zero
	if strings.Contains(s, `"filename"`) {
		t.Fatalf("expected filename omitted when empty, got: %s", s)
	}
	if strings.Contains(s, `"dst_ip"`) {
		t.Fatalf("expected dst_ip omitted when empty, got: %s", s)
	}
}
