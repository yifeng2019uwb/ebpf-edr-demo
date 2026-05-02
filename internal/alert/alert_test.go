package alert

import (
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
