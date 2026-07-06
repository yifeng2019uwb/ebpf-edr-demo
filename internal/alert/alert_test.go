package alert

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"ebpf-edr-demo/pkg/workload"
)

// testSink collects alerts for testing
type testSink struct {
	alerts []Alert
}

func (ts *testSink) Write(ctx context.Context, a Alert) error {
	ts.alerts = append(ts.alerts, a)
	return nil
}

func (ts *testSink) Close() error {
	return nil
}

// newTestHandler creates a Handler with a test sink
func newTestHandler(t *testing.T) (*Handler, *testSink) {
	t.Helper()
	sink := &testSink{}
	return NewHandler([]Sink{sink}), sink
}

func TestHandlerSend_WritesFormattedLine(t *testing.T) {
	h, sink := newTestHandler(t)

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

	if len(sink.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(sink.alerts))
	}

	a := sink.alerts[0]
	if a.Level != Critical || a.Rule != "shell_spawn_container" || a.Pid != 1234 {
		t.Fatalf("alert fields mismatch: %+v", a)
	}
}

func TestHandlerSend_FilenameInExtra(t *testing.T) {
	h, sink := newTestHandler(t)

	h.Send(Alert{
		Level:    High,
		Rule:     "sensitive_file_access",
		Message:  "Container accessed SSH key",
		Comm:     "cat",
		Filename: "/root/.ssh/id_rsa",
		Workload: workload.ResolveResult{State: workload.StateResolved},
	})
	h.Close()

	if len(sink.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(sink.alerts))
	}
	if sink.alerts[0].Filename != "/root/.ssh/id_rsa" {
		t.Fatalf("expected filename, got: %v", sink.alerts[0])
	}
}

func TestHandlerSend_DstIPInExtra(t *testing.T) {
	h, sink := newTestHandler(t)

	h.Send(Alert{
		Level:    High,
		Rule:     "unauthorized_external_connect",
		Message:  "Unauthorized external connection",
		Comm:     "python3",
		DstIP:    "8.8.8.8",
		DstPort:  443,
		Workload: workload.ResolveResult{State: workload.StateResolved},
	})
	h.Close()

	if len(sink.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(sink.alerts))
	}
	if sink.alerts[0].DstIP != "8.8.8.8" || sink.alerts[0].DstPort != 443 {
		t.Fatalf("expected dst, got: %v", sink.alerts[0])
	}
}

func TestHandlerSend_FilenameTakesPriorityOverDstIP(t *testing.T) {
	h, sink := newTestHandler(t)

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

	if len(sink.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(sink.alerts))
	}
	a := sink.alerts[0]
	if a.Filename != "/etc/shadow" {
		t.Fatalf("expected filename, got: %v", a)
	}
}

func TestHandlerClose_DoesNotPanic(t *testing.T) {
	h, _ := newTestHandler(t)
	h.Close()
}

func TestHandlerSend_WriteErrorDoesNotPanic(t *testing.T) {
	// Close the handler before Send to test error handling
	h, _ := newTestHandler(t)
	h.Close()

	// Send should not panic even if sink is closed
	h.Send(Alert{
		Level:    High,
		Rule:     "sensitive_file_access",
		Comm:     "cat",
		Workload: workload.ResolveResult{State: workload.StateResolved},
	})
}

func TestNewHandler_WithMultipleSinks(t *testing.T) {
	sink1 := &testSink{}
	sink2 := &testSink{}

	h := NewHandler([]Sink{sink1, sink2})
	defer h.Close()

	h.Send(Alert{
		Level:    High,
		Rule:     "test_rule",
		Comm:     "test",
		Workload: workload.ResolveResult{State: workload.StateResolved},
	})

	if len(sink1.alerts) != 1 || len(sink2.alerts) != 1 {
		t.Fatalf("expected alert in both sinks")
	}
}

func TestAlert_JSONMarshal(t *testing.T) {
	a := Alert{
		Level:   Critical,
		Rule:    "shell_spawn_container",
		Message: "Shell spawned from container",
		Comm:    "bash",
		Workload: workload.ResolveResult{
			Identity: workload.WorkloadIdentity{Service: "auth-service"},
			Meta:     workload.WorkloadMeta{Namespace: "default"},
			State:    workload.StateResolved,
		},
	}

	b, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)

	for _, want := range []string{
		`"Level":"CRITICAL"`,
		`"Rule":"shell_spawn_container"`,
		`"Comm":"bash"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in JSON\ngot: %s", want, s)
		}
	}
}
