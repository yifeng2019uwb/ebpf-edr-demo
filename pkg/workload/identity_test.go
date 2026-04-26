package workload

import "testing"

func TestResolveStateConstants(t *testing.T) {
	tests := []struct {
		name string
		got  ResolveState
		want ResolveState
	}{
		{"resolved", StateResolved, "resolved"},
		{"host", StateHost, "host"},
		{"pending", StatePending, "pending"},
		{"unknown", StateUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestResolveResultStoresIdentityAndMeta(t *testing.T) {
	result := ResolveResult{
		Identity: WorkloadIdentity{
			Runtime: "docker",
			Service: "auth-service",
		},
		Meta: WorkloadMeta{
			Container: "order-processor-auth_service",
			Pod:       "order-processor-auth_service",
			Namespace: "",
			Node:      "node-1",
			Region:    "us-west1",
		},
		State: StateResolved,
	}

	if result.Identity.Runtime != "docker" {
		t.Fatalf("Runtime = %q, want docker", result.Identity.Runtime)
	}
	if result.Identity.Service != "auth-service" {
		t.Fatalf("Service = %q, want auth-service", result.Identity.Service)
	}
	if result.Meta.Container != "order-processor-auth_service" {
		t.Fatalf("Container = %q", result.Meta.Container)
	}
	if result.State != StateResolved {
		t.Fatalf("State = %q, want resolved", result.State)
	}
}
