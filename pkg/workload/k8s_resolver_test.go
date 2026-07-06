//go:build linux

package workload

import (
	"testing"

	"ebpf-edr-demo/internal/processor"
)

func TestK8sResolverResolveCacheHit(t *testing.T) {
	resolver := &K8sResolver{
		cache: map[uint32]ResolveResult{
			56789: {
				Identity: WorkloadIdentity{
					Runtime: "k8s",
					Service: "auth-service",
				},
				Meta: WorkloadMeta{
					Container: "auth-service",
					Pod:       "auth-service-abc123",
					Namespace: "default",
					Node:      "gke-node",
					Region:    "us-west1",
					Cluster:   "order-processor-cluster-us-west1",
				},
				State: StateResolved,
			},
		},
		node:    "gke-node",
		region:  "us-west1",
		cluster: "order-processor-cluster-us-west1",
	}

	got := resolver.Resolve(&processor.ProcessEvent{MntNsId: 56789, Pid: 111})

	if got.State != StateResolved {
		t.Fatalf("State = %q, want %q", got.State, StateResolved)
	}
	if got.Identity.Runtime != "k8s" {
		t.Fatalf("Runtime = %q, want k8s", got.Identity.Runtime)
	}
	if got.Identity.Service != "auth-service" {
		t.Fatalf("Service = %q, want auth-service", got.Identity.Service)
	}
	if got.Meta.Pod != "auth-service-abc123" {
		t.Fatalf("Pod = %q, want auth-service-abc123", got.Meta.Pod)
	}
	if got.Meta.Namespace != "default" {
		t.Fatalf("Namespace = %q, want default", got.Meta.Namespace)
	}
	if got.Meta.Cluster != "order-processor-cluster-us-west1" {
		t.Fatalf("Cluster = %q, want order-processor-cluster-us-west1", got.Meta.Cluster)
	}
}

func TestK8sResolverResolveCacheMissReturnsPending(t *testing.T) {
	resolver := &K8sResolver{
		cache:  map[uint32]ResolveResult{},
		node:   "gke-node",
		region: "us-west1",
	}

	got := resolver.Resolve(&processor.ProcessEvent{MntNsId: 99999, Pid: 123})

	// K8sResolver.Resolve()'s cache-miss path returns a bare ResolveResult{State: StatePending}
	// (unlike DockerResolver, which populates Identity/Meta via bareResult() on the pending path too).
	// So Identity/Meta are zero-valued here, not Node/Region from the resolver's own fields.
	if got.State != StatePending {
		t.Fatalf("State = %q, want %q", got.State, StatePending)
	}
}

func TestCrictlContainerMapWithMissingCrictlDoesNotPanic(t *testing.T) {
	got := crictlContainerMap("node-1", "us-west1", "order-processor-cluster-us-west1", "local")

	if got == nil {
		t.Fatalf("crictlContainerMap returned nil map")
	}
}
