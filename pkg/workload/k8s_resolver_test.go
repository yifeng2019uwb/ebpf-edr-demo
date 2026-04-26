//go:build linux

package workload

import "testing"

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
				},
				State: StateResolved,
			},
		},
		node:   "gke-node",
		region: "us-west1",
	}

	got := resolver.Resolve(56789, 111)

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
}

func TestK8sResolverResolveCacheMissReturnsPending(t *testing.T) {
	resolver := &K8sResolver{
		cache:  map[uint32]ResolveResult{},
		node:   "gke-node",
		region: "us-west1",
	}

	got := resolver.Resolve(99999, 123)

	if got.State != StatePending {
		t.Fatalf("State = %q, want %q", got.State, StatePending)
	}
	if got.Identity.Runtime != "k8s" {
		t.Fatalf("Runtime = %q, want k8s", got.Identity.Runtime)
	}
	if got.Meta.Node != "gke-node" {
		t.Fatalf("Node = %q, want gke-node", got.Meta.Node)
	}
	if got.Meta.Region != "us-west1" {
		t.Fatalf("Region = %q, want us-west1", got.Meta.Region)
	}
}

func TestCrictlContainerMapWithMissingCrictlDoesNotPanic(t *testing.T) {
	got := crictlContainerMap("node-1", "us-west1")

	if got == nil {
		t.Fatalf("crictlContainerMap returned nil map")
	}
}
