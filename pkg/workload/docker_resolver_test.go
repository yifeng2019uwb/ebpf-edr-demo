//go:build linux

package workload

import "testing"

func TestNormalizeServiceName(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "docker compose service with prefix",
			raw:  "order-processor-auth_service",
			want: "auth-service",
		},
		{
			name: "service with underscore",
			raw:  "inventory_service",
			want: "inventory-service",
		},
		{
			name: "plain service",
			raw:  "redis",
			want: "redis",
		},
		{
			name: "dash prefix keeps last segment",
			raw:  "order-processor-localstack",
			want: "localstack",
		},
		{
			name: "underscore after last dash",
			raw:  "order-processor-user_service",
			want: "user-service",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeServiceName(tt.raw)
			if got != tt.want {
				t.Fatalf("normalizeServiceName(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestDockerResolverResolveCacheHit(t *testing.T) {
	resolver := &DockerResolver{
		cache: map[uint32]ResolveResult{
			12345: {
				Identity: WorkloadIdentity{
					Runtime: "docker",
					Service: "auth-service",
				},
				Meta: WorkloadMeta{
					Container: "order-processor-auth_service",
					Pod:       "order-processor-auth_service",
					Node:      "docker-node",
					Region:    "us-west1",
				},
				State: StateResolved,
			},
		},
		node:   "docker-node",
		region: "us-west1",
	}

	got := resolver.Resolve(12345, 999)

	if got.State != StateResolved {
		t.Fatalf("State = %q, want %q", got.State, StateResolved)
	}
	if got.Identity.Runtime != "docker" {
		t.Fatalf("Runtime = %q, want docker", got.Identity.Runtime)
	}
	if got.Identity.Service != "auth-service" {
		t.Fatalf("Service = %q, want auth-service", got.Identity.Service)
	}
	if got.Meta.Container != "order-processor-auth_service" {
		t.Fatalf("Container = %q", got.Meta.Container)
	}
}

func TestDockerResolverResolveCacheMissReturnsUnknown(t *testing.T) {
	resolver := &DockerResolver{
		cache:  map[uint32]ResolveResult{},
		node:   "docker-node",
		region: "us-west1",
	}

	got := resolver.Resolve(99999, 123)

	if got.State != StateUnknown {
		t.Fatalf("State = %q, want %q", got.State, StateUnknown)
	}
	if got.Identity.Runtime != "docker" {
		t.Fatalf("Runtime = %q, want docker", got.Identity.Runtime)
	}
	if got.Meta.Node != "docker-node" {
		t.Fatalf("Node = %q, want docker-node", got.Meta.Node)
	}
	if got.Meta.Region != "us-west1" {
		t.Fatalf("Region = %q, want us-west1", got.Meta.Region)
	}
}
