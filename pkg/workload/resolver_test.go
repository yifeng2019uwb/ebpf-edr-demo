//go:build linux

package workload

import (
	"os"
	"testing"
)

func TestNewResolverReturnsK8sResolver(t *testing.T) {
	t.Setenv("REGION", "us-west1")

	resolver := NewResolver("k8s")

	if _, ok := resolver.(*K8sResolver); !ok {
		t.Fatalf("NewResolver(k8s) returned %T, want *K8sResolver", resolver)
	}
}

func TestNewResolverReturnsDockerResolverByDefault(t *testing.T) {
	t.Setenv("REGION", "us-west1")

	tests := []string{
		"docker",
		"",
		"unknown",
	}

	for _, runtime := range tests {
		t.Run(runtime, func(t *testing.T) {
			resolver := NewResolver(runtime)

			if _, ok := resolver.(*DockerResolver); !ok {
				t.Fatalf("NewResolver(%q) returned %T, want *DockerResolver", runtime, resolver)
			}
		})
	}
}

func TestNewResolverUsesRegionFromEnvironment(t *testing.T) {
	t.Setenv("REGION", "us-central1")

	resolver := NewResolver("k8s")

	k8sResolver, ok := resolver.(*K8sResolver)
	if !ok {
		t.Fatalf("NewResolver(k8s) returned %T, want *K8sResolver", resolver)
	}

	if k8sResolver.region != "us-central1" {
		t.Fatalf("region = %q, want us-central1", k8sResolver.region)
	}

	if k8sResolver.node == "" {
		hostname, _ := os.Hostname()
		if hostname != "" {
			t.Fatalf("node should not be empty")
		}
	}
}

func TestNewResolverUsesClusterFromEnvironment(t *testing.T) {
	t.Setenv("CLUSTER_NAME", "order-processor-cluster-us-west1")

	tests := []struct {
		runtime string
	}{
		{"k8s"},
		{"docker"},
	}

	for _, tt := range tests {
		t.Run(tt.runtime, func(t *testing.T) {
			resolver := NewResolver(tt.runtime)

			var cluster string
			switch r := resolver.(type) {
			case *K8sResolver:
				cluster = r.cluster
			case *DockerResolver:
				cluster = r.cluster
			default:
				t.Fatalf("unexpected resolver type %T", resolver)
			}

			if cluster != "order-processor-cluster-us-west1" {
				t.Fatalf("cluster = %q, want order-processor-cluster-us-west1", cluster)
			}
		})
	}
}
