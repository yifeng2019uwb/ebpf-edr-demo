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
