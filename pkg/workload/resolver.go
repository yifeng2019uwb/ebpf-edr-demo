//go:build linux

package workload

import "os"

// WorkloadResolver maps a kernel mount namespace ID to a WorkloadIdentity.
// Resolve must never block — it reads from an in-memory cache only.
// A cache miss triggers an async background refresh and returns a best-effort result.
type WorkloadResolver interface {
	Resolve(mntNsID uint32, pid uint32) WorkloadIdentity
	Start() error
}

// NewResolver returns the resolver for the given runtime.
// Supported values: "docker", "k8s" (Phase 2), "auto" (default: docker).
func NewResolver(runtime string) WorkloadResolver {
	node, _ := os.Hostname()
	region := os.Getenv("REGION")
	switch runtime {
	case "k8s":
		panic("k8s resolver not yet implemented — coming in Phase 2")
	default: // "docker" or "auto"
		return &DockerResolver{node: node, region: region}
	}
}
