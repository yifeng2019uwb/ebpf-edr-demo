// Package workload defines the WorkloadIdentity type and the WorkloadResolver interface.
package workload

// WorkloadIdentity identifies the workload that produced an eBPF event.
// Service is the primary field used by detection rules — it is stable across
// runtimes, restarts, and replica scaling.
type WorkloadIdentity struct {
	Runtime   string // "docker" | "k8s"
	Container string // raw container name from runtime
	Pod       string // pod name (k8s) or same as Container (docker)
	Namespace string // k8s namespace; empty for Docker
	Service   string // logical service name used in all detection rules
	// Sentinels: "host" | "unknown-ns" | "pending-ns"
	Node   string // host node name — for cross-node correlation (Section 5)
	Region string // GCP region — for cross-region correlation (Section 5)
}
