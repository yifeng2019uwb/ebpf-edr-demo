package workload

// ResolveState represents how well we resolved a mnt_ns_id → workload mapping.
// Full explanation: NOTES.md "K8s pending-ns vs Docker unknown-ns"
// Design rationale: gke-expansion-design.md Section 3 "Resolver design constraints"
type ResolveState string

const (
	// StateResolved — mnt_ns_id matched a known container/pod in cache. Normal path.
	// Detection rules run fully.
	StateResolved ResolveState = "resolved"

	// StateHost — mnt_ns_id matches the host (PID 1 or agent's own namespace).
	// Most detection rules are skipped — host processes are expected.
	// Exception: host_reads_container_fs still fires on /var/lib/docker/overlay2/.
	StateHost ResolveState = "host"

	// StatePending — container not yet in resolver cache (new pod/container starting up).
	// Buffered and retried every 3s, up to 20 retries / 60s max.
	// Escalates to StateUnknown if still unresolved after grace period.
	// Prevents false CRITICAL alerts during normal pod/container startup.
	StatePending ResolveState = "pending"

	// StateUnknown — mnt_ns_id unresolved after all retries.
	// Process is in a namespace we cannot explain → possible container escape.
	// Triggers CRITICAL unknown_namespace_process alert.
	StateUnknown ResolveState = "unknown"
)

// WorkloadIdentity is the small identity used by detection rules.
// Keep this intentionally minimal.
type WorkloadIdentity struct {
	Runtime string // "docker" | "k8s"
	Service string // logical service name used by detection rules
}

// WorkloadMeta keeps raw/debug information.
// Detection rules should usually NOT depend on these fields.
type WorkloadMeta struct {
	Container string
	Pod       string
	Namespace string
	Node      string
	Region    string
}

// ResolveResult separates identity from resolution state.
type ResolveResult struct {
	Identity WorkloadIdentity
	Meta     WorkloadMeta
	State    ResolveState
}

type WorkloadResolver interface {
	Resolve(mntNsID uint32, pid uint32) ResolveResult
	Start() error
}
