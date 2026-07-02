package workload

// Runtime represents the container management system.
type Runtime string

const (
	// RuntimeK8s: Kubernetes cluster (uses crictl, works with Docker/containerd/cri-o)
	RuntimeK8s Runtime = "k8s"

	// RuntimeDocker: Docker daemon (standalone VMs or Compose)
	RuntimeDocker Runtime = "docker"

	// RuntimeUnknown: Unrecognized runtime (possible future support: podman, containerd standalone, cri-o standalone)
	// Standalone podman would require separate resolver (different cgroup paths, socket detection).
	RuntimeUnknown Runtime = "unknown"
)

// ResolveState represents how well we resolved a mnt_ns_id → workload mapping.
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
	Runtime Runtime // RuntimeK8s | RuntimeDocker
	Service string  // logical service name used by detection rules
	Env     string  // cloud provider + infrastructure, e.g. "gcp-vm", "gke" — set via ENV env var
	// Note: Env currently captures cloud provider for alert whitelisting (suppress cloud-specific noise).
	// Could split into Env (provider) + Stage (alpha/production) for deployment-stage-aware rules,
	// but kept simple for now (single field, cloud provider filtering is sufficient).
}

// WorkloadMeta keeps raw/debug information.
// Detection rules should usually NOT depend on these fields.
type WorkloadMeta struct {
	Container string
	Pod       string
	Namespace string
	Node      string
	Region    string
	Cluster   string
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
