package workload

// Runtime represents the container management system.
type Runtime string

const (
	// RuntimeK8s: Kubernetes cluster (uses crictl, works with Docker/containerd/cri-o)
	RuntimeK8s Runtime = "k8s"

	// RuntimeDocker: Docker daemon (standalone VMs or Compose)
	RuntimeDocker Runtime = "docker"

	// RuntimeHost: Native host process (not in a container)
	RuntimeHost Runtime = "host"

	// RuntimeUnknown: Unrecognized runtime (possible future support: podman, containerd standalone, cri-o standalone)
	// Standalone podman would require separate resolver (different cgroup paths, socket detection).
	RuntimeUnknown Runtime = "unknown"
)

// Service name constants for whitelisted host/infrastructure processes
const (
	HostProcessService = "host-process"
	K8sInfraService    = "k8s-infra"
)

// ResolveState represents how well we resolved a mnt_ns_id → workload mapping.
type ResolveState string

const (
	// StateResolved — Successfully identified the workload (container, pod, or host process).
	// Detection rules run normally. Host processes have RuntimeHost; containers have RuntimeDocker/RuntimeK8s.
	StateResolved ResolveState = "resolved"

	// StatePending — Container/pod not yet in resolver cache (starting up).
	// Buffered and retried every 3s, up to 20 retries / 60s max.
	// Escalates to StateUnknown if still unresolved after grace period.
	// Prevents false CRITICAL alerts during normal startup.
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
	// Namespace is the Kubernetes namespace (e.g. kube-system, default); empty for
	// Docker workloads. This is NOT the Linux mount namespace (mnt_ns_id) used to
	// resolve container identity — the alert/DB field name stays "namespace", but
	// the dashboard labels it "K8s Namespace" to avoid that confusion.
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
	Resolve(event interface{}) ResolveResult // EnrichedEvent from pipeline package (avoids circular import)
	Start() error
}
