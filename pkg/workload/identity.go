package workload

type ResolveState string

const (
	StateResolved ResolveState = "resolved"
	StateHost     ResolveState = "host"
	StatePending  ResolveState = "pending"
	StateUnknown  ResolveState = "unknown"
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
