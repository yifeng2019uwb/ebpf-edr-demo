package rules

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"ebpf-edr-demo/internal/alert"
)

// Config is the top-level rules configuration.
type Config struct {
	Rules RulesSection `yaml:"rules"`
}

// InfrastructureCategory defines a category of infrastructure processes with path validation
type InfrastructureCategory struct {
	AllowedComms    []string `yaml:"allowed_comms"`
	TrustedPrefixes []string `yaml:"trusted_prefixes"`
}

// InfrastructureFilters defines Layer 1 fast-path infrastructure whitelist by category
type InfrastructureFilters struct {
	HostSystem    InfrastructureCategory `yaml:"host_system"`
	DockerRuntime InfrastructureCategory `yaml:"docker_runtime"`
	Kubernetes    InfrastructureCategory `yaml:"kubernetes"`
	Agent         InfrastructureCategory `yaml:"agent"`
}

// GlobalException defines a Layer 2 pre-filter exception (context-aware whitelist)
type GlobalException struct {
	Description   string   `yaml:"description"`
	ProcessIn     []string `yaml:"process_in"`
	ParentContext string   `yaml:"parent_context"` // "init" or "infrastructure"
	FilePrefixes  []string `yaml:"file_prefixes"`
}

// RulesSection contains all rule definitions (lists, macros, detections).
type RulesSection struct {
	InfrastructureFilters InfrastructureFilters `yaml:"infrastructure_filters"`
	GlobalExceptions      []GlobalException     `yaml:"global_exceptions"`
	Lists                 []ListDef             `yaml:"lists"`
	Macros                []MacroDef            `yaml:"macros"`
	Detections            map[string]Detection  `yaml:"detections"`
	Network               Network               `yaml:"network"`
	IgnoreNamespaces      []string              `yaml:"ignore_namespaces"`
}

// ListDef defines a named list (reusable collection).
type ListDef struct {
	Name  string        `yaml:"name"`
	Items []interface{} `yaml:"items"`
}

// MacroDef defines a named macro (reusable condition).
type MacroDef struct {
	Name      string `yaml:"name"`
	Condition string `yaml:"condition"`
}

// Detection represents a single detection rule.
type Detection struct {
	// Simple field matching (backward compatible)
	DirPrefixes  []string `yaml:"dir_prefixes"`
	Suffixes     []string `yaml:"suffixes"`
	Paths        []string `yaml:"paths"`
	Tools        []string `yaml:"tools"`
	Binaries     []string `yaml:"binaries"`
	ExcludePaths []string `yaml:"exclude_paths"`

	// Container escape specific
	ContainerFS       []string `yaml:"container_fs"`
	ProcEscape        []string `yaml:"proc_escape"`
	ProcEscapeAllowed []string `yaml:"proc_escape_allowed"`
	SuspiciousPaths   []string `yaml:"suspicious_paths"`

	// Future: condition-based (Falco-style)
	Condition       string   `yaml:"condition"`        // e.g., "spawned_shell and in_container"
	ExceptionMacros []string `yaml:"exception_macros"` // macro names to exclude
	Severity        string   `yaml:"severity"`         // CRITICAL, HIGH, MEDIUM
	Output          string   `yaml:"output"`           // output message template
}

// Network contains network policy.
type Network struct {
	AllowedPorts    []uint16 `yaml:"allowed_ports"`
	AllowedServices []string `yaml:"allowed_services"`
}

// ── Structured detections (per-sensor YAML files) ─────────────────────────────

// MatchSpec holds declarative match primitives for a structured detection.
// Each field names a list from the shared lists; all specified fields must
// match (AND). An empty spec matches nothing.
type MatchSpec struct {
	CommSuffixIn string `yaml:"comm_suffix_in"` // comm ends with any list item
	CommBaseIn   string `yaml:"comm_base_in"`   // filepath.Base(comm) equals any list item
	CommPrefixIn string `yaml:"comm_prefix_in"` // comm starts with any list item
}

// listRefs returns the list names referenced by the spec (for validation).
func (m MatchSpec) listRefs() []string {
	var refs []string
	for _, name := range []string{m.CommSuffixIn, m.CommBaseIn, m.CommPrefixIn} {
		if name != "" {
			refs = append(refs, name)
		}
	}
	return refs
}

// DetectionRule is one structured detection entry from a per-sensor rules file.
// Entries are evaluated in file order (CRITICAL → LOW, validated at load).
type DetectionRule struct {
	Name             string      `yaml:"name"`              // emitted rule name
	Severity         alert.Level `yaml:"severity"`          // CRITICAL | HIGH | MEDIUM | LOW
	RequireContainer bool        `yaml:"require_container"` // false = also host/unknown
	Match            MatchSpec   `yaml:"match"`
	Exceptions       MatchSpec   `yaml:"exceptions"`
	Message          string      `yaml:"message"`
}

// sensorConfig is the top-level structure of a per-sensor rules file
// (process.yaml, file.yaml, network.yaml).
type sensorConfig struct {
	Detections []DetectionRule `yaml:"detections"`
}

// severityRank orders severities for load-time order validation
// (detections must be sorted CRITICAL → LOW in each sensor file).
var severityRank = map[alert.Level]int{alert.Critical: 4, alert.High: 3, alert.Medium: 2, alert.Low: 1}

// loadSensorDetections reads and validates one per-sensor detections file.
func loadSensorDetections(path string, lists map[string][]interface{}) ([]DetectionRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read sensor rules file %s: %w", path, err)
	}
	var cfg sensorConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse sensor rules YAML %s: %w", path, err)
	}
	if err := validateDetections(cfg.Detections, lists); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	log.Printf("rules: loaded %d detections from %s", len(cfg.Detections), path)
	return cfg.Detections, nil
}

// validateDetections fail-fast checks: known severity, CRITICAL→LOW file order,
// non-empty name/message/match, and every referenced list exists.
func validateDetections(dets []DetectionRule, lists map[string][]interface{}) error {
	prev := severityRank[alert.Critical]
	for i, det := range dets {
		if det.Name == "" {
			return fmt.Errorf("detection %d: missing name", i)
		}
		rank, ok := severityRank[det.Severity]
		if !ok {
			return fmt.Errorf("detection %s: invalid severity %q", det.Name, det.Severity)
		}
		if rank > prev {
			return fmt.Errorf("detection %s: severity %s out of order — detections must be sorted CRITICAL→LOW", det.Name, det.Severity)
		}
		prev = rank
		if det.Message == "" {
			return fmt.Errorf("detection %s: missing message", det.Name)
		}
		if len(det.Match.listRefs()) == 0 {
			return fmt.Errorf("detection %s: match must specify at least one primitive", det.Name)
		}
		for _, ref := range append(det.Match.listRefs(), det.Exceptions.listRefs()...) {
			if _, ok := lists[ref]; !ok {
				return fmt.Errorf("detection %s: unknown list reference %q", det.Name, ref)
			}
		}
	}
	return nil
}

// RulesDB is the compiled rules database.
type RulesDB struct {
	InfrastructureFilters InfrastructureFilters // Layer 1: fast-path infrastructure whitelist
	GlobalExceptions      []GlobalException     // Layer 2 pre-filter: context-aware exceptions
	Lists                 map[string][]interface{}
	Macros                map[string]string
	Detections            map[string]Detection
	ProcessDetections     []DetectionRule // structured process rules (rules/process.yaml, ordered)
	Network               Network
	IgnoreNs              map[string]bool
	Env                   Environment // detected environment: gcp, digitalocean, local
}

// LoadRules loads and compiles rules from YAML file, plus the per-sensor
// detection files next to it (process.yaml). Sensor files are required —
// without them the detector would silently run with no rules.
func LoadRules(path string) (*RulesDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file %s: %w", path, err)
	}
	log.Printf("rules: loaded from %s (%d bytes)", path, len(data))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse rules YAML: %w", err)
	}

	// Compile to RulesDB
	db := CompileRules(&cfg)

	db.ProcessDetections, err = loadSensorDetections(filepath.Join(filepath.Dir(path), "process.yaml"), db.Lists)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// CompileRules converts Config to RulesDB (preprocessed for fast lookup).
func CompileRules(cfg *Config) *RulesDB {
	r := &cfg.Rules

	// Build lists map
	lists := make(map[string][]interface{})
	for _, list := range r.Lists {
		lists[list.Name] = list.Items
	}

	// Build macros map
	macros := make(map[string]string)
	for _, macro := range r.Macros {
		macros[macro.Name] = macro.Condition
	}

	// Build ignore namespaces set
	ignoreNs := make(map[string]bool)
	for _, ns := range r.IgnoreNamespaces {
		ignoreNs[ns] = true
	}

	return &RulesDB{
		InfrastructureFilters: r.InfrastructureFilters,
		GlobalExceptions:      r.GlobalExceptions,
		Lists:                 lists,
		Macros:                macros,
		Detections:            r.Detections,
		Network:               r.Network,
		IgnoreNs:              ignoreNs,
	}
}

// GetList returns items from a named list.
func (db *RulesDB) GetList(name string) []interface{} {
	return db.Lists[name]
}

// GetMacro returns the condition string for a named macro.
func (db *RulesDB) GetMacro(name string) string {
	return db.Macros[name]
}

// IsIgnoredNamespace checks if namespace should be ignored.
func (db *RulesDB) IsIgnoredNamespace(ns string) bool {
	return db.IgnoreNs[ns]
}

// Environment represents the deployment environment.
type Environment string

const (
	EnvGCP          Environment = "gcp"
	EnvDigitalOcean Environment = "digitalocean"
	EnvLocal        Environment = "local"

	// AWS and Azure support (design extensible, currently only validating GCP + DigitalOcean)
	// EnvAWS   Environment = "aws"
	// EnvAzure Environment = "azure"
)

// DetectEnvironment detects the current cloud environment by querying metadata servers.
// Uses short timeout (1.5s total) so agent doesn't hang on-prem or when metadata unavailable.
// Tries each provider in order: DigitalOcean, GCP, then defaults to local.
func DetectEnvironment() Environment {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	// Try DigitalOcean metadata service first (169.254.169.254/metadata/v1/)
	if tryMetadata(ctx, "GET", "http://169.254.169.254/metadata/v1/", map[string]string{}) {
		log.Printf("rules: detected DigitalOcean environment")
		return EnvDigitalOcean
	}

	// Try GCP metadata server (metadata.google.internal with Metadata-Flavor header)
	if tryMetadata(ctx, "GET", "http://metadata.google.internal/computeMetadata/v1/", map[string]string{"Metadata-Flavor": "Google"}) {
		log.Printf("rules: detected GCP environment")
		return EnvGCP
	}

	log.Printf("rules: no cloud environment detected, using local")
	return EnvLocal
}

// tryMetadata attempts to query a metadata server with given method, URL, and headers.
// Returns true if server responds with 200 OK.
func tryMetadata(ctx context.Context, method, url string, headers map[string]string) bool {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return false
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

// LoadRulesForEnvironment loads rules and records the detected cloud environment.
// Environment-specific trust (gcp_cloud_agents, gke_infrastructure_procs,
// digitalocean_* lists) is not merged here — it belongs in the YAML-rule-driven
// trust checks (trusted_parent_names / ancestry), not a startup list merge.
func LoadRulesForEnvironment(path string) (*RulesDB, error) {
	db, err := LoadRules(path)
	if err != nil {
		return nil, err
	}

	db.Env = DetectEnvironment() // store detected environment for detector use

	return db, nil
}
