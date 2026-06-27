package rules

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level rules configuration.
type Config struct {
	Rules RulesSection `yaml:"rules"`
}

// RulesSection contains all rule definitions (lists, macros, detections).
type RulesSection struct {
	Lists            []ListDef            `yaml:"lists"`
	Macros           []MacroDef           `yaml:"macros"`
	Detections       map[string]Detection `yaml:"detections"`
	Network          Network              `yaml:"network"`
	IgnoreNamespaces []string             `yaml:"ignore_namespaces"`
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

// RulesDB is the compiled rules database.
type RulesDB struct {
	Lists      map[string][]interface{}
	Macros     map[string]string
	Detections map[string]Detection
	Network    Network
	IgnoreNs   map[string]bool
}

// LoadRules loads and compiles rules from YAML file.
func LoadRules(path string) (*RulesDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse rules YAML: %w", err)
	}

	// Compile to RulesDB
	return CompileRules(&cfg), nil
}

// LoadDefaultRules loads from default location.
func LoadDefaultRules() (*RulesDB, error) {
	return LoadRules("rules/default.yaml")
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
		Lists:      lists,
		Macros:     macros,
		Detections: r.Detections,
		Network:    r.Network,
		IgnoreNs:   ignoreNs,
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

// MergeWhitelists adds environment-specific whitelists to the rules database.
func (db *RulesDB) MergeWhitelists(env Environment) {
	var cloudAgents []interface{}
	var infraProcs []interface{}

	switch env {
	case EnvGCP:
		cloudAgents = db.Lists["gcp_cloud_agents"]
		infraProcs = db.Lists["gke_infrastructure_procs"]
	case EnvDigitalOcean:
		cloudAgents = db.Lists["digitalocean_cloud_agents"]
		infraProcs = db.Lists["digitalocean_infrastructure_procs"]
	default:
		return
	}

	// Merge cloud agents into whitelisted processes
	if cloudAgents != nil {
		if baseWhitelist, ok := db.Lists["whitelisted_processes"]; ok {
			db.Lists["whitelisted_processes"] = append(baseWhitelist, cloudAgents...)
		}
	}

	// Build whitelisted_unknown_ns_procs from base K8s + environment-specific infrastructure
	baseK8s := db.Lists["k8s_infrastructure_procs"]
	if baseK8s != nil {
		db.Lists["whitelisted_unknown_ns_procs"] = append([]interface{}{}, baseK8s...)
		if infraProcs != nil {
			db.Lists["whitelisted_unknown_ns_procs"] = append(db.Lists["whitelisted_unknown_ns_procs"], infraProcs...)
		}
	}

	logMsg := fmt.Sprintf("rules: merged %d cloud agents", len(cloudAgents))
	if infraProcs != nil {
		logMsg = fmt.Sprintf("%s, %d infrastructure procs", logMsg, len(infraProcs))
	}
	log.Printf(logMsg)
}

// LoadRulesForEnvironment loads rules and merges environment-specific whitelists.
func LoadRulesForEnvironment(path string) (*RulesDB, error) {
	db, err := LoadRules(path)
	if err != nil {
		return nil, err
	}

	env := DetectEnvironment()
	db.MergeWhitelists(env)

	return db, nil
}
