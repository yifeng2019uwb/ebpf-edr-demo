# pkg/rules — Detection Rules Loader

Loads security rules from `rules/common.yaml` and provides a queryable interface for the detector engine.

## What It Does

1. **Parses YAML** — Loads lists, macros, detection rules from YAML
2. **Detects environment** — Identifies deployment (K8s, GCP, DigitalOcean, etc.)
3. **Merges whitelists** — Adds cloud-specific agents and K8s infrastructure processes
4. **Provides interface** — `GetList()`, `GetMacro()` for detector to query rules

## Files

- **loader.go** — YAML parser and RulesDB builder
  - `LoadRulesForEnvironment()` — loads YAML + detects environment
  - `DetectEnvironment()` — checks cloud metadata (timeout 1.5s)
  - `MergeWhitelists()` — adds cloud agents + K8s infrastructure
  
- **common.yaml** — All detection rules in one file
  - `lists:` — reusable collections (shell_binaries, network_tools, etc.)
  - `macros:` — compound conditions (is_container, accessing_ssh_keys, etc.)
  - `detections:` — 14 MITRE techniques with condition + severity + output
  - `network:` — allowed ports and services
  - `ignore_namespaces:` — skip certain K8s namespaces

## Key Concepts

**Single Source of Truth:** All detection rules in YAML. No hardcoded Go policies.

**Environment-Aware:** Same YAML works on GCP, DigitalOcean, Kubernetes. Environment-specific whitelists merged at runtime (e.g., GCP getconf, DO droplet-agent).

**Reusable Lists:** `shell_processes`, `network_tools`, `ssh_key_dirs`, etc. Referenced by multiple rules.

**Conditions:** YAML-like expressions (`is_container and proc.name in (network_tools)`) evaluated by detector.

## Usage

```go
// Load rules
rulesDB, err := rules.LoadRulesForEnvironment("rules/common.yaml")

// Create detector with environment awareness
det := detector.NewYAMLDetectorWithEnv(rulesDB, string(rulesDB.Env))

// Query rules
list := rulesDB.GetList("shell_processes")  // ["bash", "sh", "zsh", ...]
macro := rulesDB.GetMacro("is_container")   // condition string
```

See: `cmd/edr-monitor/main.go` for full pipeline.

## Extending Rules

**Add new MITRE detection:**
1. Add entry to `lists:` if needed (e.g., new file patterns)
2. Add entry to `macros:` if needed (e.g., new conditions)
3. Add detection rule to `detections:` with condition, severity, output
4. Reload (no code rebuild needed)

**Add new cloud environment:**
1. Add cloud agent names to `lists/gcp_cloud_agents` or `lists/digitalocean_cloud_agents`
2. Update `DetectEnvironment()` if new metadata endpoint
3. Reload rules

---

**Last Updated:** 2026-06-30
