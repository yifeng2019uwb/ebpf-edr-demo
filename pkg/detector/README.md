# pkg/detector — Detection Rules & Response Actions

Detection engine that applies YAML-based security rules to enriched kernel events and issues alerts.

## What It Does

1. **Receives events** from enricher (process, file, network with workload identity)
2. **Applies detection rules** from `rules/default.yaml` (14 MITRE techniques)
3. **Issues alerts** with severity (CRITICAL, HIGH, MEDIUM, LOW)
4. **Executes response actions** (kill_process, blockIP) based on rule policy

## Files

- **yaml_detector.go** — Main detection engine (reads rules from YAML)
  - `checkProcessRules()` — detects shell spawn, tool execution, escape attempts
  - `checkFileRules()` — detects credential/SSH access, system file access
  - `checkNetworkRules()` — detects external connections, IP blocking
  
- **responder.go** — Response action execution
  - `kill_process` — terminate container process
  - `blockIP` — block IP in kernel eBPF map (IPv4 only)
  
- **network_init.go** — K8s networking support
  - Handles GKE service CIDR detection
  - Used by network rule evaluation

## Key Concepts

**Detection Rules:** All rules live in `rules/default.yaml`. No hardcoding in Go.

**Environment Awareness:** Rules adapt to deployment environment (GCP, DigitalOcean, Kubernetes). Environment-specific whitelists merged at runtime.

**Response Actions:** Rules can specify response (kill process, block IP). Response can escalate severity ("if kill_process → CRITICAL").

**Whitelist Exceptions:** Use `exception_macros` to suppress alerts for legitimate processes.

## Usage

```go
// Create detector
det := detector.NewYAMLDetectorWithEnv(rulesDB, "k8s")

// Detect alerts from event
alerts := det.Detect(event)

// Execute response actions
action := detector.ResponseFor(alert.Rule, alert.Level)
if action != detector.ActionNone {
    action = responder.Respond(&alert, action)
}
```

See: `cmd/edr-monitor/main.go` for pipeline integration.

## Testing

Unit tests in `pkg/detector/` verify rule matching logic.

Functional tests: `./validate-do-k8s.sh` (12 MITRE scenarios end-to-end).

---

**Last Updated:** 2026-06-30
