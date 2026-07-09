# pkg/detector — Detection Engine & Response Actions

Detection engine that evaluates the structured YAML rules against enriched
kernel events and issues alerts, with optional automated response.

## What It Does

1. **Receives events** from enricher (process, file, network with workload identity)
2. **Evaluates structured detections** from `rules/process.yaml` / `file.yaml` /
   `network.yaml` in file order (CRITICAL→LOW); first match wins
3. **Issues alerts** with severity (CRITICAL, HIGH, MEDIUM, LOW) and the fired
   rule's requested `response:`
4. **Executes response actions** (kill_process, block_ip) via the Responder

## Files

- **yaml_detector.go** — the matcher engine
  - compiles each detection's list references once at startup (`compileDetections`)
  - `checkProcessRules()` / `checkFileRules()` / `checkNetworkRules()` — one
    loop over the compiled detections per event type
  - Go pipeline logic that is NOT YAML rules: ppid==1 skip, runc-state file
    whitelist, ancestry-walk trust for state=unknown, LOW telemetry emission

- **response.go** — response action execution (`Responder`)
  - `kill_process` — SIGKILL the alerting process
  - `block_ip` — add dst IP to the blocked_ips LPMTrie (kernel side must be
    compiled first; skipped with a log line until then)

- **ancestry_cache.go** — live pid → exec record cache for parent verification
  (see docs/DESIGN-PROCESS-ANCESTRY-CACHE.md)

- **rule_names.go** — rule name constants (design spec / technique reference)

## Key Concepts

**Rules are YAML, engine is Go.** Match primitives, severity, order, exceptions,
and `response:` come from `rules/*.yaml`; the detector hardcodes no per-rule policy.

**Response flow:** the detector stamps the fired rule's `response:` on the alert
(`ResponseAction`); main.go has the Responder execute it and replaces the field
with the action actually taken before the alert reaches the sinks.

## Usage

```go
det := detector.NewYAMLDetectorWithRuntime(rulesDB, runtime)

a := det.Detect(event) // nil, or an alert with ResponseAction = requested response

if a.ResponseAction != alert.ActionNone {
    a.ResponseAction = responder.Respond(a, a.ResponseAction)
}
```

See: `cmd/edr-monitor/main.go` for pipeline integration.

## Testing

Unit tests in `pkg/detector/` verify rule matching and response stamping.

Functional tests: `./validate-do-k8s.sh` (K8s) and `validate.sh` (Docker VM).

---

**Last Updated:** 2026-07-09
