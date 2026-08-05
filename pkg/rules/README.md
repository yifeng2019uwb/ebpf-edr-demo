# pkg/rules — Detection Rules Loader

Loads and validates the detection rule data from `rules/` and provides the
compiled `RulesDB` the detector engine consumes.

## What It Does

1. **Parses YAML** — `common.yaml` (shared lists + Layer 1/2 config) plus the
   per-sensor detection files (`process.yaml`, `file.yaml`, `network.yaml`)
2. **Validates fail-fast at load** — severity values, CRITICAL→LOW file order,
   list references, response values; a bad rules file stops agent startup
3. **Detects environment** — GCP / DigitalOcean / local via metadata servers
4. **Provides interface** — `GetList()`, ordered `*Detections` slices for the detector

## Files

- **loader.go** — YAML parser, validation, and RulesDB builder
  - `LoadRulesForEnvironment()` — loads all rules files + detects environment
  - `loadSensorDetections()` — one per-sensor file: parse + validate
  - `DetectEnvironment()` — checks cloud metadata (timeout 1.5s)

Rule data lives in `rules/` (self-documented):
- **process.yaml / file.yaml / network.yaml** — structured detections per eBPF
  hook: `name`, `severity`, `require_container`, `match`/`exceptions`
  (list-referencing primitives), `message`, `response` (kill_process / block_ip)
- **common.yaml** — shared `lists:` the detections and pipeline reference,
  Layer 1 `infrastructure_filters:`, Layer 2 `global_exceptions:`,
  `ignore_namespaces:`

## Key Concepts

**YAML is the source of truth for rules.** Match, severity, check order
(file order, CRITICAL→LOW), and response are declared per detection entry.
The Go detector compiles and evaluates them; only pipeline logic (ppid==1 skip,
ancestry walk, state=unknown telemetry) is Go code.

**Ordered evaluation.** Detections are a LIST; the first matching entry wins.
Duplicate `name:` entries are allowed (e.g. T1552_004 has a CRITICAL ssh-dirs
entry and a HIGH key-suffix entry).

**Reusable lists:** `shell_processes`, `reverse_shell_tools`, `ssh_key_dirs`, etc. —
referenced by name from match/exception primitives and validated at load.

## Usage

```go
// Load rules (entry point path: rules/common.yaml; sensor files load from its dir)
rulesDB, err := rules.LoadRulesForEnvironment("rules/common.yaml")

// Create detector
det := detector.NewYAMLDetectorWithRuntime(rulesDB, runtime)

// Query
list := rulesDB.GetList("shell_processes")   // ["bash", "sh", "zsh", ...]
procRules := rulesDB.ProcessDetections       // ordered []DetectionRule
```

See: `cmd/edr-monitor/main.go` for full pipeline.

## Extending Rules

**Add a new detection:**
1. Add a list to `common.yaml` `lists:` if needed (e.g. new file patterns)
2. Add an entry to the matching sensor file, in severity order, with
   `match:`/`exceptions:` primitives and optional `response:`
3. Rebuild/redeploy the agent image (rules ship in the image via `COPY rules/`)

**Add a new eBPF hook:** add a new per-sensor YAML file and load it in
`LoadRules()` — one file per hook.

---

**Last Updated:** 2026-07-09
