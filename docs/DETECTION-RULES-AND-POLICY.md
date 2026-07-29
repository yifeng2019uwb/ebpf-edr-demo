# Detection Rules & Policy Design

**Scope:** the detection *model* — the evaluation layers, the policy, and the non-obvious
reasoning behind suppressions. The **exact rule data** (match conditions, paths, lists, severity,
response) lives in `rules/*.yaml`, self-documented with inline comments — that is the single place
rules are edited and the source of truth. Companion docs:
[MITRE-COVERAGE.md](MITRE-COVERAGE.md) (technique ↔ rule table),
[DESIGN-PROCESS-ANCESTRY-CACHE.md](DESIGN-PROCESS-ANCESTRY-CACHE.md) (parent verification).

---

## 0. How the pieces fit

```
kernel sensors           →  raw events
  execsnoop              → ProcessEvent
  lsm-file (file_open)   → FileEvent
  lsm-connect            → NetEvent
        │
        ▼
enrich + workload resolver   →  attaches identity {runtime, service, state}
        │
        ▼
detector (matcher engine)    →  compiles + evaluates the declarative rules ↓
        │
        ▼
rules/*.yaml                 →  per-sensor detections (match, severity, order, response)
rules/common.yaml            →  shared lists + policy-layer config
```

**Where truth lives.** The `.bpf.c` sensors carry no detection logic — they emit events only. The
rules are declarative matchers in `rules/*.yaml` (per-sensor detections plus `common.yaml` shared
lists and layer config). The Go engine compiles and evaluates them but hardcodes no per-rule
policy — only pipeline logic (ppid==1 skip, ancestry walk, state=unknown telemetry). Tune
behaviour by editing the YAML.

---

## 1. The detection layers (evaluation order)

Every event runs this gauntlet. Order matters — the first thing that drops or matches wins.

| # | Layer | Effect |
|---|-------|--------|
| 0 | **Sensor** | process / file / network sensor emits the raw event |
| 1 | **Workload resolution** | attaches `runtime` ∈ {docker, k8s, host, unknown} and `state` ∈ {resolved, pending, unknown} |
| 2 | **Layer 1 infra fast-path** | persistent daemons matching `infrastructure_filters` become trust roots for the ancestry walk |
| 3 | **`ignore_namespaces`** | events in pure-infra K8s namespaces → dropped |
| 4 | **Layer 2 `global_exceptions`** | context-aware pre-filter drop (init / infrastructure parent). **Skipped for verified containers** — a shell/curl *inside* a container is the signal, not host noise |
| 5 | **`ppid == 1` short-circuit** | direct children of init/systemd = trusted infra → dropped |
| 6 | **Process whitelist** | `customer_applications` → dropped (T1036 is checked *before* this) |
| 7 | **Container-context gating** | container-specific rules fire **only** for verified containers (`state != unknown` AND `runtime ∈ {docker,k8s}`) |
| 8 | **`state=unknown` handling** | ancestry-trusted parent → suppress; else → **LOW telemetry**, not CRITICAL |
| 9 | **Rule match** | first match wins, ordered CRITICAL→…→LOW |
| 10 | **Response** | the fired rule's `response:` (kill_process / block_ip) for a short list of rules; everything else alert-only |
| 11 | **Sinks** | file + Supabase always; Redis drops LOW (keeps telemetry off the live dashboard) |

**Two gates do most of the false-positive work:**

- **Container-context gating.** If we could not *verify* the process belongs to a container
  (`state == unknown`), we do **not** fire container-specific rules on it. Absence of identity is
  a visibility gap, not a threat.
- **Ancestry parent verification.** A process whose ancestry roots in verified infrastructure is
  lifecycle activity, not an escape. Name-agnostic — safety is *who spawned it*, not what it is
  called. Model in [DESIGN-PROCESS-ANCESTRY-CACHE.md](DESIGN-PROCESS-ANCESTRY-CACHE.md).

---

## 2. Detections — by sensor

Each rule's attack, exact match conditions, severity, and response are declared and commented in
`rules/*.yaml`; the technique ↔ rule mapping is in [MITRE-COVERAGE.md](MITRE-COVERAGE.md). This
section records only the pipeline reasoning a single rule doesn't show.

### 2.1 Process (`execsnoop` → `checkProcessRules`)

Check order: `ppid==1` drop → **T1036 before the whitelist** → whitelist → `state=unknown` branch
→ verified-container rules.

- **T1036 (masquerading) runs ahead of the whitelist on purpose** — a binary's *location* (a
  writable dir) is the signal, so it fires even if the binary's name is whitelisted.
- The rest (shell execution, ingress tools, container-discovery tools) fire only for a verified
  container and are **alert-only** — the same binaries run in legitimate builds and health checks,
  so killing would break workloads.

### 2.2 File (`lsm/file_open` → `checkFileRules`)

All file rules require a verified container.

- **T1082 reader-gate.** `/etc/passwd`/`/etc/group` are world-readable and read constantly by libc
  NSS, so matching the path alone is a false-positive storm. The rule also gates on the *reader*
  being a recon/shell tool, so an app's own NSS reads stay quiet while discovery still fires. (An
  entrypoint that runs `getent`/`id`/`cat` at startup still fires → allowlist that service.)
- **`kill_process` on credential reads** (private keys, `/etc/shadow`) — never legitimate in a
  container. **Caveat (planned fix):** this currently kills a *trusted app reading its own*
  cert/key (e.g. localstack, cilium). No eBPF field separates that from an attacker reading a
  stolen key — only resolved service identity does, so the fix is the trusted-app whitelist
  (service-scoped exceptions; see HANDOFF Active design), not a sensor change.
- **T1611 host-reads-overlay is defined but inactive** — its check is disabled pending a host
  allowlist.

### 2.3 Network (`lsm-connect` → `checkNetworkRules`)

Outbound connect to a non-private destination on a non-allowed port/service. Response `block_ip`
denies the destination at the kernel on re-connect (outbound IPv4; the kernel-side block map must
be compiled for the block to take effect — alert-only until then).

### 2.4 Unresolved namespace → LOW telemetry (not a rule)

A process whose namespace never resolved *and* whose ancestry can't be verified as infrastructure
is a **visibility gap, not an escape** — emitted at LOW (off the live dashboard), not CRITICAL.
Real escape detection lives in the file-based T1611 rules and, longer term, in escape *primitives*
(setns, release_agent, privileged mounts).

---

## 3. Policy layers in detail

The exact list contents (which daemons, which paths) are in `rules/common.yaml`; this describes
the mechanism.

### Layer 1 — `infrastructure_filters` (fast-path trust roots)
Persistent daemons only, matched by **comm + trusted binary prefix** (path validation blocks
spoofs like `/tmp/sshd`): host system daemons, the container runtime, the K8s node components, and
the agent itself. The resolver discovers these at startup and hands their PIDs to the detector to
seed the ancestry walk. Dynamically-spawned `runc` is **not** here — the ancestry walk handles it.

### Layer 2 — `global_exceptions` (context-aware pre-filter)
Drops legitimate activity **before** rule matching, gated on `parent_context`:
- `init` (ppid == 1): package managers and system utilities during startup.
- `infrastructure` (ancestry roots in a Layer 1 PID / trusted daemon): SSH-session utilities,
  runtime health checks.
- `su/sudo` reading only auth files — scoped so it can't be abused to read keys or secrets.

**Critical rule:** `parent_context: infrastructure` exceptions are **skipped for verified
containers** — otherwise a container shell/curl (whose parent is the trusted `containerd-shim`)
would be wrongly suppressed. Host/node infra noise is quieted; the in-container signal is kept.

### Whitelists
- `customer_applications` — known-benign app, suppress all rules (checked after T1036).
- `whitelisted_file_access_procs` — container-init runc states that read `/etc/passwd` by design.
- `pem_exclude_paths` — CA bundles, excluded from the private-key check.

### Host handling (flat, not tiered)
Host processes resolve to a single `runtime=host` identity and are trusted via the `ppid==1`
short-circuit + ancestry walk; residual unresolved host activity goes to LOW telemetry. There is
**no** per-host-service policy tier — an earlier design proposed one but it was not adopted.

### Responses
Automated response is deliberately narrow — only where action is unambiguously safe:

| Rule | Response | Rationale |
|------|----------|-----------|
| private-key read | `kill_process` | no container should read private keys (but see the trusted-app caveat, §2.2) |
| `/etc/shadow` read | `kill_process` | never legitimate in a container |
| exfiltration | `block_ip` | deny the dst IP at the kernel on re-connect |
| everything else | alert-only | shells / curl / `.env` / discovery have legitimate uses; killing risks breaking workloads |

---

## 4. Known drift / gotchas

- **T1611 host-reads-container-overlay is inactive** — disabled pending its host allowlist.
- **T1082 startup FP** — a service that runs `getent`/`id`/`cat` in its entrypoint will fire;
  allowlist per-service.
- **Response coverage is narrow by design** — adding a rule does not add a response unless its
  YAML entry sets `response:`.
- **Trusted-app credential FP** — `kill_process` credential rules fire on trusted apps reading
  their own cert/key; the fix is the trusted-app whitelist (see §2.2 and HANDOFF Active design).
