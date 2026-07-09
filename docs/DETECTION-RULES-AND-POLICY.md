# Detection Rules & Policy Design

**Status:** Current — matches `pkg/detector/yaml_detector.go` + `rules/default.yaml` (2026-07-08)

Single source of truth for **how each detection fires** and **the policy layers around it**.
Companion docs: [MITRE-COVERAGE.md](MITRE-COVERAGE.md) (technique table),
[DESIGN-PROCESS-ANCESTRY-CACHE.md](DESIGN-PROCESS-ANCESTRY-CACHE.md) (parent-verification model).

---

## 0. How the pieces fit

```
kernel sensors (.bpf.c)          →  raw events
  execsnoop   → ProcessEvent
  opensnoop   → FileEvent
  lsm-connect → NetEvent
        │
        ▼
enrich + workload resolver        →  attaches identity {runtime, service, state}
        │
        ▼
detector (pkg/detector/yaml_detector.go)   ←  THE matching logic lives here (Go)
        │      uses lists / exceptions / network / ignore_namespaces from ↓
        ▼
rules/default.yaml                →  tunable DATA (lists, macros, exceptions, network, namespaces)
```

**Important — where truth lives.** The eBPF `.bpf.c` files are **sensors only**; they carry no
detection logic. The matching, severities, and responses are **hardcoded in Go**
(`yaml_detector.go`, `response_policy.go`). `default.yaml` supplies the **data** those checks read
(the `lists:`, `global_exceptions:`, `network:`, `ignore_namespaces:`). The YAML `detections:`
block and its `macros:`/`condition:` fields are **declarative reference** — there is no expression
evaluator yet, so they document intent but do **not** drive matching. When the YAML block and the
Go code disagree, **the Go code wins** (e.g. `/etc/shadow` is CRITICAL in Go but the YAML block
still says HIGH). Tune behaviour by editing the *lists*; changing a `condition:` string does
nothing until an evaluator exists (deferred — see ancestry-cache doc §5).

---

## 1. The detection layers (evaluation order)

Every event runs this gauntlet. Order matters — the first thing that drops or matches wins.

| # | Layer | Where | Effect |
|---|-------|-------|--------|
| 0 | **Sensor** | kernel | execsnoop / opensnoop / lsm-connect emit the raw event |
| 1 | **Workload resolution** | enricher + resolver | attaches `runtime` ∈ {docker, k8s, host, unknown} and `state` ∈ {resolved, pending, unknown} |
| 2 | **Layer 1 infra fast-path** | resolver → `safeInfraPIDs` | persistent daemons matching `infrastructure_filters` (comm + trusted binary prefix) are discovered at startup; their PIDs become trust roots for the ancestry walk |
| 3 | **`ignore_namespaces`** | `Detect()` | events in `kube-system`, `gmp-system`, `gke-managed-cim` → dropped |
| 4 | **Layer 2 `global_exceptions`** | `isGloballyExcepted()` | context-aware pre-filter drop (init / infrastructure parent). **Infrastructure exceptions are skipped for verified containers** (a shell/curl *inside* a container is the signal, not host noise) |
| 5 | **`ppid == 1` short-circuit** | per-type checks | direct children of init/systemd = trusted infra → dropped |
| 6 | **Process whitelist** | `isWhitelisted()` | `customer_applications` (e.g. `redis-cli`) → dropped (T1036 is checked *before* this) |
| 7 | **Container-context gating** | `isContainerContext()` | `state != unknown` AND `runtime ∈ {docker,k8s}`. Container-specific rules fire **only** for verified containers |
| 8 | **`state=unknown` handling** | per-type checks | ancestry-trusted parent → suppress; eBPF capture artifacts → suppress; else → **LOW telemetry** (Phase 3), not CRITICAL |
| 9 | **Rule match** | `checkProcess/File/NetworkRules` | first match wins, ordered CRITICAL→…→LOW |
| 10 | **Response** | `ResponseFor()` | kill_process / block_ip for a short list of rules; everything else alert-only |
| 11 | **Sinks** | alertsink | file + Supabase always; **Redis drops LOW** (keeps telemetry off the live dashboard) |

**Two gates do most of the false-positive work:**

- **Container-context gating (`isContainerContext`).** If we could not *verify* the process
  belongs to a container (`state == unknown`), we do **not** fire container-specific rules on it.
  Absence of identity is a visibility gap, not a threat (Falco-aligned). This is why an
  unresolved process never trips T1059/T1552/etc.
- **Ancestry parent verification (`isParentTrusted`).** A process whose ancestry roots in verified
  infrastructure (a Layer 1 PID, or a trusted daemon/shell chain resolved via the ancestry cache)
  is lifecycle activity, not an escape. Name-agnostic — safety is *who spawned it*, not what it is
  called. Full model in [DESIGN-PROCESS-ANCESTRY-CACHE.md](DESIGN-PROCESS-ANCESTRY-CACHE.md) §3.5.

---

## 2. Rules — the attack and how we detect it

Each rule below: **what the adversary is doing**, **the kernel signal**, **the exact condition as
coded**, **severity + response**, and **what suppresses it**. Grouped by sensor.

### 2.1 Process execution (execsnoop → `checkProcessRules`)

Order inside `checkProcessRules`: `ppid==1` drop → **T1036 (before whitelist)** → whitelist →
`state=unknown` branch → verified-container rules.

---

#### T1036 — Masquerading  ·  HIGH  ·  alert-only
**Attack.** The adversary drops a malicious binary named after something legitimate (e.g.
`/tmp/sshd`, `/dev/shm/nginx`) and runs it from a writable directory to blend in with `ps`.

**Signal.** execsnoop captures the `execve` with the full binary path (`comm`).

**Condition (Go).** `comm` has a prefix in `suspicious_exec_paths`
(`/tmp/`, `/dev/shm/`, `/var/tmp/`, `/run/user/`). Checked **before** the process whitelist and
**before** container gating — so a masqueraded binary fires even if its *name* (`sshd`) is
whitelisted, and regardless of resolution state. Location is the signal, not the name.

**Suppression.** None specific — deliberately runs ahead of the whitelist.

---

#### T1059.004 / T1609 — Unix shell execution  ·  CRITICAL  ·  alert-only
**Attack.** After RCE inside a container, the adversary spawns an interactive shell
(`/bin/sh`, `/bin/bash`) — the classic "I'm in" step, or `kubectl exec`/`docker exec` abuse.

**Signal.** execsnoop captures the shell `execve`.

**Condition (Go).** verified container **and** `base(comm) ∈ shell_processes` (bash, sh, zsh, dash).

**Suppression.** `customer_applications`; not gated for `state=unknown`; alert-only because shells
run constantly in legitimate builds / health checks — killing would break workloads.

---

#### T1105 / T1095 — Ingress tool transfer  ·  HIGH  ·  alert-only
**Attack.** The adversary stages tooling or exfiltrates with a transfer utility (`nc`, `ncat`,
`wget`) that has no business inside an app container.

**Signal.** execsnoop captures the tool `execve`.

**Condition (Go).** verified container **and** `base(comm) ∈ network_tools` (nc, ncat, wget).

**Suppression.** The Layer 2 "health checks spawned by container runtimes" exception covers
`curl/wget/nc` **only when the parent is infrastructure and off-container** — inside a verified
container it still fires.

---

#### T1613 — Container & resource discovery  ·  HIGH  ·  alert-only
**Attack.** Inside a container, the adversary runs a container-management tool (`docker`,
`kubectl`, `crictl`, `ctr`, `podman`) to enumerate the surrounding environment and find lateral
movement targets.

**Signal.** execsnoop captures the `execve` (fires even though the tool later fails with no socket
mounted — the process event precedes any I/O).

**Condition (Go).** verified container **and** `base(comm) ∈ container_mgmt_tools`.

**Suppression.** Container gating. The agent's own `crictl` sync is excluded by seeding the agent
namespace as `RuntimeHost` (see K8s resolver notes).

---

### 2.2 File access (opensnoop → `checkFileRules`)

Order: `ppid==1` drop → `whitelisted_file_access_procs` (special runc states) → whitelist →
container-gated rules. All file rules require `isVerifiedContainer` unless noted.

---

#### T1552.004 — Private key access  ·  CRITICAL (dir) / HIGH (suffix)  ·  **kill_process**
**Attack.** The adversary reads an SSH private key from inside a container to pivot to other hosts.

**Signal.** opensnoop captures the `file_open`.

**Condition (Go).** verified container and either the path is under `ssh_key_dirs`
(`/root/.ssh/`, `/home/.ssh/`) → **CRITICAL**, or the filename ends in a `ssh_key_suffixes` entry
(`.key`, `.pem`, `id_rsa`, `id_ed25519`) → **HIGH**. `.pem` under `pem_exclude_paths`
(`/site-packages/`, `/certifi/`) is skipped — those are CA bundles, not private keys.

**Response.** `kill_process` (High+) — no container should read SSH keys.

---

#### T1003.008 — OS credential dumping  ·  CRITICAL  ·  **kill_process**
**Attack.** The adversary reads `/etc/shadow` to crack password hashes offline.

**Signal.** opensnoop captures the `file_open`.

**Condition (Go).** verified container and path prefix in `credential_dump_paths` (`/etc/shadow`).
*(Note: the YAML `detections:` block labels this HIGH; the Go code fires it CRITICAL — Go wins.)*

**Response.** `kill_process` — never legitimate inside a container.

---

#### T1552.001 — Credentials in files  ·  HIGH  ·  alert-only
**Attack.** The adversary harvests plaintext secrets — a Docker secret mount or a `.env` file with
DB passwords / API keys.

**Signal.** opensnoop captures the `file_open`.

**Condition (Go).** verified container and (path under `credential_file_dirs` = `/run/secrets/`,
or filename ends in `credential_file_suffixes` = `.env`).

**Suppression / why alert-only.** Apps legitimately read their own `.env` at startup, so we alert
but don't kill.

---

#### T1082 — System information discovery  ·  MEDIUM  ·  alert-only
**Attack.** The adversary enumerates local accounts (`cat /etc/passwd`) to find privilege-escalation
targets.

**Signal.** opensnoop captures the `file_open`.

**Condition (Go).** verified container **and** the *reader* is a recon/shell tool
(`base(comm) ∈ recon_file_readers`) **and** the path is in `system_info_paths`
(`/etc/passwd`, `/etc/group`).

**The reader gate is the key fix.** `/etc/passwd` and `/etc/group` are world-readable and read
constantly by libc NSS (`getpwuid`/`getgrgid`), so *every* normal service tripped this — a
false-positive storm. Gating on the reader means the app's own NSS reads stay quiet while
`cat /etc/passwd`-style discovery still fires. Caveat: a service whose entrypoint runs
`getent`/`id`/`cat` at startup would still fire → allowlist that service.

---

#### T1053.003 — Scheduled task / cron  ·  HIGH  ·  alert-only
**Attack.** The adversary edits cron for persistence inside the container.

**Signal.** opensnoop captures the `file_open`.

**Condition (Go).** verified container and path prefix in `cron_paths` (`/etc/cron.*`,
`/var/spool/cron/`, `/etc/crontab`).

---

#### T1070.003 — Clear command history  ·  MEDIUM  ·  alert-only
**Attack.** The adversary covers tracks by reading/clearing shell history.

**Signal.** opensnoop captures the `file_open`.

**Condition (Go).** verified container and filename ends in `shell_history_suffixes`
(`.bash_history`, `.zsh_history`, `.ash_history`, `.sh_history`).

---

#### T1611 — Escape to host (procfs)  ·  HIGH  ·  alert-only
**Attack.** A container process reaches the host init process via `/proc/1/` — a namespace-escape
tell.

**Signal.** opensnoop captures the `file_open`.

**Condition (Go).** verified container and path prefix in `proc_escape_paths` (`/proc/1/`) **and**
not one of the read-only `proc_escape_allowed` files (`/proc/1/stat|status|cmdline|mountinfo`,
which monitoring tools legitimately read).

**Why alert-only.** GKE monitoring sidecars hit this as a known FP.

---

#### T1611 — Escape to host (filesystem)  ·  CRITICAL  ·  **DEFINED BUT INACTIVE**
**Attack.** A process on the *host* reads a container's overlay filesystem directly
(`/var/lib/docker/overlay2/…`, `/run/containerd/…`), bypassing container isolation to steal
secrets.

**Current state.** The rule exists in `default.yaml` (`container_fs_paths`) but its check in
`checkFileRules` is **commented out** — GKE/host system processes (containerd, installers)
legitimately touch these paths and the whitelist to separate them is not built. **Not firing
today.** To re-enable: uncomment the `RuntimeHost` block in `checkFileRules`, complete the host
allowlist, then re-add validate test T7.

---

### 2.3 Network (lsm-connect → `checkNetworkRules`)

---

#### T1041 / T1048 — Exfiltration over C2 / alternative protocol  ·  HIGH  ·  **block_ip**
**Attack.** A compromised container opens an outbound connection to attacker C2 / an exfil
endpoint.

**Signal.** lsm-connect audits the `socket_connect` (destination IP + port).

**Condition (Go).** destination **not** in `private_ranges` (RFC1918 + loopback + link-local, v4
and v6) **and** verified container **and** destination port ∉ `network.allowed_ports`
(53 DNS, 123 NTP, 6543 Supabase) **and** service ∉ `network.allowed_services`
(`inventory-service` → CoinGecko).

**Response.** `block_ip` — the first connection fires the alert and writes the dst IP into the
`blocked_ips` LPMTrie map; subsequent connects to that IP get EPERM at the kernel before the TCP
handshake (outbound-only, IPv4). Private IPs are never blocked.

---

### 2.4 Unresolved namespace → telemetry (not a rule)

#### `EDR_telemetry_unresolved_namespace`  ·  LOW  ·  off the dashboard
**What it is.** A process whose namespace never resolved **and** whose ancestry could not be
verified as infrastructure. This is a **visibility gap**, not an escape (Falco has no equivalent
"unknown = threat" signal). Emitted at LOW so it still lands in the file + Supabase (input to a
future anomaly service), but the Redis sink drops LOW so it stays off the live dashboard.

This **supersedes** the old `T1611_escape_host_ns` CRITICAL. That YAML entry is retained only as
the technique reference; `is_unknown_namespace` no longer means "escape." Real escape detection
lives in the file-based T1611 rules above and, longer term, in escape *primitives* (setns,
release_agent, privileged mounts) rather than a resolver-timing artifact
([DESIGN-PROCESS-ANCESTRY-CACHE.md](DESIGN-PROCESS-ANCESTRY-CACHE.md) §3.6, §5).

---

## 3. Policy layers in detail

### Layer 1 — `infrastructure_filters` (fast-path trust roots)
Persistent daemons only, matched by **comm + trusted binary prefix** (path validation blocks
spoofs like `/tmp/sshd`): `host_system` (systemd family, dbus, sshd, cron), `docker_runtime`
(dockerd, containerd, containerd-shim, docker-proxy), `kubernetes` (kubelet, kube-proxy, crio),
`agent` (ebpf-edr self). The resolver discovers these at startup and hands their PIDs to the
detector as `safeInfraPIDs`, which seed the ancestry walk. Dynamically-spawned `runc` is **not**
here — it's handled by the ancestry walk at Layer 2.

### Layer 2 — `global_exceptions` (context-aware pre-filter)
Drops legitimate activity **before** rule matching. Each exception gates on `parent_context`:
- `init` (ppid == 1): package managers, common utilities, system-info tools during startup.
- `infrastructure` (ancestry roots in a Layer 1 PID / trusted daemon): SSH-session utilities,
  runtime health checks (`curl/wget/nc`).
- `su/sudo` reading only auth files (`/etc/passwd|group|shadow`, `/etc/pam.d/`) — scoped so it
  can't be abused to read SSH keys or secrets.

**Critical rule:** `parent_context: infrastructure` exceptions are **skipped for verified
containers** (`isContainerContext` true) — otherwise a container shell/curl (whose parent is the
trusted `containerd-shim`) would be wrongly suppressed. Host/node infra noise is quieted; the
in-container signal is preserved.

### `ignore_namespaces`
`kube-system`, `gmp-system`, `gke-managed-cim` — pure K8s infra noise, dropped wholesale.

### Whitelists
- `customer_applications` (`redis-cli`) — known-benign app, suppress all rules (checked after
  T1036).
- `whitelisted_file_access_procs` (`runc:[2:INIT]`, `runc:[1:CHILD]`) — container-init runc states
  that read `/etc/passwd` by design.
- `pem_exclude_paths` — CA bundles, excluded from the `.pem` private-key check.

### Host handling (flat, not tiered)
Host processes resolve to a single `runtime=host, service=host-process` and are trusted via the
`ppid==1` short-circuit + ancestry walk; residual unresolved host activity goes to LOW telemetry.
There is **no** per-host-service policy tier (systemd vs dockerd vs init) — an earlier design
(`HOST_RUNTIME_POLICIES.md`) proposed one but it was not adopted; the ancestry-walk + telemetry
approach replaced it.

### Responses (`response_policy.go`)
Automated response is deliberately narrow — only where action is unambiguously safe:

| Rule | Response | Rationale |
|------|----------|-----------|
| T1552.004 private keys | `kill_process` | no container should read SSH keys |
| T1003.008 `/etc/shadow` | `kill_process` | never legitimate in a container |
| T1041 exfiltration | `block_ip` | deny the dst IP at the kernel on re-connect |
| everything else | alert-only | shells/curl/`.env`/`/etc/passwd` etc. have legitimate uses; killing risks breaking workloads |

---

## 4. Known drift / gotchas

- **YAML `detections:` severities can lag Go.** They are reference; Go is truth (e.g.
  `/etc/shadow` CRITICAL in Go vs HIGH in YAML). Don't trust the YAML block for severity.
- **`T1611_escape_host_fs` is inactive** (commented out) — the YAML rule reads as live but does
  not fire.
- **T1082 startup FP** — a service that runs `getent`/`id`/`cat` in its entrypoint will fire;
  allowlist per-service.
- **Response coverage is 3 rules** — adding a rule does not add a response unless listed in
  `response_policy.go`.
