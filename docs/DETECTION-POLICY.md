# Detection Policy

This document covers **what we suppress and why**, organized by environment.
For what we detect and MITRE mapping, see [MITRE-COVERAGE.md](MITRE-COVERAGE.md).
For implementation details and technical notes, see [NOTES.md](NOTES.md).

---

## Policy Philosophy

1. **Never suppress a rule just to reduce noise** — if a rule fires on legitimate traffic, make the rule smarter (add comm/path/namespace context), not smaller.
2. **Whitelist at the right layer** — process whitelists go in `whitelistComm` or `fileCommWhitelist` in `policy.go`. Never hardcode suppressions inside detection logic.
3. **Document every suppression** — if it's not documented here, it should not be in the whitelist.
4. **Environment-specific noise belongs here** — each deployment environment has its own system daemons. Document them per environment so future operators understand why they're suppressed.
5. **False positives are a signal** — if a rule fires on normal traffic it means the rule needs tightening, not deletion.

---

## How to Add a Whitelist Entry

1. Identify the `comm` name from `DBG file-detect` or `DBG file-enrich` logs
2. Confirm it is a known legitimate OS/platform daemon (not user code)
3. Add to the appropriate list in `pkg/detector/policy.go`:
   - `whitelistComm` — suppress ALL rules for this process (process + file + network)
   - `fileCommWhitelist` — suppress file access rules only (process still monitored)
   - `unknownNsCommsWhitelist` — K8s infrastructure processes in unknown namespaces
4. Add a comment in `policy.go` explaining what the process is and why it's safe
5. Add an entry in this document under the relevant environment section

---

## Environment Noise Policy

### GCP Docker VM (`instance-20260318-023006`)

Runtime: `--runtime=docker`
Services: order-processor (8 containers)

| Process | Whitelist | Reason |
|---------|-----------|--------|
| `runc`, `runc:[2:INIT]`, `runc:[1:CHILD]` | `fileCommWhitelist` | Reads `/etc/passwd` to resolve UIDs during container init |
| `dockerd` | `fileCommWhitelist` | Reads overlay2 on every docker exec / container lifecycle event |
| `containerd-shim` | `fileCommWhitelist` | Manages container stdio and lifecycle files under `/run/containerd/` |
| `curl` | `fileCommWhitelist` | Calls `getpwuid()` to find home dir before looking up `~/.curlrc` |
| `id` | `fileCommWhitelist` | Reads `/etc/passwd` and `/etc/group` by design — that is its only purpose |
| `bash` | `fileCommWhitelist` | Reads `/etc/passwd` at startup for `$PS1` prompt — `shell_spawn_container` CRITICAL already fires separately |
| `systemd-logind` | `fileCommWhitelist` | Session manager reads `/etc/passwd` and `/proc/1/` during login events |
| `sshd` | `whitelistComm` | SSH access from laptop — all rules suppressed |
| `runc` | `whitelistComm` | Docker container runtime |
| `dockerd` | `whitelistComm` | Docker daemon |
| `containerd` | `whitelistComm` | Container runtime |
| `getconf` | `whitelistComm` | GCP guest agent |

---

### GKE (on-demand — `make test-env-up`)

Runtime: `--runtime=k8s`
Services: order-processor (5 pods)

**System namespace suppression** — `kube-system`, `gmp-system`, `gke-managed-cim` suppressed entirely.
Constant high-frequency noise (kube-proxy iptables, prometheus /proc reads, kubelet polling) with no actionable signal.

**Infrastructure process whitelist** (`unknownNsCommsWhitelist`):

| Process | Reason |
|---------|--------|
| `iptables`, `iptables-legacy`, `iptables-restore` | kube-proxy syncs network rules every ~30s |
| `ip6tables` | IPv6 iptables variant |
| `conntrack` | Connection tracking tool |
| `ip` | iproute2 route/addr management |
| `kube-proxy` | Kubernetes network proxy |
| `pause` | GKE pod sandbox container |
| `systemd-sysctl` | Node sysctl configuration |
| `bridge-network-interface` | udev network bridge setup |

**Known GKE false positives** (not suppressed — see below):

| Process | Rule | Reason not suppressed |
|---------|------|----------------------|
| `iptables`/`ip6tables` | `unknown_namespace_process` CRITICAL | kube-proxy in host net namespace — already handled by `unknownNsCommsWhitelist` |
| `redis-cli` | `unknown_namespace_process` CRITICAL | kubelet liveness probe — runs from host namespace |
| `operator` → port 10250 | `unauthorized_external_connect` HIGH | GKE Managed Prometheus polls kubelet metrics API |
| `sidecar`/`prometheus` reading `/proc/1/stat` | `sensitive_file_access` HIGH | GKE monitoring sidecars — expected behavior |
| LocalStack | `shell_spawn_container` CRITICAL + `sensitive_file_access` HIGH | Runs internal shell scripts + reads own `.pem`/`.key` at startup. **Intentionally not suppressed** — if LocalStack were compromised, these are exactly the signals we want. Accept as known startup noise. |

---

### Oracle VM1 (`163.192.46.25`) — gateway + auth-service

Runtime: `--runtime=docker` via systemd `ebpf-edr`
Services: healthcare-gateway (8080), healthcare-auth (8082)
Private IP: `10.0.1.160`

**Oracle-specific noise:**

| Process | Whitelist | Reason |
|---------|-----------|--------|
| `pmdaproc` | `fileCommWhitelist` | Oracle Performance Co-Pilot (PCP) process monitoring daemon. Reads `/proc/*/stat`, `/proc/*/statm`, `/proc/*/wchan` for every process every 30s. Generates hundreds of file events per second. |
| `pmdalinux` | `fileCommWhitelist` | Oracle PCP Linux performance metrics agent. Reads `/sys/class/net/*/speed`, `/proc/net/if_inet6`, `/proc/self/mounts`. Normal Oracle Linux monitoring. |

> **Status**: `pmdaproc` and `pmdalinux` are NOT yet added to `policy.go` — pending rebuild.
> Until then, use `EBPF_DEBUG=0` (default) to suppress DBG output.

---

### Oracle VM2 (`163.192.30.193`) — provider-service + ai-service

Runtime: `--runtime=docker` via systemd `ebpf-edr`
Services: healthcare-provider (8083), healthcare-ai (8085)
Private IP: `10.0.1.55`
Access: internal only — reachable from VM1 via `10.0.1.x`, not publicly accessible

Same Oracle-specific noise as VM1 (`pmdaproc`, `pmdalinux`).
eBPF agent not yet installed on VM2 — pending.

---

## Noise Pattern: `/proc` polling daemons

A recurring pattern across environments: system monitoring daemons that poll `/proc` continuously.

| Daemon | Environment | Files read | Events/sec (approx) |
|--------|-------------|------------|---------------------|
| `pmdaproc` | Oracle VM | `/proc/*/stat`, `/proc/*/statm`, `/proc/*/wchan` | 100–500 |
| `pmdalinux` | Oracle VM | `/sys/class/net/*`, `/proc/net/*` | 10–50 |
| `prometheus` | GKE | `/proc/1/stat`, `/proc/self/*` | 5–20 |
| `kubelet` | GKE | `/proc/*/status` | 10–30 |

**Rule**: any process that reads `/proc/*/` on a regular interval and is a known system daemon belongs in `fileCommWhitelist`, not in detection rules.

---

## DBG Logging Policy

DBG log lines (`DBG file-detect`, `DBG file-enrich`, `DBG file-pending`, `DBG file-drop`) are for development only.

- **Default (production)**: `EBPF_DEBUG` not set → DBG lines suppressed
- **Debug mode**: `EBPF_DEBUG=1` → all DBG lines enabled

> **Status**: DBG gating behind `EBPF_DEBUG=1` is not yet implemented — pending rebuild.
> Currently ALL file events are logged to journal, causing high CPU and journal flood on Oracle VMs.

Set in systemd service to enable:
```ini
[Service]
Environment=EBPF_DEBUG=1
```

---

## Pending Policy Changes

| Change | Environment | Status | File |
|--------|-------------|--------|------|
| Add `pmdaproc` to `fileCommWhitelist` | Oracle VM1, VM2 | Pending rebuild | `policy.go` |
| Add `pmdalinux` to `fileCommWhitelist` | Oracle VM1, VM2 | Pending rebuild | `policy.go` |
| Gate DBG lines behind `EBPF_DEBUG=1` | All | Pending rebuild | `rules.go`, `main.go` |
| Rebuild binary + redeploy Oracle VMs | Oracle VM1, VM2 | Blocked on above | — |
