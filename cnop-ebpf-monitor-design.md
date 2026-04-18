# cnop-ebpf-monitor — Design Doc

> Reference detail: `cnop-ebpf-monitor-design-detail.md`

## References
- [cilium/ebpf](https://github.com/cilium/ebpf) — Go library used to load and manage BPF programs
- [bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial) — eBPF learning resource

---

## 1. Scope & Requirements

### Goal
Personal learning project to practice eBPF and EDR concepts using a real running workload.
Build a working EDR agent that monitors containerized services using Go + cilium/ebpf.

### What we build
- eBPF programs to capture process, network, and file events from containers
- Go userspace agent that reads events, matches detection rules, and emits JSON alerts
- Optional enforce mode that kills a matching process

### Out of scope
- Production hardening, scalability, dashboards
- Automated test suite / CI pipeline
- Android or embedded targets

## 2. Environment

### Host
- GCP VM, Debian 12, kernel 6.1.0-44-cloud-amd64
- Toolchain: Go + cilium/ebpf + bpf2go + clang/llvm (verified working)
- Repo: [ebpf-edr-demo](https://github.com/yifeng2019uwb/ebpf-edr-demo) at `~/workspace/ebpf-edr-demo`

### Target workload
- Repo: [cloud-native-order-processor](https://github.com/yifeng2019uwb/cloud-native-order-processor) at `~/workspace/cloud-native-order-processor`
- 8 Docker containers, all on internal bridge network

| Container | Language | Port | Role |
|-----------|----------|------|------|
| `order-processor-gateway` | Go | 8080 | API gateway — only public entry point |
| `order-processor-auth_service` | Python | internal | JWT auth |
| `order-processor-user_service` | Python | internal | Balance / portfolio |
| `order-processor-inventory_service` | Python | internal | Asset catalog |
| `order-processor-order_service` | Python | internal | Trade execution |
| `order-processor-insights_service` | Python | internal | AI insights |
| `order-processor-redis` | Redis | internal | Rate limiting, locks |
| `order-processor-localstack` | Java | internal | DynamoDB emulation |

### Accessing services from local laptop
GCP VM only exposes SSH. Use port forwarding to reach the gateway:
```bash
ssh -L 8080:localhost:8080 <user>@<GCP_VM_IP>
# then: curl http://localhost:8080/health
```

## 3. Architecture

### High-level: Kernel Plane → User Plane

```
  Build time
  ──────────────────────────────────────────────────
  write .bpf.c (kernel program)
      ↓
  go generate  →  bpf2go compiles .c → .o + Go wrapper
      ↓
  write main.go using generated wrapper
      ↓
  go build && sudo ./cnop-ebpf-monitor

  Runtime
  ──────────────────────────────────────────────────
┌─────────────────────────────────────────────────┐
│  KERNEL  (.bpf.c programs)                      │
│                                                 │
│  process_monitor    network_monitor  file_monitor│
│  sys_enter_execve   tcp_v4_connect   sys_enter_  │
│                                     openat       │
│         │                │               │      │
│         └────────────────┼───────────────┘      │
│                          │                      │
│               BPF Ring Buffer                   │
└──────────────────────────┼──────────────────────┘
                           │
┌──────────────────────────▼──────────────────────┐
│  USERSPACE  (main.go)                           │
│                                                 │
│  load & attach via bpf2go generated wrapper     │
│         │                                       │
│         ▼                                       │
│  read events from ring buffer                   │
│         │                                       │
│         ▼                                       │
│  resolve container name                         │
│  (mnt_ns → /proc/<pid>/cgroup)                  │
│         │                                       │
│         ▼                                       │
│  match detection rules                          │
│         │                                       │
│         ▼                                       │
│  print JSON alert to stdout                     │
└─────────────────────────────────────────────────┘
```

> Phase 1–4: Audit mode only (print JSON alert)
> Phase 5: Enforce mode (future — requires thorough whitelist validation first)

**What to learn for each part (from [bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial)):**

Batch 1 — build the kernel plane + event transport first:

| Lesson | Topic | Covers |
|--------|-------|--------|
| 04 | opensnoop | file_monitor — `openat` hook |
| 07 | execsnoop | process_monitor — `execve` hook |
| 08 | ringbuf | ring buffer — how kernel sends events to Go agent |

Batch 2 — add network monitor + enforce mode:

| Lesson | Topic | Covers |
|--------|-------|--------|
| 02/03 | kprobe / fentry | hook pattern needed for network_monitor |
| 13 | tcpconnlat | network_monitor — `tcp_v4_connect` |
| 19 | lsm-connect | enforce mode — block at kernel level instead of SIGKILL |

### Why these 3 monitors

The order processor runs 5 Python services + 1 Go gateway. Normal operation:
- Services talk to each other on the Docker bridge — no external connections
- No service should spawn a shell or run system commands
- JWT keys and `.env` credentials sit on disk — services read them once at startup, not repeatedly at runtime

So any of these happening at runtime is suspicious:

| If we see... | Monitor | What it likely means |
|---|---|---|
| `auth_service` spawns `bash` or `nc` | process_monitor | Code execution — attacker got in |
| `order_service` connects to external IP | network_monitor | Exfiltration or C2 callback |
| Any service reads `/etc/shadow` or `*.key` | file_monitor | Credential theft attempt |

### What file_monitor watches

| Path | Why it matters |
|------|----------------|
| `/etc/passwd`, `/etc/shadow` | Credential dumping |
| `*.key`, `*.pem`, `id_rsa` | Private key access |
| `/proc/*/environ` | Environment variables often hold JWT secrets, DB passwords |
| `/var/run/docker.sock` | Container escape — access to this socket = control of the Docker daemon |

### Container Correlation
- Map each event to its container using mount namespace ID (`mnt_ns`)
- Details TBD during implementation

### Detection Engine
- Rules evaluated in Go userspace against each event
- Each rule: ID, severity, MITRE technique, match condition
- Details TBD during implementation

### Response Mode
- Phase 1–4: Audit only — print JSON alert to stdout
- Phase 5 (future): Enforce mode — requires whitelist validation first

## 4. Threat Model
<!-- What we detect and why -->
- [ ] Detection rules table (Det ID, hook, logic, MITRE, severity)
- [ ] Known false positives / whitelists

## 5. Implementation Plan
<!-- Phase by phase, each with a done condition -->
- [ ] Phase 1 — Process monitor end-to-end
- [ ] Phase 2 — Container correlation
- [ ] Phase 3 — Network + file monitors
- [ ] Phase 4 — Detection engine + JSON alerts
- [ ] Phase 5 — Enforce mode
- [ ] Phase 6 — Validation

## 6. Validation
<!-- How to verify it works -->
    ### Manual test scenarios
    - [ ] Manual test scenarios (trigger → expected alert)
    - [ ] Enforce mode verification

    ### Integration test validation
    - Run `run_all_tests.sh` while monitor active
    - Verify: no false positive alerts during normal test run
    - Verify: alerts trigger when test intentionally violates rules

    ### Evidence
    - Screenshots of alerts triggering
    - Alert log showing correct severity/rule/pid
    - Integration test output showing tests pass alongside monitor


