# Validation Guide — eBPF EDR Detection Rules

Manual test procedure to verify each detection rule fires correctly against real container behavior.
Run on the GCP VM while the EDR agent is running.

---

## Prerequisites

- EDR agent running: `sudo ./ebpf-edr-demo`
- All 8 order-processor containers running: `docker ps`
- Two terminals open:
  - Terminal 1: `tail -f alerts/alert.log` — watch alerts in real time
  - Terminal 2: run `sudo ./validate.sh` — execute test cases

---

## Test Cases

### T1 — Shell Spawn in Container

**Threat**: Attacker achieved RCE inside a container and spawned an interactive shell.

**Monitor**: execsnoop (`sys_enter_execve`)

**Command**:
```bash
docker exec order-processor-auth_service bash -c "id"
```

**Expected alert**:
```
level=CRITICAL rule=shell_spawn_container container=order-processor-auth_service comm=bash
```

**Why it fires**: `bash` binary path matches `shellBinaries` suffix list. Any shell spawn inside a
container is treated as RCE evidence regardless of the command run inside it.

---

### T2 — Network Recon Tool in Container

**Threat**: Attacker inside a container runs `wget` or `nc` to probe external hosts or exfiltrate data.

**Monitor**: execsnoop (`sys_enter_execve`)

**Command**:
```bash
docker exec order-processor-auth_service wget --timeout=2 -q http://1.1.1.1 2>/dev/null || true
```

**Expected alert**:
```
level=HIGH rule=network_tool_container container=order-processor-auth_service comm=wget
```

**Note**: Detection fires on binary execution, not network connection. If `wget` is not installed in
the container, use `nc` or `ncat` — any binary in `networkBinaries` triggers this rule.

---

### T3 — Sensitive File: `/etc/shadow`

**Threat**: Attacker inside a container reads the password hash file to crack credentials offline.

**Monitor**: opensnoop (`sys_enter_openat` + `sys_exit_openat`)

**Command**:
```bash
docker exec order-processor-auth_service cat /etc/shadow
```

**Expected alert**:
```
level=HIGH rule=sensitive_file_access container=order-processor-auth_service comm=cat
msg=Container accessed sensitive file: /etc/shadow
```

**Note**: `cat` gets `EACCES` (permission denied) but opensnoop still fires — the two-probe design
emits on access-denied opens, not just successful ones. This is intentional: the *attempt* to read
shadow is the signal, not the success.

---

### T4 — Sensitive File: SSH Private Key

**Threat**: Attacker reads an SSH private key from inside a container to move laterally.

**Monitor**: opensnoop

**Setup** (run once to create a test key in the container):
```bash
docker exec order-processor-auth_service bash -c \
  "mkdir -p /root/.ssh && echo 'test-key-material' > /root/.ssh/id_rsa"
```

**Command**:
```bash
docker exec order-processor-auth_service cat /root/.ssh/id_rsa
```

**Expected alert**:
```
level=CRITICAL rule=sensitive_file_access container=order-processor-auth_service comm=cat
msg=Container accessed SSH credential file: /root/.ssh/id_rsa
```

**Note**: The setup step also triggers `shell_spawn_container` CRITICAL — that is expected.
The SSH key read itself is a separate CRITICAL event.

---

### T5 — Unauthorized External Network Connection

**Threat**: Compromised container reaches out to an attacker-controlled external IP (C2, exfiltration).

**Monitor**: lsm-connect (`lsm/socket_connect`)

**Command**:
```bash
docker exec order-processor-auth_service python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(('8.8.8.8', 80))
finally:
    s.close()
" 2>/dev/null || true
```

**Expected alert**:
```
level=HIGH rule=unauthorized_external_connect container=order-processor-auth_service
msg=Container made unauthorized external connection to 8.8.8.8:80
```

**Why it fires**: `auth_service` is not in `externalAllowedContainers`. Any external IP (non-RFC-1918)
connection from an unauthorized container triggers HIGH.

---

### T6 — Authorized External Connection (Audit Log)

**Threat model**: Verify the allowlist works — `inventory_service` is the only container permitted
to call the external CoinGecko API. This test confirms the LOW audit log fires (not a HIGH alert).

**Monitor**: lsm-connect

**Command**: Trigger the inventory service to fetch live market data via the API gateway:
```bash
curl http://localhost:8080/api/v1/assets   # adjust endpoint to match your gateway route
```

**Expected alert**:
```
level=LOW rule=external_connect_allowed container=order-processor-inventory_service
msg=order-processor-inventory_service external connect to <ip>:443 (expected: api.coingecko.com)
```

**Why LOW not HIGH**: `inventory_service` is listed in `externalAllowedContainers`. The connection
is expected but still logged for audit — operator can verify the destination IP resolves to CoinGecko.

---

### T7 — Host Process Reads Container Filesystem

**Threat**: Attacker on the host (via container escape or stolen host credentials) reads secrets
directly from a container's filesystem on disk — bypassing container isolation entirely.

**Monitor**: opensnoop

**Command**:
```bash
MERGED=$(docker inspect order-processor-auth_service \
  --format '{{.GraphDriver.Data.MergedDir}}')
cat "${MERGED}/etc/hostname"
```

**Expected alert**:
```
level=CRITICAL rule=host_reads_container_fs container=host
msg=Host process accessed Docker container filesystem: /var/lib/docker/overlay2/.../etc/hostname
```

**Why it fires**: Any host process (container == "host") opening a path under
`/var/lib/docker/overlay2/` is treated as a container filesystem access from outside.
No legitimate application reads container overlay mounts directly.

---

## Out of Scope

| Scenario | Why excluded |
|---|---|
| SSH login detection | Host-level auth — outside container threat model |
| `systemd-logind` session events | OS login handling — not a container threat |
| Container escape via kernel exploit | Requires real CVE — impractical to simulate safely |
| Host-level network monitoring | No host process allowlist — too noisy without full inventory |

---

## Results Checklist

Run all tests and verify each fires:

- [ ] T1 — CRITICAL `shell_spawn_container`
- [ ] T2 — HIGH `network_tool_container`
- [ ] T3 — HIGH `sensitive_file_access` (`/etc/shadow`)
- [ ] T4 — CRITICAL `sensitive_file_access` (SSH key)
- [ ] T5 — HIGH `unauthorized_external_connect`
- [ ] T6 — LOW `external_connect_allowed` (inventory_service)
- [ ] T7 — CRITICAL `host_reads_container_fs`
