# eBPF EDR — Full System Testing Guide

Step-by-step checklist to bring up all monitored environments and verify both the
services and the eBPF agent are running for each one before attack simulations.

Each environment section has two checks:
- **Service check** — are the monitored containers/pods running?
- **eBPF agent check** — is the agent running and seeing events from this environment?

---

## Architecture Overview

```
GCP Docker VM  ─── eBPF agent (Docker runtime) ──┐
GKE cluster    ─── eBPF DaemonSet (K8s runtime) ──┼─→ Cloud Logging (ebpfagent)
Oracle VM1     ─── eBPF agent (Docker runtime) ──┤      ↓
Oracle VM2     ─── eBPF agent (Docker runtime) ──┘  Alert Router (WebSocket UI)
```

**Cost note**: GCP VM + Oracle VMs run 24/7 at ~$0/month (always free).
GKE costs ~$100/month — bring up only for testing, destroy after with `make test-env-down`.

---

## Infrastructure Rules

**Always use Makefile targets to provision and remove cloud resources — never raw `gcloud`, `kubectl`, or `pulumi` commands directly.**

Bypassing Pulumi creates state drift (Pulumi thinks a resource exists when it doesn't), which causes failures on the next `pulumi up`.

| Task | Command | Never do |
|------|---------|---------|
| Deploy all infra | `make infra-up` | `gcloud ... create` |
| Destroy all infra | `make infra-down` | `gcloud ... delete` |
| Fix state drift | `make infra-refresh` | `pulumi state delete` |
| Add sensor VM | `make sensor-up` | `gcloud compute instances create` |
| Remove sensor VM | `make sensor-down` | `gcloud compute instances delete` |
| Deploy GKE + app | `make test-env-up` | `pulumi up` directly |
| Destroy GKE + app | `make test-env-down` | `kubectl delete` + `pulumi destroy` |

If resources were changed outside Pulumi (e.g. manual deletion), sync state first:
```bash
make infra-refresh   # pulumi refresh → detect drift → pulumi up to reconcile
```

---

## Step 1 — GCP Docker VM

Services: order-processor (8 containers)
eBPF runtime: `--runtime=docker` on the host VM

### 1a. Service check

```bash
gcloud compute instances list --project=project-3f1d99fa-d525-4aff-a03 \
  --format="table(name,zone,status)"
```

Expected: `instance-20260318-023006   us-west1-b   RUNNING`

If VM not running:
```bash
gcloud compute instances start instance-20260318-023006 \
  --zone=us-west1-b --project=project-3f1d99fa-d525-4aff-a03
```

Then SSH in and check containers:
```bash
ssh instance-20260318-023006
docker ps --format "table {{.Names}}\t{{.Status}}"
```

Expected: 8 order-processor containers (auth, gateway, user, inventory, order, etc.)

If containers not running:
```bash
cd ~/workspace/cloud-native-order-processor
docker compose up -d
```

### 1b. eBPF agent check

```bash
# On GCP VM — is agent running?
pgrep -a ebpf-edr
```

Expected: process listed with `--runtime=docker`

If not running — start it:
```bash
cd ~/workspace/ebpf-edr-demo
sudo env GOOGLE_CLOUD_PROJECT=ebpfagent ./ebpf-edr --runtime=docker
```

Confirm startup:
```
Cloud Logging enabled: project=ebpfagent
Pub/Sub enabled: topic=edr-alerts
```

Verify agent sees containers (trigger a test event):
```bash
docker exec order-processor-auth_service ls /tmp
# Should produce an opensnoop event — check alert log:
tail -5 ~/workspace/ebpf-edr-demo/alerts/alert.log
```

---

## Step 2 — Oracle VM1 (gateway + auth-service)

Services: healthcare-gateway (8080), healthcare-auth (8082)
eBPF runtime: `--runtime=docker` via systemd service `ebpf-edr`

> **After VM reboot:** Services do NOT auto-start. Always start VM2 first (gateway depends on backend).
> eBPF agent auto-starts via systemd.
> `BACKEND_VM_IP` in VM1's `.env` must be VM2's **private IP** (`10.0.1.55`) — set by `deploy-vm.sh` automatically.

### 2a. Service check

```bash
ssh -i ~/.ssh/oracle_vm opc@163.192.46.25 \
  "sudo docker ps --format '{{.Names}}\t{{.Status}}'"
```

Expected:
```
healthcare-auth     Up X minutes
healthcare-gateway  Up X minutes
```

If containers not running (start VM2 first — see Step 3a, then):
```bash
ssh -i ~/.ssh/oracle_vm opc@163.192.46.25 \
  "cd ~/healthcare/docker && sudo docker compose -f compose-gateway.yml up -d"
```

Verify `BACKEND_VM_IP` is set to private IP (not public):
```bash
ssh -i ~/.ssh/oracle_vm opc@163.192.46.25 "grep BACKEND_VM_IP ~/healthcare/docker/.env"
# Expected: BACKEND_VM_IP=10.0.1.55
```

Validate service health:
```bash
cd ~/workspace/github_projects/health-ai/healthcare-ai-microservices/integration_tests
./run-it.sh auth
```

Expected: `✓ Auth endpoints passed`

### 2b. eBPF agent check

```bash
ssh -i ~/.ssh/oracle_vm opc@163.192.46.25 \
  "systemctl is-active ebpf-edr && sudo journalctl -u ebpf-edr -n 5 --no-pager"
```

Expected: `active` + recent log lines showing agent running

If not active:
```bash
ssh -i ~/.ssh/oracle_vm opc@163.192.46.25 "sudo systemctl start ebpf-edr"
```

If not installed — deploy agent (requires SA key):
```bash
cd ~/workspace/github_projects/health-ai/healthcare-ai-microservices
EBPF_SA_KEY_FILE=/tmp/oracle-agent.json ./docker/setup-vm.sh
```

Verify agent sees containers:
```bash
# Trigger CRITICAL alert — shell spawn inside container
ssh -i ~/.ssh/oracle_vm opc@163.192.46.25 \
  "sudo docker exec healthcare-gateway bash -c 'id'"

# Check Cloud Logging for VM1 events
gcloud logging read 'jsonPayload.env="oracle-vm1"' \
  --project=ebpfagent --log-filter='logName="projects/ebpfagent/logs/ebpf-edr-alerts"' \
  --limit=3 --format="table(timestamp,jsonPayload.service,jsonPayload.rule)"
```

---

## Step 3 — Oracle VM2 (provider-service + ai-service)

Services: healthcare-provider (8083), healthcare-ai (8085)
eBPF runtime: `--runtime=docker` via systemd service `ebpf-edr`

> **After VM reboot:** Start VM2 BEFORE VM1. Services do NOT auto-start. eBPF agent auto-starts via systemd.
> VM2 is backend-only — accessible only from VM1 via internal VCN (10.0.1.x). Not publicly reachable.

### 3a. Service check

```bash
ssh -i ~/.ssh/oracle_vm opc@163.192.30.193 \
  "sudo docker ps --format '{{.Names}}\t{{.Status}}'"
```

Expected:
```
healthcare-provider  Up X minutes
healthcare-ai        Up X minutes
```

If containers not running (start VM2 FIRST, before VM1):
```bash
ssh -i ~/.ssh/oracle_vm opc@163.192.30.193 \
  "cd ~/healthcare/docker && sudo docker compose -f compose-backend.yml up -d"
```

Check memory usage:
```bash
ssh -i ~/.ssh/oracle_vm opc@163.192.30.193 "sudo docker stats --no-stream"
```

Expected: provider ~200MB, ai ~250MB — both well within 522MB limit.

### 3b. eBPF agent check

```bash
ssh -i ~/.ssh/oracle_vm opc@163.192.30.193 \
  "systemctl is-active ebpf-edr && sudo journalctl -u ebpf-edr -n 5 --no-pager"
```

Expected: `active`

If not active:
```bash
ssh -i ~/.ssh/oracle_vm opc@163.192.30.193 "sudo systemctl start ebpf-edr"
```

Verify agent sees containers:
```bash
# Trigger test event on VM2
ssh -i ~/.ssh/oracle_vm opc@163.192.30.193 \
  "sudo docker exec healthcare-provider ls /tmp"

# Check Cloud Logging for VM2 events
gcloud logging read 'jsonPayload.env="oracle-vm2"' \
  --project=ebpfagent --log-filter='logName="projects/ebpfagent/logs/ebpf-edr-alerts"' \
  --limit=3 --format="table(timestamp,jsonPayload.service,jsonPayload.rule)"
```

---

## Step 4 — GKE (on-demand — ~$100/month while running)

Services: order-processor (5 pods: user, inventory, order, auth, gateway)
eBPF runtime: `--runtime=k8s` via DaemonSet in `kube-system`

### 4a. Service check

```bash
gcloud container clusters list --project=ebpfagent --format="table(name,location,status)"
```

If no cluster — deploy everything:
```bash
cd ~/workspace/ebpf-edr-demo
make test-env-up   # ~10 min
```

Check pods:
```bash
kubectl get pods -n order-processor
kubectl get svc gateway-service -n order-processor   # get EXTERNAL-IP
```

Expected: all pods `Running`, gateway has an EXTERNAL-IP.

### 4b. eBPF agent check

```bash
kubectl get pods -n kube-system -l app=ebpf-edr
kubectl logs -n kube-system -l app=ebpf-edr --tail=5
```

Expected: DaemonSet pod `Running` with:
```
Cloud Logging enabled: project=ebpfagent
Pub/Sub enabled: topic=edr-alerts
```

Verify agent sees pods:
```bash
# Trigger test event in a pod
POD=$(kubectl get pods -n order-processor -l component=user-service -o jsonpath='{.items[0].metadata.name}')
kubectl exec $POD -n order-processor -- ls /tmp

# Check Cloud Logging for GKE events
gcloud logging read 'jsonPayload.runtime="k8s"' \
  --project=ebpfagent --log-filter='logName="projects/ebpfagent/logs/ebpf-edr-alerts"' \
  --limit=3 --format="table(timestamp,jsonPayload.service,jsonPayload.rule)"
```

---

## Step 5 — Sensor VM (optional — IoT workload, droppable)

Services: env-sensor, gps-tracker, device-health (3 Docker containers)
eBPF runtime: `--runtime=docker` on the host VM
Cost: ~$15/month (e2-small) — destroy when not testing

> Status: IoT sensor workload is in planning phase. The VM infrastructure is ready
> but the sensor containers are not yet fully implemented. Skip this step unless
> testing CO-RE compatibility on a new kernel or IoT sensor attack scenarios.

### 5a. Service check

Check if sensor VM exists:
```bash
gcloud compute instances list --project=ebpfagent --format="table(name,zone,status)"
```

If not running — provision it:
```bash
cd ~/workspace/ebpf-edr-demo/infra
pulumi config set sensorEnabled true
make infra-up
```

SSH in and check containers:
```bash
SENSOR_IP=$(cd ~/workspace/ebpf-edr-demo/infra && pulumi stack output sensorPublicIp)
ssh ubuntu@$SENSOR_IP "docker ps --format 'table {{.Names}}\t{{.Status}}'"
```

Expected: 3 sensor containers running (env-sensor, gps-tracker, device-health)

### 5b. eBPF agent check

```bash
ssh ubuntu@$SENSOR_IP "sudo systemctl status ebpf-edr --no-pager | head -10"
```

Expected: `Active: active (running)`

Verify agent sees sensor containers:
```bash
# Trigger test event
ssh ubuntu@$SENSOR_IP "sudo docker exec sensor-env-sensor ls /tmp"

# Check Cloud Logging for sensor VM events
gcloud logging read 'jsonPayload.env="sensor-vm"' \
  --project=ebpfagent --log-filter='logName="projects/ebpfagent/logs/ebpf-edr-alerts"' \
  --limit=3 --format="table(timestamp,jsonPayload.service,jsonPayload.rule)"
```

### Destroy sensor VM when done

```bash
cd ~/workspace/ebpf-edr-demo/infra
pulumi config set sensorEnabled false
make infra-up   # removes sensor VM, keeps all other infra
```

---

## Step 6 — Alert Router (laptop)

Real-time WebSocket UI showing alerts from all environments.

```bash
cd ~/workspace/ebpf-edr-demo
make run-alert-router
```

Open **http://localhost:8888**

Alerts from all environments appear here tagged with `env` field:
- `gcp-vm` — GCP Docker VM
- `oracle-vm1` — Oracle VM1 (gateway + auth)
- `oracle-vm2` — Oracle VM2 (provider + ai)
- `sensor-vm` — Sensor VM (IoT, optional)
- `k8s` runtime — GKE pods

---

## Step 6 — Run attack simulations

Once all environments are verified, run the full test suites:

### GCP Docker VM
```bash
# On GCP VM
cd ~/workspace/ebpf-edr-demo
sudo ./validate.sh
```
See `docs/VALIDATION.md` for T1–T7 test cases.

### GKE
```bash
# On laptop with kubectl configured
./validate-gke.sh
```
See `docs/VALIDATION-GKE.md` for GKE test cases.

### Oracle VMs (manual)
```bash
# Shell spawn — should fire CRITICAL shell_spawn_container
ssh -i ~/.ssh/oracle_vm opc@163.192.30.193 \
  "sudo docker exec healthcare-provider bash -c 'id'"

# Watch agent log in real time
ssh -i ~/.ssh/oracle_vm opc@163.192.30.193 "sudo journalctl -u ebpf-edr -f"
```

---

## Step 7 — Tear down GKE when done

```bash
cd ~/workspace/ebpf-edr-demo
make test-env-down
```

GCP VM and Oracle VMs keep running (always free / ~$0).
eBPF Cloud Logging and Pub/Sub infra kept (near zero cost).

---

## Quick Status (all environments at once)

```bash
echo "=== GCP VM ===" && \
gcloud compute instances list --project=project-3f1d99fa-d525-4aff-a03 --format="table(name,zone,status)" 2>/dev/null

echo "=== GKE ===" && \
gcloud container clusters list --project=ebpfagent --format="table(name,status)" 2>/dev/null || echo "not running"

echo "=== Oracle VM1 ===" && \
ssh -i ~/.ssh/oracle_vm -o ConnectTimeout=5 opc@163.192.46.25 \
  "systemctl is-active ebpf-edr; sudo docker ps --format '{{.Names}}'" 2>/dev/null || echo "unreachable"

echo "=== Oracle VM2 ===" && \
ssh -i ~/.ssh/oracle_vm -o ConnectTimeout=5 opc@163.192.30.193 \
  "systemctl is-active ebpf-edr; sudo docker ps --format '{{.Names}}'" 2>/dev/null || echo "unreachable"

echo "=== Recent eBPF Alerts ===" && \
gcloud logging read 'logName="projects/ebpfagent/logs/ebpf-edr-alerts"' \
  --project=ebpfagent --limit=5 \
  --format="table(timestamp,jsonPayload.env,jsonPayload.service,jsonPayload.rule)"
```
