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
                                                   ↓
                                           Alert Router (WebSocket UI)
```

**Cost note**: GCP VM runs 24/7 at ~$0/month (always free).
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

Verify agent sees containers (trigger a shell spawn — simplest observable event):
```bash
docker exec order-processor-auth_service bash -c "id"
# Should produce a CRITICAL T1059_unix_shell_execution alert — check alert log:
tail -5 ~/workspace/ebpf-edr-demo/alerts/alert.log
```

---

## Step 2 — GKE (on-demand — bring up only for testing)

Services: health-ai (4 pods: auth-service, provider-service, gateway, ai-service)
eBPF runtime: `--runtime=k8s` via DaemonSet in `kube-system`
Cluster: `health-ai-cluster-us-west1`, namespace: `health-ai`, project: `ebpfagent`

### 4a. Service check

```bash
gcloud container clusters list --project=ebpfagent --format="table(name,location,status)"
```

If no cluster — bring it up:
```bash
cd kubernetes/pulumi && pulumi up
cd kubernetes && ./deploy.sh all
```

Check pods:
```bash
kubectl get pods -n health-ai
kubectl get svc gateway -n health-ai   # get EXTERNAL-IP
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
```

Verify agent sees pods (trigger a shell spawn — simplest observable event):
```bash
POD=$(kubectl get pods -n health-ai -l component=auth-service -o jsonpath='{.items[0].metadata.name}')
kubectl exec $POD -n health-ai -- sh -c "exit 0"

# Check Cloud Logging for GKE events
gcloud logging read 'jsonPayload.runtime="k8s"' \
  --project=ebpfagent --log-filter='logName="projects/ebpfagent/logs/ebpf-edr-alerts"' \
  --limit=3 --format="table(timestamp,jsonPayload.service,jsonPayload.rule)"
```

---

## Step 3 — Sensor VM (optional — IoT workload, droppable)

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

## Step 4 — Alert Router (laptop)

Real-time WebSocket UI showing alerts from all environments.

```bash
cd ~/workspace/ebpf-edr-demo
make run-alert-router
```

Open **http://localhost:8888**

Alerts from all environments appear here tagged with `env` field:
- `gcp-vm` — GCP Docker VM
- `sensor-vm` — Sensor VM (IoT, optional)
- `k8s` runtime — GKE pods

---

## Step 5 — Run attack simulations

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

---

## Step 6 — Tear down GKE when done

```bash
cd ~/workspace/ebpf-edr-demo
make test-env-down
```

GCP VM keeps running (always free / ~$0).
eBPF Cloud Logging and Pub/Sub infra kept (near zero cost).

---

## Quick Status (all environments at once)

```bash
echo "=== GCP VM ===" && \
gcloud compute instances list --project=project-3f1d99fa-d525-4aff-a03 --format="table(name,zone,status)" 2>/dev/null

echo "=== GKE ===" && \
gcloud container clusters list --project=ebpfagent --format="table(name,status)" 2>/dev/null || echo "not running"

echo "=== Recent eBPF Alerts ===" && \
gcloud logging read 'logName="projects/ebpfagent/logs/ebpf-edr-alerts"' \
  --project=ebpfagent --limit=5 \
  --format="table(timestamp,jsonPayload.env,jsonPayload.service,jsonPayload.rule)"
```
