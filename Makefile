BINARY          := ebpf-edr
DOCKER_REGISTRY := us-west1-docker.pkg.dev/ebpfagent/ebpf-edr
DOCKER_IMAGE    := $(DOCKER_REGISTRY)/ebpf-edr:latest
SENSOR_IMAGE    := $(DOCKER_REGISTRY)/sensor:latest
COLLECTOR_IMAGE := $(DOCKER_REGISTRY)/collector:latest

# Path to order-processor repo (override if needed)
ORDER_PROCESSOR_DIR ?= $(HOME)/workspace/github_projects/order_processor/cloud-native-order-processor

.PHONY: generate build rebuild test vet clean docker-build docker-push sensor-build sensor-push run-docker run-alert-router infra-up infra-down github-release test-env-up test-env-down

## generate — compile .bpf.c → .o and regenerate Go wrappers in pkg/bpf/
## Requires: clang, llvm, libbpf-dev (run on GCP VM, not Mac)
generate:
	go generate ./pkg/bpf/

## build — compile the EDR agent binary (cross-compiles to linux/amd64 from any host)
build:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY) ./cmd/edr-monitor/

## rebuild — regenerate BPF wrappers then build (use after editing .bpf.c files)
rebuild: generate build

## test — run unit tests for non-BPF packages and show coverage
test:
	go test -v -count=1 -coverprofile=coverage.out ./internal/... ./pkg/detector/...
	go tool cover -func=coverage.out

## vet — run go vet on non-BPF packages (safe on any Linux host)
vet:
	go vet ./internal/... ./pkg/detector/... ./pkg/workload/... ./pkg/pipeline/...

## clean — remove built binary
clean:
	rm -f $(BINARY)

## docker-build — cross-compile binary then build image locally (does not push)
docker-build: build
	docker buildx build --platform linux/amd64 --no-cache \
		-t $(DOCKER_IMAGE) .

## docker-push — cross-compile binary then build image and push to Artifact Registry
docker-push: build
	docker buildx build --platform linux/amd64 --no-cache --push \
		-t $(DOCKER_IMAGE) .

## run-docker — run the EDR agent on the Docker VM (sets GOOGLE_CLOUD_PROJECT, must run as root)
run-docker:
	sudo env GOOGLE_CLOUD_PROJECT=ebpfagent ./$(BINARY) --runtime=docker

## run-alert-router — run the Alert Router on laptop (open http://localhost:8888)
run-alert-router:
	go run ./cmd/alert-router/

## sensor-build — cross-compile sensor + collector binaries for linux/amd64
sensor-build:
	cd sensor && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o sensor .
	cd sensor/collector && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o collector .

## sensor-push — build and push sensor + collector images to Artifact Registry
sensor-push: sensor-build
	docker buildx build --platform linux/amd64 --no-cache --push \
		-t $(SENSOR_IMAGE) sensor/
	docker buildx build --platform linux/amd64 --no-cache --push \
		-t $(COLLECTOR_IMAGE) sensor/collector/

## infra-up — provision all infrastructure via Pulumi (logging, pubsub, IAM, sensor VM)
infra-up:
	cd infra && pulumi up

## infra-down — destroy all Pulumi-managed infrastructure
infra-down:
	cd infra && pulumi destroy

## infra-refresh — sync Pulumi state with actual GCP state (fixes drift from manual changes)
## Run this if resources were changed outside Pulumi (e.g. manually deleted via gcloud)
infra-refresh:
	cd infra && pulumi refresh --yes && pulumi up --yes

## sensor-up — provision sensor VM (IoT workload testing)
sensor-up:
	cd infra && pulumi config set sensorEnabled true && pulumi up

## sensor-down — destroy sensor VM to save costs (~$15/month)
## Always use this instead of gcloud compute instances delete
sensor-down:
	cd infra && pulumi config set sensorEnabled false && pulumi up

## test-env-up — spin up all test environments (GKE + order-processor + eBPF DaemonSet)
## Cost: ~$100/month while running — destroy when done with make test-env-down
## Usage: make test-env-up
## Override order-processor path: make test-env-up ORDER_PROCESSOR_DIR=/path/to/repo
test-env-up:
	@echo "=== Step 1: eBPF infra (Cloud Logging, Pub/Sub, IAM) ==="
	$(MAKE) infra-up
	@echo ""
	@echo "=== Step 2: GKE cluster (order-processor) ==="
	cd $(ORDER_PROCESSOR_DIR)/gcp_gke && pulumi up --yes
	@echo ""
	@echo "=== Step 3: Deploy order-processor + eBPF DaemonSet ==="
	cd $(ORDER_PROCESSOR_DIR)/gcp_gke && ./deploy.sh all
	@echo ""
	@echo "=== Done ==="
	@echo "Gateway URL: check 'kubectl get svc -n order-processor' for EXTERNAL-IP"
	@echo "eBPF alerts: gcloud logging read 'logName=\"projects/ebpfagent/logs/ebpf-edr-alerts\"' --project=ebpfagent --limit=10"
	@echo "Alert Router: make run-alert-router"
	@echo ""
	@echo "IMPORTANT: Run 'make test-env-down' when done to stop ~\$$100/month charges"

## test-env-down — destroy all test environments to save ~$100/month
## Keeps: eBPF infra (Cloud Logging, Pub/Sub, IAM), GCP Docker VM
## Destroys: GKE cluster, Load Balancer, Cloud NAT
test-env-down:
	@echo "=== Destroying GKE cluster + order-processor ==="
	cd $(ORDER_PROCESSOR_DIR)/gcp_gke && ./cleanup.sh 2>/dev/null || true
	cd $(ORDER_PROCESSOR_DIR)/gcp_gke && pulumi destroy --yes
	@echo ""
	@echo "=== Verifying no orphaned resources ==="
	@gcloud compute forwarding-rules list --project=ebpfagent --format="table(name,region)" 2>/dev/null && echo "Load balancers: none ✓" || true
	@gcloud container clusters list --project=ebpfagent --format="table(name,location)" 2>/dev/null && echo "GKE clusters: none ✓" || true
	@echo ""
	@echo "=== Done — GCP charges now ~\$$1/month ==="
	@echo "eBPF monitoring continues on GCP VM + Oracle VMs"

## github-release — build linux/amd64 binary and publish as a GitHub release
## Usage: make github-release VERSION=v0.1.0
## Requires: gh CLI authenticated (gh auth login)
VERSION ?= $(shell git describe --tags --always --dirty)
github-release: build
	gh release create $(VERSION) $(BINARY) \
		--title "eBPF EDR $(VERSION)" \
		--notes "linux/amd64 binary — deploy to any Linux env (GCP VM, Oracle Cloud, GKE, etc.)"
