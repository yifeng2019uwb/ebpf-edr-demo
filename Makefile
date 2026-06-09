BINARY := ebpf-edr
GHCR_IMAGE := ghcr.io/yifeng2019uwb/ebpf-edr:latest

.PHONY: generate build rebuild test vet clean run_ebpf run-docker run-alert-router infra-up infra-down infra-refresh github-release docker-push-ghcr docker-push-ghcr-prebuilt

## generate — compile .bpf.c → .o and regenerate Go wrappers in pkg/bpf/
## Requires: clang, llvm, libbpf-dev (run on GCP VM, not Mac)
generate:
	go generate ./pkg/bpf/

## build — compile the EDR agent binary (cross-compiles to linux/amd64 from any host)
build:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BINARY) ./cmd/edr-monitor/

## rebuild — regenerate BPF wrappers then build (use after editing .bpf.c files on GCP VM)
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

## run_ebpf — detach any stale LSM links then run the agent (use on shared VMs to avoid BPF_MAX_TRAMP_LINKS)
run_ebpf:
	@sudo bpftool link list | awk '/^[0-9]+: tracing/{id=$$1; sub(":","",id)} /lsm_mac/{print id}' | \
	  xargs -I{} sudo bpftool link detach id {} 2>/dev/null || true
	sudo env GOOGLE_CLOUD_PROJECT=ebpfagent ./$(BINARY) --runtime=docker

## run-docker — run the EDR agent on the Docker VM (sets GOOGLE_CLOUD_PROJECT, must run as root)
run-docker:
	sudo env GOOGLE_CLOUD_PROJECT=ebpfagent ./$(BINARY) --runtime=docker

## run-alert-router — run the Alert Router on laptop (open http://localhost:8888)
run-alert-router:
	go run ./cmd/alert-router/

## infra-up — provision GCP infra via Pulumi (Cloud Logging, Pub/Sub, IAM)
## Note: GCP free tier expires 2026-06-17
infra-up:
	cd infra && pulumi up

## infra-down — destroy all Pulumi-managed GCP infrastructure
infra-down:
	cd infra && pulumi destroy

## infra-refresh — sync Pulumi state with actual GCP state (fixes drift from manual changes)
infra-refresh:
	cd infra && pulumi refresh --yes && pulumi up --yes

## docker-push-ghcr — build binary + image and push to ghcr.io (run on GCP VM — needs Linux for BPF headers)
docker-push-ghcr: build
	docker buildx build --platform linux/amd64 --no-cache --push \
		-t $(GHCR_IMAGE) .

## docker-push-ghcr-prebuilt — push image using committed binary (safe to run on Mac)
docker-push-ghcr-prebuilt:
	docker buildx build --platform linux/amd64 --no-cache --push \
		-t $(GHCR_IMAGE) .

## github-release — build linux/amd64 binary and publish as a GitHub release
## Usage: make github-release VERSION=v0.1.0
## Requires: gh CLI authenticated (gh auth login)
VERSION ?= $(shell git describe --tags --always --dirty)
github-release: build
	gh release create $(VERSION) $(BINARY) \
		--title "eBPF EDR $(VERSION)" \
		--notes "linux/amd64 binary — deploy to any Linux env (GCP VM, GKE, etc.)"


# ── LEGACY ────────────────────────────────────────────────────────────────────
# Kept for reference — do not use unless restoring a previous environment.

# GCP Artifact Registry (expires 2026-06-17)
# DOCKER_REGISTRY := us-west1-docker.pkg.dev/ebpfagent/ebpf-edr
# DOCKER_IMAGE    := $(DOCKER_REGISTRY)/ebpf-edr:latest
# SENSOR_IMAGE    := $(DOCKER_REGISTRY)/sensor:latest
# COLLECTOR_IMAGE := $(DOCKER_REGISTRY)/collector:latest

## docker-build — build image locally using GCP Artifact Registry (legacy)
# docker-build: build
# 	docker buildx build --platform linux/amd64 --no-cache \
# 		-t $(DOCKER_IMAGE) .

## docker-push — build and push to GCP Artifact Registry (legacy)
# docker-push: build
# 	docker buildx build --platform linux/amd64 --no-cache --push \
# 		-t $(DOCKER_IMAGE) .

## docker-push-prebuilt — push committed binary to GCP Artifact Registry (legacy)
# docker-push-prebuilt:
# 	docker buildx build --platform linux/amd64 --no-cache --push \
# 		-t $(DOCKER_IMAGE) .

## sensor-build/push — sensor + collector images (legacy IoT workload)
# sensor-build:
# 	cd sensor && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o sensor .
# 	cd sensor/collector && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o collector .
# sensor-push: sensor-build
# 	docker buildx build --platform linux/amd64 --no-cache --push -t $(SENSOR_IMAGE) sensor/
# 	docker buildx build --platform linux/amd64 --no-cache --push -t $(COLLECTOR_IMAGE) sensor/collector/

## sensor-up/down — IoT sensor VM via Pulumi (legacy)
# sensor-up:
# 	cd infra && pulumi config set sensorEnabled true && pulumi up
# sensor-down:
# 	cd infra && pulumi config set sensorEnabled false && pulumi up

## test-env-up/down — GKE + order-processor full environment (legacy)
# ORDER_PROCESSOR_DIR ?= $(HOME)/workspace/github_projects/order_processor/cloud-native-order-processor
# test-env-up:
# 	$(MAKE) infra-up
# 	cd $(ORDER_PROCESSOR_DIR)/gcp_gke && pulumi up --yes
# 	cd $(ORDER_PROCESSOR_DIR)/gcp_gke && ./deploy.sh all
# test-env-down:
# 	cd $(ORDER_PROCESSOR_DIR)/gcp_gke && ./cleanup.sh 2>/dev/null || true
# 	cd $(ORDER_PROCESSOR_DIR)/gcp_gke && pulumi destroy --yes
