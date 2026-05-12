BINARY          := ebpf-edr-demo
DOCKER_REGISTRY := us-west1-docker.pkg.dev/ebpfagent/ebpf-edr
DOCKER_IMAGE    := $(DOCKER_REGISTRY)/ebpf-edr:latest
SENSOR_IMAGE    := $(DOCKER_REGISTRY)/sensor:latest
COLLECTOR_IMAGE := $(DOCKER_REGISTRY)/collector:latest

.PHONY: generate build rebuild test vet clean docker-build docker-push sensor-build sensor-push run-docker run-alert-router infra-up infra-down

## generate — compile .bpf.c → .o and regenerate Go wrappers in pkg/bpf/
## Requires: clang, llvm, libbpf-dev (run on GCP VM, not Mac)
generate:
	go generate ./pkg/bpf/

## build — compile the EDR agent binary (cross-compiles to linux/amd64 from any host)
build:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY) ./cmd/edr-monitor/

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

## infra-down — destroy all Pulumi-managed infrastructure (drops sensor VM when not in use)
infra-down:
	cd infra && pulumi destroy
