BINARY         := ebpf-edr-demo
DOCKER_REGISTRY := us-west1-docker.pkg.dev/ebpfagent/ebpf-edr
DOCKER_IMAGE    := $(DOCKER_REGISTRY)/ebpf-edr:latest

.PHONY: generate build rebuild test vet clean docker-build docker-push

## generate — compile .bpf.c → .o and regenerate Go wrappers in pkg/bpf/
## Requires: clang, llvm, libbpf-dev (run on GCP VM, not Mac)
generate:
	go generate ./pkg/bpf/

## build — compile the EDR agent binary (cross-compiles to linux/amd64 from any host)
build:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY) ./cmd/edr-monitor/

## rebuild — regenerate BPF wrappers then build (use after editing .bpf.c files)
rebuild: generate build

## test — run unit tests for non-BPF packages
test:
	go test -v -count=1 ./internal/... ./pkg/detector/...

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
