BINARY := ebpf-edr-demo

.PHONY: generate build rebuild test vet clean

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
