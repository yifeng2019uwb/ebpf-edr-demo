# Setup Guide

## One-time: Install Go 1.24

```bash
wget https://go.dev/dl/go1.24.2.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc

# Verify
go version  # should show go1.24.2
```

## One-time: Project Setup

```bash
mkdir ~/workspace/ebpf-edr-demo
cd ~/workspace/ebpf-edr-demo
mkdir kernel

go mod init ebpf-edr-demo
go get github.com/cilium/ebpf
go get -tool github.com/cilium/ebpf/cmd/bpf2go
go mod tidy
```

## Per Session: After Adding C Files

```bash
# Create gen.go listing your .bpf.c files

# Compile C → Go wrappers
go generate

# Verify generated files
ls *.go *.o
```

## Build and Run
// add main.go

```bash
go mod tidy
go build
sudo ./ebpf-edr-demo
// sudo ./ebpf-edr-demo > output.txt 2>&1
```

