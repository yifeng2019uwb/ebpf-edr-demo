# ebpf-edr-demo

eBPF-based runtime security monitor for containerized services, built for endpoint security and EDR (Endpoint Detection and Response) research.

---

## Background

This project monitors [cloud-native-order-processor](https://github.com/yifeng2019uwb/cloud-native-order-processor) — a production-style microservices platform deployed on a GCP VM (Debian 12, kernel 6.1).

The order processor runs 8 Docker containers:

| Container             | Role                                      |
|-----------------------|-------------------------------------------|
| `gateway`             | Go API gateway, port 8080                 |
| `auth_service`        | Python/uvicorn, JWT authentication        |
| `user_service`        | Python/uvicorn, balance and portfolio     |
| `inventory_service`   | Python/uvicorn, asset catalog             |
| `order_service`       | Python/uvicorn, trade execution           |
| `insights_service`    | Python/uvicorn, AI portfolio insights     |
| `redis`               | Rate limiting, IP blocking, distributed locks |
| `localstack`          | DynamoDB (local AWS emulation)            |

The goal: attach eBPF probes to the running kernel on the GCP VM, observe all 8 services at the syscall and network level, and generate security alerts — without modifying any service code.

---

## Projects

### New — Go + cilium/ebpf monitor (this directory)

Container-aware runtime security monitor for the cloud-native order processor.
Uses [cilium/ebpf](https://github.com/cilium/ebpf) to load BPF programs from Go,
maps kernel events to Docker containers via cgroup IDs, and generates structured alerts.

> Work in progress.

### Legacy — bpftrace + Python EDR demo

Original learning project: bpftrace hooks `execve`, Python agent applies detection rules.

See [legacy/](legacy/) for code and usage.
