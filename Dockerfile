FROM debian:bookworm-slim
ARG CRICTL_VERSION=v1.30.0
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    curl -fsSL https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-amd64.tar.gz | \
    tar -xz -C /usr/local/bin && \
    apt-get remove -y curl && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*
RUN mkdir -p /alerts /app/rules
COPY bin/ebpf-edr /usr/local/bin/ebpf-edr
COPY rules/default.yaml /app/rules/default.yaml
WORKDIR /app
ENTRYPOINT ["/usr/local/bin/ebpf-edr", "-runtime=k8s"]
