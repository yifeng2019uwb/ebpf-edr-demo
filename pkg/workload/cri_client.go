//go:build linux

// cri_client.go — RuntimeClient for the CRI runtimes (containerd / cri-o) via crictl.
// Enriches a container ID into its k8s service/pod/namespace by reading the standard
// io.kubernetes.* labels crictl reports. Holds no persistent connection — crictl is a CLI.
package workload

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"os/exec"
)

// k8s label keys crictl reports on every CRI container.
const (
	k8sContainerNameLabel = "io.kubernetes.container.name"
	k8sPodNameLabel       = "io.kubernetes.pod.name"
	k8sPodNamespaceLabel  = "io.kubernetes.pod.namespace"
)

// criContainerList is the subset of `crictl ps -o json` we read.
type criContainerList struct {
	Containers []struct {
		Labels map[string]string `json:"labels"`
	} `json:"containers"`
}

type CriClient struct{}

var _ RuntimeClient = (*CriClient)(nil)

// newCriClient verifies crictl is available; errors if not (runtime then stays unregistered).
func newCriClient() (*CriClient, error) {
	if _, err := exec.LookPath("crictl"); err != nil {
		return nil, err
	}
	return &CriClient{}, nil
}

func (c *CriClient) Runtime() Runtime { return RuntimeK8s }

// Enrich runs `crictl ps --id <id>` and reads the k8s labels. Service is the k8s container
// name (already the clean service name — not normalized, which would corrupt hyphenated names).
func (c *CriClient) Enrich(ctx context.Context, containerID string) (WorkloadIdentity, WorkloadMeta, bool) {
	cmd := exec.CommandContext(ctx, "crictl", "ps", "--id", containerID, "--output", "json")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		log.Printf("cri client: crictl ps --id %s failed: %v, stderr=%s", containerID, err, stderr.Bytes())
		return WorkloadIdentity{}, WorkloadMeta{}, false
	}
	var list criContainerList
	if err := json.Unmarshal(out, &list); err != nil {
		log.Printf("cri client: crictl ps --id %s: json.Unmarshal failed: %v, output=%s", containerID, err, out)
		return WorkloadIdentity{}, WorkloadMeta{}, false
	}
	if len(list.Containers) == 0 {
		log.Printf("cri client: crictl ps --id %s: 0 containers returned", containerID)
		return WorkloadIdentity{}, WorkloadMeta{}, false
	}
	labels := list.Containers[0].Labels
	name := labels[k8sContainerNameLabel]
	if name == "" {
		log.Printf("cri client: crictl ps --id %s: no %s label, labels=%v", containerID, k8sContainerNameLabel, labels)
		return WorkloadIdentity{}, WorkloadMeta{}, false
	}
	return WorkloadIdentity{Runtime: RuntimeK8s, Service: name},
		WorkloadMeta{Container: name, Pod: labels[k8sPodNameLabel], Namespace: labels[k8sPodNamespaceLabel]}, true
}

func (c *CriClient) Close() error { return nil }
