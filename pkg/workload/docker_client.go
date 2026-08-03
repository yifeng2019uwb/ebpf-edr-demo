//go:build linux

// docker_client.go — RuntimeClient for the Docker daemon. Enriches a container ID into
// its service name via ContainerInspect. Holds only the daemon connection; the engine
// owns the cache, host path, and dispatch.
package workload

import (
	"context"
	"log"
	"strings"

	"github.com/docker/docker/client"
)

// dockerComposeLabel names the docker-compose service a container belongs to.
const dockerComposeLabel = "com.docker.compose.service"

type DockerClient struct {
	cli *client.Client
}

var _ RuntimeClient = (*DockerClient)(nil)

// newDockerClient dials the Docker daemon; errors if it is unreachable.
func newDockerClient() (*DockerClient, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &DockerClient{cli: cli}, nil
}

func (d *DockerClient) Runtime() Runtime { return RuntimeDocker }

// Enrich looks up a container's name via ContainerInspect. Service is the compose-service
// label when present, else the container name.
func (d *DockerClient) Enrich(ctx context.Context, containerID string) (WorkloadIdentity, WorkloadMeta, bool) {
	inspect, err := d.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		log.Printf("DEBUG: docker ContainerInspect(%s) failed: %v", containerID, err)
		return WorkloadIdentity{}, WorkloadMeta{}, false
	}
	name := strings.TrimPrefix(inspect.Name, "/")
	service := name
	if label, ok := inspect.Config.Labels[dockerComposeLabel]; ok && label != "" {
		service = label
	}
	return WorkloadIdentity{Runtime: RuntimeDocker, Service: service},
		WorkloadMeta{Container: name, Pod: name}, true
}

func (d *DockerClient) Close() error { return d.cli.Close() }
