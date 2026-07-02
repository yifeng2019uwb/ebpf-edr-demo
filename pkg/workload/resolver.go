//go:build linux

package workload

import (
	"fmt"
	"log"
	"os"

	"ebpf-edr-demo/internal/config"
)

func NewResolver(runtime Runtime) WorkloadResolver {
	node, err := os.Hostname()
	if err != nil {
		log.Printf("workload: os.Hostname() failed: %v — node field will be empty in alerts", err)
	}
	region := os.Getenv(config.EnvRegion)
	cluster := os.Getenv(config.EnvClusterName)
	env := os.Getenv(config.EnvEnv)

	switch runtime {
	case RuntimeK8s:
		return &K8sResolver{node: node, region: region, cluster: cluster, env: env}
	case RuntimeDocker:
		return &DockerResolver{hostname: node, region: region, env: env}
	default:
		panic(fmt.Sprintf("workload: runtime %q not supported", runtime))
	}
}
