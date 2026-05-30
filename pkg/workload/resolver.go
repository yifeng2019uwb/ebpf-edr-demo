//go:build linux

package workload

import (
	"log"
	"os"
)

func NewResolver(runtime string) WorkloadResolver {
	node, err := os.Hostname()
	if err != nil {
		log.Printf("workload: os.Hostname() failed: %v — node field will be empty in alerts", err)
	}
	region := os.Getenv("REGION")
	cluster := os.Getenv("CLUSTER_NAME")
	env := os.Getenv("ENV")

	switch runtime {
	case "k8s":
		return &K8sResolver{node: node, region: region, cluster: cluster, env: env}
	default:
		return &DockerResolver{node: node, region: region, cluster: cluster, env: env}
	}
}
