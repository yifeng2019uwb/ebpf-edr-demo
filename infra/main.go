package main

import (
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

const (
	project = "ebpfagent"
	region  = "us-west1"
	logName = "ebpf-edr-alerts"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		agentMembers, err := deployAgentIdentities(ctx)
		if err != nil {
			return err
		}

		topic, err := deployBase(ctx, agentMembers)
		if err != nil {
			return err
		}

		if config.GetBool(ctx, "sensorEnabled") {
			return deploySensor(ctx, topic)
		}
		return nil
	})
}
