package main

import (
	"github.com/pulumi/pulumi-gcp/sdk/v9/go/gcp/logging"
	"github.com/pulumi/pulumi-gcp/sdk/v9/go/gcp/projects"
	"github.com/pulumi/pulumi-gcp/sdk/v9/go/gcp/pubsub"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// deployBase provisions Cloud Logging, Pub/Sub, and IAM for all eBPF agents.
// agentMembers is the full list of agent SA member strings from deployAgentIdentities.
// Returns the edr-alerts topic so deploySensor can attach additional grants.
func deployBase(ctx *pulumi.Context, agentMembers pulumi.StringArray) (*pubsub.Topic, error) {

	// ── Hot storage: Cloud Logging custom bucket, 365-day retention ──────────
	//
	// Replaces the _Default bucket (30-day) for ebpf-edr-alerts.
	// Queryable via: gcloud logging read 'logName=...' --project=ebpfagent
	_, err := logging.NewProjectBucketConfig(ctx, "ebpf-edr-logging-bucket", &logging.ProjectBucketConfigArgs{
		BucketId:      pulumi.String("ebpf-edr-security-logs-" + region),
		Location:      pulumi.String(region),
		Project:       pulumi.String(project),
		RetentionDays: pulumi.Int(365),
	})
	if err != nil {
		return nil, err
	}

	// Route ebpf-edr-alerts into the custom bucket.
	// UniqueWriterIdentity=true gives the sink its own SA (least-privilege).
	_, err = logging.NewProjectSink(ctx, "ebpf-edr-to-logging-bucket", &logging.ProjectSinkArgs{
		Name:        pulumi.String("ebpf-edr-to-logging-bucket-" + region),
		Destination: pulumi.String("logging.googleapis.com/projects/" + project + "/locations/" + region + "/buckets/ebpf-edr-security-logs-" + region),
		Filter:      pulumi.String(`logName="projects/` + project + `/logs/` + logName + `"`),
		UniqueWriterIdentity: pulumi.Bool(true),
	})
	if err != nil {
		return nil, err
	}

	// ── logging.logWriter — all agents write to central Cloud Logging ─────────
	//
	// IAMBinding is authoritative for this role.
	// Add new environments in agents.go — no changes needed here.
	_, err = projects.NewIAMBinding(ctx, "ebpf-agents-logging-writer", &projects.IAMBindingArgs{
		Project: pulumi.String(project),
		Role:    pulumi.String("roles/logging.logWriter"),
		Members: agentMembers,
	})
	if err != nil {
		return nil, err
	}

	// ── Pub/Sub — real-time alert stream ─────────────────────────────────────
	//
	// Agents publish CRITICAL/HIGH alerts here (fire-and-forget, async).
	// Alert Router subscribes and fans out via WebSocket to the browser.
	// Topic-level IAM keeps publisher grants minimal (not project-wide).
	topic, err := pubsub.NewTopic(ctx, "edr-alerts-topic", &pubsub.TopicArgs{
		Name:    pulumi.String("edr-alerts"),
		Project: pulumi.String(project),
	})
	if err != nil {
		return nil, err
	}

	_, err = pubsub.NewSubscription(ctx, "edr-alerts-router-sub", &pubsub.SubscriptionArgs{
		Name:                     pulumi.String("edr-alerts-router-sub"),
		Topic:                    topic.Name,
		Project:                  pulumi.String(project),
		MessageRetentionDuration: pulumi.String("604800s"), // 7 days
		AckDeadlineSeconds:       pulumi.Int(60),
	})
	if err != nil {
		return nil, err
	}

	// All agents — publisher on edr-alerts topic (topic-level, not project-wide)
	_, err = pubsub.NewTopicIAMBinding(ctx, "ebpf-agents-pubsub-publisher", &pubsub.TopicIAMBindingArgs{
		Topic:   topic.Name,
		Project: pulumi.String(project),
		Role:    pulumi.String("roles/pubsub.publisher"),
		Members: agentMembers,
	})
	if err != nil {
		return nil, err
	}

	// ── Cold storage: GCS bucket + lifecycle + sink ───────────────────────────
	//
	// Full lifecycle design (not deployed for personal project — enable when needed):
	//
	//   Day 0–365:   GCS Standard — parallel full copy via sink below
	//   Day 365:     Coldline ($0.004/GB/mo) — Cloud Logging bucket auto-expires
	//   Day 1095:    Archive ($0.0012/GB/mo) — equivalent to AWS Glacier
	//   Day 1095+:   Delete (extend if compliance requires longer retention)
	//
	// Regulation basis: SOC 2 Type II (1yr), PCI DSS 10.7 (1yr), NIST SP 800-92 (3yr)
	//
	// gcsBucket, err := storage.NewBucket(ctx, "ebpf-edr-cold-bucket", &storage.BucketArgs{ ... })
	// gcsSink, err := logging.NewProjectSink(ctx, "ebpf-edr-to-gcs", &logging.ProjectSinkArgs{ ... })
	// _, err = storage.NewBucketIAMMember(ctx, "ebpf-edr-sink-gcs-writer", ...)

	return topic, nil
}
