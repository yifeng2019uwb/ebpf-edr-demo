package main

import (
	"github.com/pulumi/pulumi-gcp/sdk/v9/go/gcp/logging"
	"github.com/pulumi/pulumi-gcp/sdk/v9/go/gcp/projects"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	// "github.com/pulumi/pulumi-gcp/sdk/v9/go/gcp/storage" — needed for cold storage (commented out below)
)

const (
	project = "ebpfagent"
	region  = "us-west1"
	logName = "ebpf-edr-alerts"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
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
			return err
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
			return err
		}

		// ── Cross-project agent access ───────────────────────────────────────────
		//
		// Each monitored project's compute SA gets logging.logWriter on ebpfagent.
		// The agent only needs GOOGLE_CLOUD_PROJECT=ebpfagent in /etc/environment —
		// no key file, no manual credentials.
		//
		// To add a new monitored project: find its compute SA
		//   gcloud iam service-accounts list --project=<project-id>
		// then add an entry below and run pulumi up.

		// OpenClaw project — Docker VM (instance-20260318-023006)
		_, err = projects.NewIAMMember(ctx, "openclaw-vm-logging-writer", &projects.IAMMemberArgs{
			Project: pulumi.String(project),
			Role:    pulumi.String("roles/logging.logWriter"),
			Member:  pulumi.String("serviceAccount:323172929342-compute@developer.gserviceaccount.com"),
		})
		if err != nil {
			return err
		}

		// Healthcare AI project — add compute SA once agent is deployed there
		// _, err = projects.NewIAMMember(ctx, "healthcare-vm-logging-writer", &projects.IAMMemberArgs{
		// 	Project: pulumi.String(project),
		// 	Role:    pulumi.String("roles/logging.logWriter"),
		// 	Member:  pulumi.String("serviceAccount:<project-number>-compute@developer.gserviceaccount.com"),
		// })
		// if err != nil {
		// 	return err
		// }

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
		// gcsBucket, err := storage.NewBucket(ctx, "ebpf-edr-cold-bucket", &storage.BucketArgs{
		// 	Name:                     pulumi.Sprintf("ebpf-edr-cold-%s", region),
		// 	Location:                 pulumi.String(region),
		// 	StorageClass:             pulumi.String("STANDARD"),
		// 	UniformBucketLevelAccess: pulumi.Bool(true),
		// 	LifecycleRules: storage.BucketLifecycleRuleArray{
		// 		&storage.BucketLifecycleRuleArgs{
		// 			Action: &storage.BucketLifecycleRuleActionArgs{
		// 				Type:         pulumi.String("SetStorageClass"),
		// 				StorageClass: pulumi.String("COLDLINE"),
		// 			},
		// 			Condition: &storage.BucketLifecycleRuleConditionArgs{Age: pulumi.IntPtr(365)},
		// 		},
		// 		&storage.BucketLifecycleRuleArgs{
		// 			Action: &storage.BucketLifecycleRuleActionArgs{
		// 				Type:         pulumi.String("SetStorageClass"),
		// 				StorageClass: pulumi.String("ARCHIVE"),
		// 			},
		// 			Condition: &storage.BucketLifecycleRuleConditionArgs{Age: pulumi.IntPtr(1095)},
		// 		},
		// 	},
		// })
		// if err != nil {
		// 	return err
		// }
		//
		// gcsSink, err := logging.NewProjectSink(ctx, "ebpf-edr-to-gcs", &logging.ProjectSinkArgs{
		// 	Name:                 pulumi.Sprintf("ebpf-edr-to-gcs-%s", region),
		// 	Destination:          pulumi.Sprintf("storage.googleapis.com/ebpf-edr-cold-%s", region),
		// 	Filter:               pulumi.Sprintf(`logName="projects/%s/logs/%s"`, project, logName),
		// 	UniqueWriterIdentity: pulumi.Bool(true),
		// })
		// if err != nil {
		// 	return err
		// }
		//
		// // GCP auto-creates a writer SA for each sink. Grant it objectCreator on the GCS bucket.
		// // gcsSink.WriterIdentity is resolved at deploy time — do not hardcode.
		// _, err = storage.NewBucketIAMMember(ctx, "ebpf-edr-sink-gcs-writer", &storage.BucketIAMMemberArgs{
		// 	Bucket: gcsBucket.Name,
		// 	Role:   pulumi.String("roles/storage.objectCreator"),
		// 	Member: gcsSink.WriterIdentity,
		// })
		// if err != nil {
		// 	return err
		// }

		return nil
	})
}
