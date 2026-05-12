package main

import (
	_ "embed"
	"fmt"

	"github.com/pulumi/pulumi-gcp/sdk/v9/go/gcp/compute"
	"github.com/pulumi/pulumi-gcp/sdk/v9/go/gcp/organizations"
	"github.com/pulumi/pulumi-gcp/sdk/v9/go/gcp/projects"
	"github.com/pulumi/pulumi-gcp/sdk/v9/go/gcp/pubsub"
	"github.com/pulumi/pulumi-tls/sdk/v4/go/tls"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

//go:embed scripts/sensor-startup.sh
var sensorStartupScript string

const (
	sensorZone        = "us-west1-a"
	sensorMachineType = "e2-small"
	sensorDiskGB      = 20
	sensorTag         = "sensor-vm"
)

var sensorTypes = []string{"env-sensor", "gps-tracker", "device-health"}

func deploySensor(ctx *pulumi.Context, alertsTopic *pubsub.Topic) error {
	proj, err := organizations.LookupProject(ctx, &organizations.LookupProjectArgs{
		ProjectId: pulumi.StringRef(project),
	}, nil)
	if err != nil {
		return err
	}
	computeSA := fmt.Sprintf("serviceAccount:%s-compute@developer.gserviceaccount.com", proj.Number)

	// ── Certs ────────────────────────────────────────────────────────────────
	caKey, err := tls.NewPrivateKey(ctx, "sensor-ca-key", &tls.PrivateKeyArgs{
		Algorithm: pulumi.String("RSA"),
		RsaBits:   pulumi.Int(2048),
	})
	if err != nil {
		return err
	}

	caCert, err := tls.NewSelfSignedCert(ctx, "sensor-ca-cert", &tls.SelfSignedCertArgs{
		PrivateKeyPem:       caKey.PrivateKeyPem,
		Subject:             &tls.SelfSignedCertSubjectArgs{CommonName: pulumi.String("SensorCA")},
		ValidityPeriodHours: pulumi.Int(87600),
		IsCaCertificate:     pulumi.Bool(true),
		AllowedUses:         pulumi.StringArray{pulumi.String("cert_signing"), pulumi.String("crl_signing")},
	})
	if err != nil {
		return err
	}

	// Metadata map: startup script + CA cert + per-sensor device certs.
	// VM reads cert content from the metadata server on first boot.
	metadata := pulumi.StringMap{
		"startup-script": pulumi.String(sensorStartupScript),
		"ca-cert":        caCert.CertPem,
	}

	for _, sensor := range sensorTypes {
		sensor := sensor

		deviceKey, err := tls.NewPrivateKey(ctx, sensor+"-key", &tls.PrivateKeyArgs{
			Algorithm: pulumi.String("RSA"),
			RsaBits:   pulumi.Int(2048),
		})
		if err != nil {
			return err
		}

		csr, err := tls.NewCertRequest(ctx, sensor+"-csr", &tls.CertRequestArgs{
			PrivateKeyPem: deviceKey.PrivateKeyPem,
			Subject:       &tls.CertRequestSubjectArgs{CommonName: pulumi.String(sensor)},
		})
		if err != nil {
			return err
		}

		deviceCert, err := tls.NewLocallySignedCert(ctx, sensor+"-cert", &tls.LocallySignedCertArgs{
			CertRequestPem:      csr.CertRequestPem,
			CaPrivateKeyPem:     caKey.PrivateKeyPem,
			CaCertPem:           caCert.CertPem,
			ValidityPeriodHours: pulumi.Int(8760),
			AllowedUses:         pulumi.StringArray{pulumi.String("digital_signature"), pulumi.String("client_auth")},
		})
		if err != nil {
			return err
		}

		metadata[sensor+"-device-key"] = deviceKey.PrivateKeyPem
		metadata[sensor+"-device-cert"] = deviceCert.CertPem
	}

	// ── VM ───────────────────────────────────────────────────────────────────
	vm, err := compute.NewInstance(ctx, "sensor-vm", &compute.InstanceArgs{
		Name:        pulumi.String("sensor-vm"),
		Zone:        pulumi.String(sensorZone),
		MachineType: pulumi.String(sensorMachineType),
		Project:     pulumi.String(project),
		Tags:        pulumi.StringArray{pulumi.String(sensorTag)},
		BootDisk: &compute.InstanceBootDiskArgs{
			InitializeParams: &compute.InstanceBootDiskInitializeParamsArgs{
				Image: pulumi.String("ubuntu-os-cloud/ubuntu-2204-lts"),
				Size:  pulumi.Int(sensorDiskGB),
			},
		},
		NetworkInterfaces: compute.InstanceNetworkInterfaceArray{
			&compute.InstanceNetworkInterfaceArgs{
				Network: pulumi.String("default"),
				AccessConfigs: compute.InstanceNetworkInterfaceAccessConfigArray{
					&compute.InstanceNetworkInterfaceAccessConfigArgs{},
				},
			},
		},
		Metadata: metadata,
		ServiceAccount: &compute.InstanceServiceAccountArgs{
			Email:  pulumi.String("default"),
			Scopes: pulumi.StringArray{pulumi.String("https://www.googleapis.com/auth/cloud-platform")},
		},
		AllowStoppingForUpdate: pulumi.Bool(true),
	})
	if err != nil {
		return err
	}

	// ── Networking ───────────────────────────────────────────────────────────
	_, err = compute.NewFirewall(ctx, "sensor-vm-ssh", &compute.FirewallArgs{
		Name:         pulumi.String("sensor-vm-ssh"),
		Network:      pulumi.String("default"),
		Project:      pulumi.String(project),
		Allows:       compute.FirewallAllowArray{&compute.FirewallAllowArgs{Protocol: pulumi.String("tcp"), Ports: pulumi.StringArray{pulumi.String("22")}}},
		TargetTags:   pulumi.StringArray{pulumi.String(sensorTag)},
		SourceRanges: pulumi.StringArray{pulumi.String("0.0.0.0/0")},
	})
	if err != nil {
		return err
	}

	// ── IAM ──────────────────────────────────────────────────────────────────
	_, err = projects.NewIAMMember(ctx, "sensor-vm-logging-writer", &projects.IAMMemberArgs{
		Project: pulumi.String(project),
		Role:    pulumi.String("roles/logging.logWriter"),
		Member:  pulumi.String(computeSA),
	})
	if err != nil {
		return err
	}

	_, err = pubsub.NewTopicIAMMember(ctx, "sensor-vm-pubsub-publisher", &pubsub.TopicIAMMemberArgs{
		Topic:   alertsTopic.Name,
		Project: pulumi.String(project),
		Role:    pulumi.String("roles/pubsub.publisher"),
		Member:  pulumi.String(computeSA),
	})
	if err != nil {
		return err
	}

	_, err = projects.NewIAMMember(ctx, "sensor-vm-ar-reader", &projects.IAMMemberArgs{
		Project: pulumi.String(project),
		Role:    pulumi.String("roles/artifactregistry.reader"),
		Member:  pulumi.String(computeSA),
	})
	if err != nil {
		return err
	}

	// ── Outputs ──────────────────────────────────────────────────────────────
	ctx.Export("sensorVMIP", vm.NetworkInterfaces.Index(pulumi.Int(0)).AccessConfigs().Index(pulumi.Int(0)).NatIp())
	ctx.Export("sensorSSHCmd", pulumi.Sprintf("gcloud compute ssh sensor-vm --zone=%s --project=%s", sensorZone, project))

	return nil
}
