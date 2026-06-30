// Package detector implements detection logic for the EDR agent.
// Network support: private IP detection + GCP K8s service CIDR discovery.
package detector

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// privateNets contains all known-private IP ranges.
// Used for network detection: private IPs don't trigger external connection alerts.
// Includes RFC 1918 + link-local + GCP K8s service CIDR (if detected).
var privateNets []*net.IPNet

func init() {
	// Initialize RFC 1918 private networks — applicable everywhere.
	// These do NOT require environment detection.
	for _, cidr := range []string{
		"10.0.0.0/8",     // RFC 1918 — private class A
		"172.16.0.0/12",  // RFC 1918 — private class B (includes Docker bridge 172.17.x)
		"192.168.0.0/16", // RFC 1918 — private class C
		"169.254.0.0/16", // link-local (APIPA)
	} {
		_, n, _ := net.ParseCIDR(cidr)
		privateNets = append(privateNets, n)
	}

	// SERVICE_CIDR environment variable — manual override (no network calls needed).
	// Set this only when auto-detection is not available (non-GKE, local Docker).
	if cidr := strings.TrimSpace(os.Getenv("SERVICE_CIDR")); cidr != "" {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			privateNets = append(privateNets, n)
			return
		}
	}

	// GKE-specific CIDRs: DEFER to AddGKEServiceCIDR() — call only when GKE detected.
	// Reason: gkeServiceCIDR() makes HTTP requests to metadata server (2s timeout).
	// Avoid unnecessary latency on non-GKE environments (Docker, bare-metal).
}

// AddGKEServiceCIDR loads GKE-specific service CIDR from metadata server.
// Call this only after detecting GKE environment.
// GKE service CIDRs are outside RFC 1918 (e.g. 34.118.x.x); inter-service calls
// via ClusterIP would otherwise be flagged as unauthorized external connections.
func AddGKEServiceCIDR() {
	if cidr := gkeServiceCIDR(); cidr != "" {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			privateNets = append(privateNets, n)
		}
	}
}

// gkeServiceCIDR reads SERVICE_CLUSTER_IP_RANGE from the GCP instance metadata server.
// Returns empty string on any error (non-GKE environment, metadata unreachable, etc.).
func gkeServiceCIDR() string {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest("GET",
		"http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		// Not on GKE or metadata server unreachable — normal for Docker/local runs.
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "SERVICE_CLUSTER_IP_RANGE:") {
			cidr := strings.TrimSpace(strings.TrimPrefix(line, "SERVICE_CLUSTER_IP_RANGE:"))
			log.Printf("gkeServiceCIDR: auto-detected service CIDR %s from GCP metadata", cidr)
			return cidr
		}
	}
	return ""
}
