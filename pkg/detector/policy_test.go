package detector

import (
	"net"
	"testing"
)

func TestIsSystemNamespace(t *testing.T) {
	tests := []struct {
		ns   string
		want bool
	}{
		{"kube-system", true},
		{"gmp-system", true},
		{"gke-managed-cim", true},
		{"default", false},
		{"order-processor", false},
		{"kube-public", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ns, func(t *testing.T) {
			got := isSystemNamespace(tt.ns)
			if got != tt.want {
				t.Fatalf("isSystemNamespace(%q) = %v, want %v", tt.ns, got, tt.want)
			}
		})
	}
}

func TestIsWhitelisted(t *testing.T) {
	tests := []struct {
		comm string
		want bool
	}{
		{"sshd", true},
		{"runc", true},
		{"dockerd", true},
		{"containerd", true},
		{"getconf", true},
		{"/usr/sbin/sshd", true},    // filepath.Base strips path prefix
		{"/usr/local/bin/runc", true},
		{"bash", false},             // whitelisted in fileCommWhitelist, not process whitelist
		{"python3", false},
		{"curl", false},             // curl excluded from process rules via fileCommWhitelist, not here
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.comm, func(t *testing.T) {
			got := isWhitelisted(tt.comm)
			if got != tt.want {
				t.Fatalf("isWhitelisted(%q) = %v, want %v", tt.comm, got, tt.want)
			}
		})
	}
}

func TestIsPemExcluded(t *testing.T) {
	tests := []struct {
		filename string
		want     bool
	}{
		{"/usr/local/lib/python3.9/site-packages/certifi/cacert.pem", true},
		{"/usr/lib/python3/dist-packages/certifi/cacert.pem", true},
		{"/usr/local/lib/python3/site-packages/requests/cacert.pem", true},
		{"/app/server.pem", false},
		{"/etc/ssl/certs/ca-bundle.pem", false},
		{"/root/.ssl/server.pem", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := isPemExcluded(tt.filename)
			if got != tt.want {
				t.Fatalf("isPemExcluded(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestMatchesSuffix(t *testing.T) {
	tests := []struct {
		comm string
		list []string
		want bool
	}{
		{"/bin/bash", shellBinaries, true},
		{"/usr/bin/zsh", shellBinaries, true},
		{"/bin/sh", shellBinaries, true},
		{"/bin/dash", shellBinaries, true},
		{"/usr/bin/python3", shellBinaries, false},
		{"/usr/bin/wget", networkBinaries, true},
		{"/bin/nc", networkBinaries, true},
		{"/usr/bin/ncat", networkBinaries, true},
		{"/usr/bin/curl", networkBinaries, false}, // curl intentionally excluded
		{"bash", shellBinaries, true},             // no path prefix still matches suffix /bash? No — suffix is "/bash"
	}

	// Note: the last case — "bash" does NOT have suffix "/bash", so want=false.
	// Fix the last test case:
	tests[len(tests)-1].want = false

	for _, tt := range tests {
		t.Run(tt.comm, func(t *testing.T) {
			got := matchesSuffix(tt.comm, tt.list)
			if got != tt.want {
				t.Fatalf("matchesSuffix(%q) = %v, want %v", tt.comm, got, tt.want)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"169.254.0.1", true},   // link-local
		{"169.254.255.255", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"104.18.0.1", false},
		{"34.118.0.1", false},   // GKE service CIDR range (not in RFC 1918)
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := isPrivateIP(ip)
			if got != tt.want {
				t.Fatalf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
