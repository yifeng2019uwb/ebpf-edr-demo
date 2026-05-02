package processor

import (
	"testing"
)

func TestCString(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"null terminated", []byte("bash\x00garbage"), "bash"},
		{"no null byte", []byte("bash"), "bash"},
		{"empty string at start", []byte("\x00abc"), ""},
		{"full path", []byte("/usr/bin/python3\x00"), "/usr/bin/python3"},
		{"empty slice", []byte{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CString(tt.input)
			if got != tt.want {
				t.Fatalf("CString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNetIP(t *testing.T) {
	// NetIP reads bytes in order: byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	// so IP a.b.c.d → n = a | b<<8 | c<<16 | d<<24
	tests := []struct {
		n    uint32
		want string
	}{
		{0x08080808, "8.8.8.8"},
		{0x0100000A, "10.0.0.1"},    // 10.0.0.1
		{0x0101A8C0, "192.168.1.1"}, // 192.168.1.1
		{0x00000000, "0.0.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := NetIP(tt.n)
			if got.String() != tt.want {
				t.Fatalf("NetIP(0x%08X) = %s, want %s", tt.n, got, tt.want)
			}
		})
	}
}

func TestNetPort(t *testing.T) {
	// NetPort swaps bytes: network byte order → host byte order
	// port 80 (0x0050) stored as 0x5000 in network order
	tests := []struct {
		n    uint16
		want uint16
	}{
		{0x5000, 80},
		{0xBB01, 443},
		{0x901F, 8080},
		{0x0000, 0},
		{0x0100, 1},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := NetPort(tt.n)
			if got != tt.want {
				t.Fatalf("NetPort(0x%04X) = %d, want %d", tt.n, got, tt.want)
			}
		})
	}
}
