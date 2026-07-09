package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebpf-edr-demo/internal/alert"
)

// TestLoadRealRules loads the repo's shipped rules files — guards against a
// default.yaml / process.yaml edit that would fail at agent startup.
func TestLoadRealRules(t *testing.T) {
	db, err := LoadRules("../../rules/default.yaml")
	if err != nil {
		t.Fatalf("LoadRules failed on shipped rules: %v", err)
	}
	if len(db.ProcessDetections) != 4 {
		t.Fatalf("expected 4 process detections, got %d", len(db.ProcessDetections))
	}
	first := db.ProcessDetections[0]
	if first.Name != "T1059_unix_shell_execution" || first.Severity != alert.Critical {
		t.Errorf("first process detection = %s/%s, want T1059_unix_shell_execution/CRITICAL", first.Name, first.Severity)
	}
	if !first.RequireContainer {
		t.Errorf("T1059 must be container-gated")
	}
}

// TestLoadRulesMissingSensorFile — sensor files are required (fail-fast),
// otherwise the detector would silently run with no process rules.
func TestLoadRulesMissingSensorFile(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "default.yaml")
	if err := os.WriteFile(base, []byte("rules:\n  lists: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRules(base)
	if err == nil || !strings.Contains(err.Error(), "process.yaml") {
		t.Fatalf("expected missing process.yaml error, got: %v", err)
	}
}

func TestValidateDetections(t *testing.T) {
	lists := map[string][]interface{}{
		"shell_processes": {"bash"},
		"apps":            {"redis-cli"},
	}
	valid := func() DetectionRule {
		return DetectionRule{
			Name:     "T_test",
			Severity: alert.High,
			Match:    MatchSpec{CommSuffixIn: "shell_processes"},
			Message:  "msg",
		}
	}

	cases := []struct {
		name    string
		dets    []DetectionRule
		wantErr string // empty = valid
	}{
		{"valid single", []DetectionRule{valid()}, ""},
		{"valid with exceptions", []DetectionRule{func() DetectionRule {
			d := valid()
			d.Exceptions = MatchSpec{CommBaseIn: "apps"}
			return d
		}()}, ""},
		{"missing name", []DetectionRule{func() DetectionRule {
			d := valid()
			d.Name = ""
			return d
		}()}, "missing name"},
		{"invalid severity", []DetectionRule{func() DetectionRule {
			d := valid()
			d.Severity = "URGENT"
			return d
		}()}, "invalid severity"},
		{"missing message", []DetectionRule{func() DetectionRule {
			d := valid()
			d.Message = ""
			return d
		}()}, "missing message"},
		{"empty match", []DetectionRule{func() DetectionRule {
			d := valid()
			d.Match = MatchSpec{}
			return d
		}()}, "at least one primitive"},
		{"unknown list ref", []DetectionRule{func() DetectionRule {
			d := valid()
			d.Match = MatchSpec{CommSuffixIn: "no_such_list"}
			return d
		}()}, "unknown list reference"},
		{"severity out of order", []DetectionRule{
			func() DetectionRule { d := valid(); d.Severity = alert.Medium; return d }(),
			func() DetectionRule { d := valid(); d.Severity = alert.Critical; return d }(),
		}, "out of order"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDetections(tc.dets, lists)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}
