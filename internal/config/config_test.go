package config

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.HoneypotPort != 18080 {
		t.Fatalf("expected port 18080, got %d", cfg.HoneypotPort)
	}
	if cfg.Credentials.RoleName != "production-infra-role" {
		t.Fatalf("expected role production-infra-role, got %s", cfg.Credentials.RoleName)
	}
	if cfg.Credentials.AccessKeyID == "" {
		t.Fatal("expected non-empty AccessKeyID")
	}
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectPort  uint16
		expectRole  string
		expectDry   bool
		expectError bool
	}{
		{
			name:        "custom port and role",
			args:        []string{"-port", "19090", "-role", "custom-role", "-bind", "0.0.0.0", "-dry-run"},
			expectPort:  19090,
			expectRole:  "custom-role",
			expectDry:   true,
			expectError: false,
		},
		{
			name:        "invalid port zero",
			args:        []string{"-port", "0"},
			expectError: true,
		},
		{
			name:        "invalid port high",
			args:        []string{"-port", "70000"},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseFlags(tc.args)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.HoneypotPort != tc.expectPort {
				t.Errorf("expected port %d, got %d", tc.expectPort, cfg.HoneypotPort)
			}
			if cfg.Credentials.RoleName != tc.expectRole {
				t.Errorf("expected role %s, got %s", tc.expectRole, cfg.Credentials.RoleName)
			}
			if cfg.DryRun != tc.expectDry {
				t.Errorf("expected dry-run %v, got %v", tc.expectDry, cfg.DryRun)
			}
		})
	}
}
