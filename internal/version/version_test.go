package version

import (
	"strings"
	"testing"
)

func TestVersionString(t *testing.T) {
	s := String()
	if !strings.Contains(s, "imds-canary 0.1.0") {
		t.Errorf("version string missing 'imds-canary 0.1.0': %s", s)
	}
	if !strings.Contains(s, "Copyright (c) 2026 smford") {
		t.Errorf("version string missing copyright: %s", s)
	}
	if !strings.Contains(s, "Licensed under the MIT License") {
		t.Errorf("version string missing license: %s", s)
	}
}
