package alerting

import (
	"strings"
	"testing"
	"time"

	"github.com/smford/imds-canary/internal/proc"
)

func TestFormatCEF(t *testing.T) {
	alert := AlertPayload{
		Timestamp:           time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC),
		AlertType:           "IMDS_PROBE_DETECTED",
		PID:                 1234,
		UID:                 1000,
		Comm:                "curl",
		OriginalDestination: "169.254.169.254:80",
		RedirectDestination: "127.0.0.1:18080",
		CanaryRole:          "production-infra-role",
		ProcessSnapshot: &proc.ProcessSnapshot{
			Exe:     "/usr/bin/curl",
			Cmdline: []string{"curl", "http://169.254.169.254"},
		},
	}

	cef := FormatCEF(alert, 9)

	if !strings.HasPrefix(cef, "CEF:0|smford|imds-canary|1.0|IMDS_PROBE_DETECTED|AWS IMDS Access Intercepted|9|") {
		t.Errorf("invalid CEF header: %s", cef)
	}

	if !strings.Contains(cef, "dpid=1234") {
		t.Errorf("CEF missing dpid: %s", cef)
	}
	if !strings.Contains(cef, "filePath=/usr/bin/curl") {
		t.Errorf("CEF missing filePath: %s", cef)
	}
	if !strings.Contains(cef, "cs1=production-infra-role") {
		t.Errorf("CEF missing cs1 canary role: %s", cef)
	}
}
