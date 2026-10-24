package alerting

import (
	"fmt"
	"strings"
)

// FormatCEF formats an alert into ArcSight Common Event Format (CEF).
// Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
func FormatCEF(alert AlertPayload, severity int) string {
	vendor := "smford"
	product := "imds-canary"
	version := "1.0"
	eventClassID := alert.AlertType
	name := "AWS IMDS Access Intercepted"

	if severity <= 0 {
		severity = 8 // High severity default for credential tampering
	}

	extensions := []string{
		fmt.Sprintf("src=%s", alert.OriginalDestination),
		fmt.Sprintf("dst=%s", alert.RedirectDestination),
		fmt.Sprintf("duser=%d", alert.UID),
		fmt.Sprintf("dpid=%d", alert.PID),
		fmt.Sprintf("dproc=%s", escapeCEF(alert.Comm)),
		fmt.Sprintf("act=redirected"),
		fmt.Sprintf("cs1=%s", escapeCEF(alert.CanaryRole)),
		fmt.Sprintf("cs1Label=CanaryRole"),
		fmt.Sprintf("rt=%d", alert.Timestamp.UnixMilli()),
	}

	if alert.ProcessSnapshot != nil {
		if alert.ProcessSnapshot.Exe != "" {
			extensions = append(extensions, fmt.Sprintf("filePath=%s", escapeCEF(alert.ProcessSnapshot.Exe)))
		}
		if len(alert.ProcessSnapshot.Cmdline) > 0 {
			extensions = append(extensions, fmt.Sprintf("cs2=%s", escapeCEF(strings.Join(alert.ProcessSnapshot.Cmdline, " "))))
			extensions = append(extensions, "cs2Label=CommandLine")
		}
	}

	return fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s",
		vendor, product, version, eventClassID, name, severity, strings.Join(extensions, " "))
}

func escapeCEF(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "=", "\\=")
	return s
}
