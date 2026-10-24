package policy

import (
	"testing"
)

func TestAllowlist_Matching(t *testing.T) {
	al := NewAllowlist("amazon-ssm-agent, /opt/aws/bin/cloudwatch-agent")

	if !al.IsAllowed("amazon-ssm-agent", "/usr/bin/amazon-ssm-agent") {
		t.Error("expected amazon-ssm-agent to be allowed by name")
	}

	if !al.IsAllowed("cloudwatch-agent", "/opt/aws/bin/cloudwatch-agent") {
		t.Error("expected cloudwatch-agent to be allowed by path")
	}

	if al.IsAllowed("curl", "/usr/bin/curl") {
		t.Error("expected curl to be disallowed")
	}

	if al.IsAllowed("python3", "") {
		t.Error("expected python3 to be disallowed")
	}
}
