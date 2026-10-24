package policy

import (
	"os"
	"os/exec"
	"testing"
)

func TestContainment_KillAndPause(t *testing.T) {
	// Start dummy sleep process
	cmd := exec.Command("sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Skip("unable to start sleep process:", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
	}()

	pid := uint32(cmd.Process.Pid)

	// Test ActionKill
	res, err := ExecuteMitigation(ActionKill, pid)
	if err != nil {
		t.Fatalf("ExecuteMitigation(kill) failed: %v", err)
	}
	if res != "SIGKILL (process terminated)" {
		t.Errorf("unexpected result: %s", res)
	}

	// Verify protected pid check (self)
	selfPid := uint32(os.Getpid())
	resSelf, errSelf := ExecuteMitigation(ActionKill, selfPid)
	if errSelf != nil || resSelf != "skipped (protected pid)" {
		t.Errorf("expected protected pid skip, got (%s, %v)", resSelf, errSelf)
	}
}
