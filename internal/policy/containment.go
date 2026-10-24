package policy

import (
	"fmt"
	"os"
	"syscall"
)

// MitigationAction specifies the containment action taken against a rogue process.
type MitigationAction string

const (
	ActionNone  MitigationAction = "none"
	ActionAlert MitigationAction = "alert"
	ActionPause MitigationAction = "pause"
	ActionKill  MitigationAction = "kill"
)

// ExecuteMitigation applies the configured mitigation action to the offending process.
func ExecuteMitigation(action MitigationAction, pid uint32) (string, error) {
	if pid <= 1 || int(pid) == os.Getpid() {
		return "skipped (protected pid)", nil
	}

	switch action {
	case ActionPause:
		if err := syscall.Kill(int(pid), syscall.SIGSTOP); err != nil {
			return "failed", fmt.Errorf("failed to send SIGSTOP to pid %d: %w", pid, err)
		}
		return "SIGSTOP (process frozen)", nil

	case ActionKill:
		if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil {
			return "failed", fmt.Errorf("failed to send SIGKILL to pid %d: %w", pid, err)
		}
		return "SIGKILL (process terminated)", nil

	case ActionNone, ActionAlert, "":
		return "none", nil

	default:
		return "unknown", fmt.Errorf("unrecognized mitigation action: %s", action)
	}
}
