package policy

import (
	"path/filepath"
	"strings"
)

// Allowlist checks whether a process is permitted to access IMDS without triggering alarms.
type Allowlist struct {
	names map[string]bool
	paths map[string]bool
}

// NewAllowlist parses a comma-separated list of process names or binary paths.
func NewAllowlist(rules string) *Allowlist {
	al := &Allowlist{
		names: make(map[string]bool),
		paths: make(map[string]bool),
	}

	for _, item := range strings.Split(rules, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "/") {
			al.paths[filepath.Clean(trimmed)] = true
		} else {
			al.names[trimmed] = true
		}
	}

	return al
}

// IsAllowed returns true if the process comm or exe path matches any allowlist entry.
func (al *Allowlist) IsAllowed(comm, exe string) bool {
	if al == nil {
		return false
	}
	if comm != "" && al.names[comm] {
		return true
	}
	if exe != "" {
		base := filepath.Base(exe)
		if al.names[base] {
			return true
		}
		if al.paths[filepath.Clean(exe)] {
			return true
		}
	}
	return false
}

// Size returns the count of allowlist rules.
func (al *Allowlist) Size() int {
	if al == nil {
		return 0
	}
	return len(al.names) + len(al.paths)
}
