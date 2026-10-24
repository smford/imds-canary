package version

import (
	"fmt"
)

var (
	// Version is the current semver release.
	Version = "0.1.0"
	// Commit is the git commit SHA injected at build time via -ldflags.
	Commit = "none"
	// Date is the build timestamp injected at build time via -ldflags.
	Date = "unknown"
	// Copyright holder.
	Copyright = "Copyright (c) 2026 smford"
	// License identifier.
	License = "Licensed under the MIT License"
)

// String returns the formatted version banner string.
func String() string {
	return fmt.Sprintf("imds-canary %s (commit: %s, date: %s)\n%s\n%s",
		Version, Commit, Date, Copyright, License)
}

// Print prints the version banner to standard output.
func Print() {
	fmt.Println(String())
}
