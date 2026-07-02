// Package buildinfo exposes compile-time metadata shared across the server.
package buildinfo

import (
	"os"
	"strings"
	"time"
)

const (
	defaultVersion   = "dev"
	defaultCommit    = "none"
	defaultBuildDate = "unknown"
)

// The following variables are overridden via ldflags during release builds.
// Defaults cover local development builds.
var (
	// Version is the semantic version or git describe output of the binary.
	Version = defaultVersion

	// Commit is the git commit SHA baked into the binary.
	Commit = defaultCommit

	// BuildDate records when the binary was built in UTC.
	BuildDate = defaultBuildDate
)

// Apply sets the process-wide build metadata, filling local development build
// dates from the executable timestamp when ldflags did not provide one.
func Apply(version, commit, buildDate string) {
	Version = defaultString(version, defaultVersion)
	Commit = defaultString(commit, defaultCommit)
	BuildDate = resolveBuildDate(buildDate)
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func resolveBuildDate(buildDate string) string {
	buildDate = strings.TrimSpace(buildDate)
	if buildDate != "" && !strings.EqualFold(buildDate, defaultBuildDate) {
		return buildDate
	}

	executable, err := os.Executable()
	if err != nil {
		return defaultBuildDate
	}
	info, err := os.Stat(executable)
	if err != nil {
		return defaultBuildDate
	}
	modTime := info.ModTime()
	if modTime.IsZero() {
		return defaultBuildDate
	}
	return modTime.UTC().Format(time.RFC3339)
}
