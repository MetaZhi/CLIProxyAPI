package buildinfo

import (
	"testing"
	"time"
)

func TestApplyPreservesInjectedBuildDate(t *testing.T) {
	const injectedBuildDate = "2026-06-30T00:00:00Z"

	Apply("v1.2.3", "abc123", injectedBuildDate)

	if Version != "v1.2.3" {
		t.Fatalf("Version = %q, want v1.2.3", Version)
	}
	if Commit != "abc123" {
		t.Fatalf("Commit = %q, want abc123", Commit)
	}
	if BuildDate != injectedBuildDate {
		t.Fatalf("BuildDate = %q, want %q", BuildDate, injectedBuildDate)
	}
}

func TestApplyFallsBackToExecutableTimestampForUnknownBuildDate(t *testing.T) {
	Apply("", "", "unknown")

	if Version != defaultVersion {
		t.Fatalf("Version = %q, want %q", Version, defaultVersion)
	}
	if Commit != defaultCommit {
		t.Fatalf("Commit = %q, want %q", Commit, defaultCommit)
	}
	if BuildDate == defaultBuildDate {
		t.Fatalf("BuildDate = %q, want executable timestamp fallback", BuildDate)
	}
	if _, err := time.Parse(time.RFC3339, BuildDate); err != nil {
		t.Fatalf("BuildDate = %q, want RFC3339 timestamp: %v", BuildDate, err)
	}
}
