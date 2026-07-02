package auth

import (
	"context"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestParseCodexQuotaWindows(t *testing.T) {
	t.Parallel()

	now := time.Unix(1782888542, 0).UTC()
	headers := http.Header{}
	headers.Set("X-Codex-Primary-Used-Percent", "87")
	headers.Set("X-Codex-Primary-Reset-At", "1782904295")
	headers.Set("X-Codex-Primary-Window-Minutes", "300")
	headers.Set("X-Codex-Secondary-Used-Percent", "76")
	headers.Set("X-Codex-Secondary-Reset-At", "1783388617")
	headers.Set("X-Codex-Secondary-Window-Minutes", "10080")

	windows := parseCodexQuotaWindows(headers, now)
	if len(windows) != 2 {
		t.Fatalf("parseCodexQuotaWindows() len = %d, want 2", len(windows))
	}
	if got := windows[0]; got.Name != "5h" || got.RemainingPercent != 13 || got.UsedPercent != 87 || got.WindowMinutes != 300 {
		t.Fatalf("primary window = %+v, want 5h remaining=13 used=87 window=300", got)
	}
	if got := windows[1]; got.Name != "week" || got.RemainingPercent != 24 || got.UsedPercent != 76 || got.WindowMinutes != 10080 {
		t.Fatalf("secondary window = %+v, want week remaining=24 used=76 window=10080", got)
	}
}

func TestParseCodexQuotaWindowUsesResetAfterFallback(t *testing.T) {
	t.Parallel()

	now := time.Unix(1782888542, 0).UTC()
	headers := http.Header{}
	headers.Set("X-Codex-Primary-Used-Percent", "25")
	headers.Set("X-Codex-Primary-Reset-After-Seconds", "120")
	headers.Set("X-Codex-Primary-Window-Minutes", "300")

	window, ok := parseCodexQuotaWindow(headers, now, "Primary", "5h")
	if !ok {
		t.Fatalf("parseCodexQuotaWindow() ok = false, want true")
	}
	if !window.ResetAt.Equal(now.Add(120 * time.Second)) {
		t.Fatalf("reset_at = %s, want %s", window.ResetAt, now.Add(120*time.Second))
	}
	if window.RemainingPercent != 75 {
		t.Fatalf("remaining_percent = %v, want 75", window.RemainingPercent)
	}
}

func TestUpdateCodexQuotaFromHeadersIgnoresInvalidQuotaHeaders(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	auth := &Auth{Provider: "codex", RuntimeMetadata: quotaWindowMetadata(now, map[string]quotaWindowTestSpec{
		"5h": {remainingPercent: 44, resetIn: time.Hour},
	})}
	before := auth.RuntimeMetadata[quotaWindowsMetadataKey]
	headers := http.Header{}
	headers.Set("X-Codex-Primary-Used-Percent", "not-a-number")
	headers.Set("X-Codex-Primary-Reset-At", now.Add(time.Hour).Format(time.RFC3339))
	headers.Set("X-Codex-Primary-Window-Minutes", "300")

	_, changed := updateCodexQuotaFromHeaders(auth, headers, now)
	if changed {
		t.Fatalf("updateCodexQuotaFromHeaders() changed = true, want false")
	}
	if !reflect.DeepEqual(auth.RuntimeMetadata[quotaWindowsMetadataKey], before) {
		t.Fatalf("quota_windows was replaced for invalid headers")
	}
}

func TestMarkResultUpdatesCodexQuotaRuntimeMetadataAndScheduler(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	manager := NewManager(nil, NewQuotaPrioritySelector(5*time.Hour), nil)
	manager.executors["codex"] = schedulerTestExecutor{}
	if _, errRegister := manager.Register(context.Background(), &Auth{
		ID:       "learned",
		Provider: "codex",
		Metadata: map[string]any{
			"type": "codex",
		},
	}); errRegister != nil {
		t.Fatalf("Register(learned) error = %v", errRegister)
	}
	if _, errRegister := manager.Register(context.Background(), &Auth{
		ID:       "known-later",
		Provider: "codex",
		RuntimeMetadata: quotaWindowMetadata(now, map[string]quotaWindowTestSpec{
			"5h": {remainingPercent: 90, resetIn: 4 * time.Hour},
		}),
	}); errRegister != nil {
		t.Fatalf("Register(known-later) error = %v", errRegister)
	}

	headers := http.Header{}
	headers.Set("X-Codex-Plan-Type", "pro")
	headers.Set("X-Codex-Primary-Used-Percent", "10")
	headers.Set("X-Codex-Primary-Reset-At", strconvFormatUnix(now.Add(30*time.Minute)))
	headers.Set("X-Codex-Primary-Window-Minutes", "300")
	headers.Set("X-Codex-Secondary-Used-Percent", "50")
	headers.Set("X-Codex-Secondary-Reset-At", strconvFormatUnix(now.Add(7*24*time.Hour)))
	headers.Set("X-Codex-Secondary-Window-Minutes", "10080")

	manager.MarkResult(context.Background(), Result{
		AuthID:   "learned",
		Provider: "codex",
		Model:    "gpt-5.5",
		Success:  true,
		Headers:  headers,
	})

	updated, ok := manager.GetByID("learned")
	if !ok {
		t.Fatalf("GetByID(learned) ok = false, want true")
	}
	if got := updated.Attributes["plan_type"]; got != "" {
		t.Fatalf("attributes.plan_type = %q, want empty", got)
	}
	if got, _ := updated.Metadata["plan_type"].(string); got != "" {
		t.Fatalf("metadata.plan_type = %q, want empty", got)
	}
	if got, _ := updated.RuntimeMetadata["plan_type"].(string); got != "pro" {
		t.Fatalf("runtime_metadata.plan_type = %q, want pro", got)
	}
	if percent, okPercent := remainingQuotaPercentAt(updated, now); !okPercent || percent != 90 {
		t.Fatalf("remainingQuotaPercentAt() = %v, %v; want 90, true", percent, okPercent)
	}

	picked, _, errPick := manager.pickNext(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatalf("pickNext() error = %v", errPick)
	}
	if picked == nil || picked.ID != "learned" {
		t.Fatalf("pickNext() auth = %+v, want learned", picked)
	}
}

func TestMarkResultCodexQuotaSuccessDoesNotPersist(t *testing.T) {
	t.Parallel()

	store := &countingStore{}
	manager := NewManager(store, NewQuotaPrioritySelector(5*time.Hour), nil)
	manager.executors["codex"] = schedulerTestExecutor{}
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), &Auth{
		ID:       "learned",
		Provider: "codex",
		Metadata: map[string]any{
			"type": "codex",
		},
	}); errRegister != nil {
		t.Fatalf("Register(learned) error = %v", errRegister)
	}

	now := time.Now().UTC().Truncate(time.Second)
	headers := http.Header{}
	headers.Set("X-Codex-Plan-Type", "pro")
	headers.Set("X-Codex-Primary-Used-Percent", "10")
	headers.Set("X-Codex-Primary-Reset-At", strconvFormatUnix(now.Add(30*time.Minute)))
	headers.Set("X-Codex-Primary-Window-Minutes", "300")

	manager.MarkResult(context.Background(), Result{
		AuthID:   "learned",
		Provider: "codex",
		Model:    "gpt-5.5",
		Success:  true,
		Headers:  headers,
	})

	if got := store.saveCount.Load(); got != 0 {
		t.Fatalf("Save() calls = %d, want 0", got)
	}
}

func TestUpdateCodexQuotaFromHeadersClearsProbeGuard(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	auth := &Auth{
		ID:       "learned",
		Provider: "codex",
		RuntimeMetadata: map[string]any{
			quotaProbeAfterMetadataKey: now.Add(time.Hour).Format(time.RFC3339Nano),
		},
	}
	headers := http.Header{}
	headers.Set("X-Codex-Primary-Used-Percent", "10")
	headers.Set("X-Codex-Primary-Reset-At", strconvFormatUnix(now.Add(30*time.Minute)))
	headers.Set("X-Codex-Primary-Window-Minutes", "300")

	if _, changed := updateCodexQuotaFromHeaders(auth, headers, now); !changed {
		t.Fatalf("updateCodexQuotaFromHeaders() changed = false, want true")
	}
	if _, ok := auth.RuntimeMetadata[quotaProbeAfterMetadataKey]; ok {
		t.Fatalf("quota probe guard still present after quota header update")
	}
	if _, ok := bestQuotaWindowScore(auth, now, 5*time.Hour); !ok {
		t.Fatalf("bestQuotaWindowScore() ok = false, want true")
	}
}

func TestMarkResultCodexSuccessWithoutQuotaHeadersSetsProbeGuard(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, NewQuotaPrioritySelector(5*time.Hour), nil)
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), &Auth{
		ID:       "unknown",
		Provider: "codex",
		Status:   StatusActive,
	}); errRegister != nil {
		t.Fatalf("Register() error = %v", errRegister)
	}

	manager.MarkResult(context.Background(), Result{
		AuthID:   "unknown",
		Provider: "codex",
		Model:    "gpt-5.5",
		Success:  true,
	})

	updated, ok := manager.GetByID("unknown")
	if !ok || updated == nil {
		t.Fatalf("GetByID() ok=%v auth=%v, want auth", ok, updated)
	}
	if probeAfter, okProbe := quotaProbeAfter(updated); !okProbe || !probeAfter.After(time.Now()) {
		t.Fatalf("quota probe_after = %v ok=%v, want future", probeAfter, okProbe)
	}
}

func TestQuotaCapacityMultiplierUsesMetadataPlanType(t *testing.T) {
	t.Parallel()

	auth := &Auth{Provider: "codex", Metadata: map[string]any{"plan_type": "pro_lite"}}
	if got := quotaCapacityMultiplier(auth); got != 5 {
		t.Fatalf("quotaCapacityMultiplier() = %v, want 5", got)
	}
}

func strconvFormatUnix(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}
