package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type codexQuotaWarmupTestExecutor struct{}

func (codexQuotaWarmupTestExecutor) Identifier() string { return "codex" }

func (codexQuotaWarmupTestExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (codexQuotaWarmupTestExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (codexQuotaWarmupTestExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (codexQuotaWarmupTestExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (codexQuotaWarmupTestExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestUpdateAggregatedAvailability_UnavailableWithoutNextRetryDoesNotBlockAuth(t *testing.T) {
	t.Parallel()

	now := time.Now()
	model := "test-model"
	auth := &Auth{
		ID: "a",
		ModelStates: map[string]*ModelState{
			model: {
				Status:      StatusError,
				Unavailable: true,
			},
		},
	}

	updateAggregatedAvailability(auth, now)

	if auth.Unavailable {
		t.Fatalf("auth.Unavailable = true, want false")
	}
	if !auth.NextRetryAfter.IsZero() {
		t.Fatalf("auth.NextRetryAfter = %v, want zero", auth.NextRetryAfter)
	}
}

func TestUpdateAggregatedAvailability_FutureNextRetryBlocksAuth(t *testing.T) {
	t.Parallel()

	now := time.Now()
	model := "test-model"
	next := now.Add(5 * time.Minute)
	auth := &Auth{
		ID: "a",
		ModelStates: map[string]*ModelState{
			model: {
				Status:         StatusError,
				Unavailable:    true,
				NextRetryAfter: next,
			},
		},
	}

	updateAggregatedAvailability(auth, now)

	if !auth.Unavailable {
		t.Fatalf("auth.Unavailable = false, want true")
	}
	if auth.NextRetryAfter.IsZero() {
		t.Fatalf("auth.NextRetryAfter = zero, want %v", next)
	}
	if auth.NextRetryAfter.Sub(next) > time.Second || next.Sub(auth.NextRetryAfter) > time.Second {
		t.Fatalf("auth.NextRetryAfter = %v, want %v", auth.NextRetryAfter, next)
	}
}

func TestManager_AvailableProvidersAndHasProviderAuth_ExcludeDisabled(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	ctx := context.Background()

	if _, err := manager.Register(ctx, &Auth{ID: "active", Provider: "claude", Status: StatusActive}); err != nil {
		t.Fatalf("register active auth: %v", err)
	}
	// Provider gemini only has an auth with the Disabled flag set.
	if _, err := manager.Register(ctx, &Auth{ID: "flag-disabled", Provider: "gemini", Disabled: true}); err != nil {
		t.Fatalf("register flag-disabled auth: %v", err)
	}
	// Provider codex only has an auth whose Status is StatusDisabled.
	if _, err := manager.Register(ctx, &Auth{ID: "status-disabled", Provider: "codex", Status: StatusDisabled}); err != nil {
		t.Fatalf("register status-disabled auth: %v", err)
	}

	providers := manager.AvailableProviders()
	present := make(map[string]bool, len(providers))
	for _, p := range providers {
		present[p] = true
	}
	if !present["claude"] {
		t.Errorf("AvailableProviders() = %v, want to include active provider claude", providers)
	}
	if present["gemini"] {
		t.Errorf("AvailableProviders() = %v, want to exclude Disabled provider gemini", providers)
	}
	if present["codex"] {
		t.Errorf("AvailableProviders() = %v, want to exclude StatusDisabled provider codex", providers)
	}

	if !manager.HasProviderAuth("claude") {
		t.Errorf("HasProviderAuth(claude) = false, want true")
	}
	if manager.HasProviderAuth("gemini") {
		t.Errorf("HasProviderAuth(gemini) = true, want false (only Disabled auth registered)")
	}
	if manager.HasProviderAuth("codex") {
		t.Errorf("HasProviderAuth(codex) = true, want false (only StatusDisabled auth registered)")
	}
}

func TestManager_ResetQuotaClearsRuntimeAndRegistryState(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	ctx := context.Background()
	authID := "reset-quota-auth"
	model := "reset-quota-model"
	next := time.Now().Add(time.Hour)

	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(authID, "claude", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() {
		reg.UnregisterClient(authID)
	})

	if _, errRegister := manager.Register(ctx, &Auth{
		ID:             authID,
		Provider:       "claude",
		Status:         StatusError,
		StatusMessage:  "quota exhausted",
		Unavailable:    true,
		NextRetryAfter: next,
		Quota:          QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: next, BackoffLevel: 2},
		ModelStates: map[string]*ModelState{
			model: {
				Status:         StatusError,
				StatusMessage:  "quota exhausted",
				Unavailable:    true,
				NextRetryAfter: next,
				Quota:          QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: next, BackoffLevel: 2},
				UpdatedAt:      next,
			},
		},
	}); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	reg.SetModelQuotaExceeded(authID, model)
	reg.SuspendClientModel(authID, model, "quota")
	if count := reg.GetModelCount(model); count != 0 {
		t.Fatalf("registry model count before reset = %d, want 0", count)
	}

	updated, models, errReset := manager.ResetQuota(ctx, authID)
	if errReset != nil {
		t.Fatalf("ResetQuota() error = %v", errReset)
	}
	if updated == nil {
		t.Fatalf("ResetQuota() updated auth is nil")
	}
	if len(models) != 1 || models[0] != model {
		t.Fatalf("ResetQuota() models = %v, want [%s]", models, model)
	}
	if updated.Status != StatusActive || updated.StatusMessage != "" || updated.Unavailable || !updated.NextRetryAfter.IsZero() {
		t.Fatalf("updated auth state = status %q message %q unavailable %v next %v", updated.Status, updated.StatusMessage, updated.Unavailable, updated.NextRetryAfter)
	}
	if updated.Quota.Exceeded || updated.Quota.Reason != "" || !updated.Quota.NextRecoverAt.IsZero() || updated.Quota.BackoffLevel != 0 {
		t.Fatalf("updated auth quota = %+v, want cleared", updated.Quota)
	}
	state := updated.ModelStates[model]
	if state == nil {
		t.Fatalf("updated model state missing")
	}
	if state.Status != StatusActive || state.StatusMessage != "" || state.Unavailable || !state.NextRetryAfter.IsZero() {
		t.Fatalf("updated model state = status %q message %q unavailable %v next %v", state.Status, state.StatusMessage, state.Unavailable, state.NextRetryAfter)
	}
	if state.Quota.Exceeded || state.Quota.Reason != "" || !state.Quota.NextRecoverAt.IsZero() || state.Quota.BackoffLevel != 0 {
		t.Fatalf("updated model quota = %+v, want cleared", state.Quota)
	}
	if count := reg.GetModelCount(model); count != 1 {
		t.Fatalf("registry model count after reset = %d, want 1", count)
	}
}

func TestManager_ResetQuotaClearsRuntimeQuotaProbeState(t *testing.T) {
	manager := NewManager(nil, NewQuotaPrioritySelector(5*time.Hour), nil)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	if _, errRegister := manager.Register(ctx, &Auth{
		ID:       "codex-runtime-quota",
		Provider: "codex",
		Status:   StatusActive,
		RuntimeMetadata: map[string]any{
			quotaWindowsMetadataKey: map[string]any{
				"5h": map[string]any{
					"remaining_percent": 50,
					"reset_at":          now.Add(time.Hour).Format(time.RFC3339Nano),
				},
			},
			quotaProbeAfterMetadataKey: now.Add(time.Hour).Format(time.RFC3339Nano),
		},
	}); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	updated, _, errReset := manager.ResetQuota(ctx, "codex-runtime-quota")
	if errReset != nil {
		t.Fatalf("ResetQuota() error = %v", errReset)
	}
	if updated == nil {
		t.Fatalf("ResetQuota() updated auth is nil")
	}
	if _, ok := updated.RuntimeMetadata[quotaWindowsMetadataKey]; ok {
		t.Fatalf("runtime quota windows still present after reset")
	}
	if _, ok := updated.RuntimeMetadata[quotaProbeAfterMetadataKey]; ok {
		t.Fatalf("quota probe guard still present after reset")
	}
}

func TestManager_LegacyQuotaWarmupSyncsProbeGuard(t *testing.T) {
	manager := NewManager(nil, NewQuotaPrioritySelector(5*time.Hour), nil)
	manager.RegisterExecutor(codexQuotaWarmupTestExecutor{})
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	if _, errRegister := manager.Register(ctx, &Auth{
		ID:       "known-quota",
		Provider: "codex",
		Status:   StatusActive,
		RuntimeMetadata: quotaWindowMetadata(now, map[string]quotaWindowTestSpec{
			"5h": {remainingPercent: 60, resetIn: time.Hour},
		}),
	}); errRegister != nil {
		t.Fatalf("register known auth: %v", errRegister)
	}
	if _, errRegister := manager.Register(ctx, &Auth{
		ID:       "unknown-quota",
		Provider: "codex",
		Status:   StatusActive,
	}); errRegister != nil {
		t.Fatalf("register unknown auth: %v", errRegister)
	}

	first, _, _, errPick := manager.pickNextMixedLegacy(ctx, []string{"codex"}, "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatalf("first pickNextMixedLegacy() error = %v", errPick)
	}
	if first == nil || first.ID != "unknown-quota" {
		t.Fatalf("first pick auth = %v, want unknown-quota", first)
	}

	stored, ok := manager.GetByID("unknown-quota")
	if !ok {
		t.Fatalf("unknown auth missing after first pick")
	}
	if probeAfter, okProbe := quotaProbeAfter(stored); !okProbe || !probeAfter.After(time.Now()) {
		t.Fatalf("stored quota probe guard = %v ok=%v, want future guard", probeAfter, okProbe)
	}

	second, _, _, errPick := manager.pickNextMixedLegacy(ctx, []string{"codex"}, "", cliproxyexecutor.Options{}, nil)
	if errPick != nil {
		t.Fatalf("second pickNextMixedLegacy() error = %v", errPick)
	}
	if second == nil || second.ID != "known-quota" {
		t.Fatalf("second pick auth = %v, want known-quota", second)
	}

	scheduled, handled, errScheduled := manager.pickViaBuiltinScheduler(ctx, schedulerStrategyQuota, "mixed", []string{"codex"}, "", cliproxyexecutor.Options{}, nil)
	if errScheduled != nil {
		t.Fatalf("pickViaBuiltinScheduler() error = %v", errScheduled)
	}
	if !handled {
		t.Fatalf("pickViaBuiltinScheduler() handled = false, want true")
	}
	if scheduled == nil || scheduled.ID != "known-quota" {
		t.Fatalf("scheduled pick auth = %v, want known-quota", scheduled)
	}
}
