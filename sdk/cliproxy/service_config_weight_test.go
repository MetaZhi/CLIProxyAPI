package cliproxy

import (
	"context"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestWeightedRoundRobinRoutingSelector(t *testing.T) {
	state := normalizedRoutingRuntimeState(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{Strategy: "wrr"},
	})
	if state.strategy != "weighted-round-robin" {
		t.Fatalf("strategy = %q, want weighted-round-robin", state.strategy)
	}
	if _, ok := newRoutingSelectorFromRuntimeState(state).(*coreauth.WeightedRoundRobinSelector); !ok {
		t.Fatalf("selector type = %T, want *auth.WeightedRoundRobinSelector", newRoutingSelectorFromRuntimeState(state))
	}
}

func TestQuotaPriorityRoutingSelectorTracksQuotaSettings(t *testing.T) {
	minimumQuotaPercent := 20.0
	state := normalizedRoutingRuntimeState(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:            "quota-priority",
			QuotaPriorityWindow: "168h",
			MinimumQuotaPercent: &minimumQuotaPercent,
		},
	})
	if state.strategy != "quota-priority" {
		t.Fatalf("strategy = %q, want quota-priority", state.strategy)
	}
	if state.quotaPriorityWindow != 168*time.Hour {
		t.Fatalf("quotaPriorityWindow = %v, want %v", state.quotaPriorityWindow, 168*time.Hour)
	}
	if state.minimumQuotaPercent != minimumQuotaPercent {
		t.Fatalf("minimumQuotaPercent = %v, want %v", state.minimumQuotaPercent, minimumQuotaPercent)
	}

	quotaSelector, ok := newRoutingSelectorFromRuntimeState(state).(*coreauth.QuotaPrioritySelector)
	if !ok {
		t.Fatalf("selector type = %T, want *auth.QuotaPrioritySelector", newRoutingSelectorFromRuntimeState(state))
	}
	if quotaSelector.Window != state.quotaPriorityWindow {
		t.Fatalf("selector window = %v, want %v", quotaSelector.Window, state.quotaPriorityWindow)
	}
	if quotaSelector.MinimumQuotaPercent != state.minimumQuotaPercent {
		t.Fatalf("selector minimum quota percent = %v, want %v", quotaSelector.MinimumQuotaPercent, state.minimumQuotaPercent)
	}

	updatedMinimumQuotaPercent := 30.0
	updatedState := normalizedRoutingRuntimeState(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:            "quota-priority",
			QuotaPriorityWindow: "168h",
			MinimumQuotaPercent: &updatedMinimumQuotaPercent,
		},
	})
	if updatedState == state {
		t.Fatal("routing state did not change after updating minimum quota percent")
	}
}

func TestServiceAppliesUpdatedQuotaPriorityRoutingSettings(t *testing.T) {
	manager := coreauth.NewManager(nil, &coreauth.RoundRobinSelector{}, nil)
	service := &Service{coreManager: manager}

	minimumQuotaPercent := 20.0
	commit := service.commitConfigUpdate(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:            "quota-priority",
			QuotaPriorityWindow: "168h",
			MinimumQuotaPercent: &minimumQuotaPercent,
		},
	})
	if !service.applyManagerConfig(context.Background(), commit) {
		t.Fatal("apply initial quota-priority routing config failed")
	}

	quotaSelector, ok := manager.Selector().(*coreauth.QuotaPrioritySelector)
	if !ok {
		t.Fatalf("selector type = %T, want *auth.QuotaPrioritySelector", manager.Selector())
	}
	if quotaSelector.MinimumQuotaPercent != minimumQuotaPercent {
		t.Fatalf("initial selector minimum quota percent = %v, want %v", quotaSelector.MinimumQuotaPercent, minimumQuotaPercent)
	}

	updatedMinimumQuotaPercent := 30.0
	updatedCommit := service.commitConfigUpdate(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:            "quota-priority",
			QuotaPriorityWindow: "168h",
			MinimumQuotaPercent: &updatedMinimumQuotaPercent,
		},
	})
	if !service.applyManagerConfig(context.Background(), updatedCommit) {
		t.Fatal("apply updated quota-priority routing config failed")
	}

	updatedSelector, ok := manager.Selector().(*coreauth.QuotaPrioritySelector)
	if !ok {
		t.Fatalf("updated selector type = %T, want *auth.QuotaPrioritySelector", manager.Selector())
	}
	if updatedSelector.MinimumQuotaPercent != updatedMinimumQuotaPercent {
		t.Fatalf("updated selector minimum quota percent = %v, want %v", updatedSelector.MinimumQuotaPercent, updatedMinimumQuotaPercent)
	}
}

func TestServiceRejectsInvalidCredentialWeightConfigCommit(t *testing.T) {
	originalCfg := &internalconfig.Config{}
	service := &Service{cfg: originalCfg}
	invalidWeight := internalconfig.MaxCredentialWeight + 1
	newCfg := &internalconfig.Config{
		VertexCompatAPIKey: []internalconfig.VertexCompatKey{{
			APIKey: "vertex-key",
			Weight: &invalidWeight,
		}},
	}

	if service.applyConfigUpdateWithAuthSynthesis(nil, newCfg, true) {
		t.Fatal("hot config application accepted an invalid credential weight")
	}
	if service.cfg != originalCfg {
		t.Fatal("invalid hot config replaced the active config")
	}
	if service.configSequence != 0 {
		t.Fatalf("config sequence = %d, want 0", service.configSequence)
	}
}
