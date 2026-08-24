package cliproxy

import (
	"context"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
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
	quotaReservePercent := 20.0
	state := normalizedRoutingRuntimeState(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:            "quota-priority",
			QuotaPriorityWindow: "168h",
			QuotaReservePercent: &quotaReservePercent,
		},
	})
	if state.strategy != "quota-priority" {
		t.Fatalf("strategy = %q, want quota-priority", state.strategy)
	}
	if state.quotaPriorityWindow != 168*time.Hour {
		t.Fatalf("quotaPriorityWindow = %v, want %v", state.quotaPriorityWindow, 168*time.Hour)
	}
	if state.quotaReservePercent != quotaReservePercent {
		t.Fatalf("quotaReservePercent = %v, want %v", state.quotaReservePercent, quotaReservePercent)
	}

	quotaSelector, ok := newRoutingSelectorFromRuntimeState(state).(*coreauth.QuotaPrioritySelector)
	if !ok {
		t.Fatalf("selector type = %T, want *auth.QuotaPrioritySelector", newRoutingSelectorFromRuntimeState(state))
	}
	if quotaSelector.Window != state.quotaPriorityWindow {
		t.Fatalf("selector window = %v, want %v", quotaSelector.Window, state.quotaPriorityWindow)
	}
	if quotaSelector.QuotaReservePercent != state.quotaReservePercent {
		t.Fatalf("selector quota reserve percent = %v, want %v", quotaSelector.QuotaReservePercent, state.quotaReservePercent)
	}

	updatedQuotaReservePercent := 30.0
	updatedState := normalizedRoutingRuntimeState(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:            "quota-priority",
			QuotaPriorityWindow: "168h",
			QuotaReservePercent: &updatedQuotaReservePercent,
		},
	})
	if updatedState == state {
		t.Fatal("routing state did not change after updating quota reserve percent")
	}
}

func TestServiceAppliesUpdatedQuotaPriorityRoutingSettings(t *testing.T) {
	manager := coreauth.NewManager(nil, &coreauth.RoundRobinSelector{}, nil)
	service := &Service{coreManager: manager}

	quotaReservePercent := 20.0
	commit := service.commitConfigUpdate(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:            "quota-priority",
			QuotaPriorityWindow: "168h",
			QuotaReservePercent: &quotaReservePercent,
		},
	})
	if !service.applyManagerConfig(context.Background(), commit) {
		t.Fatal("apply initial quota-priority routing config failed")
	}

	quotaSelector, ok := manager.Selector().(*coreauth.QuotaPrioritySelector)
	if !ok {
		t.Fatalf("selector type = %T, want *auth.QuotaPrioritySelector", manager.Selector())
	}
	if quotaSelector.QuotaReservePercent != quotaReservePercent {
		t.Fatalf("initial selector quota reserve percent = %v, want %v", quotaSelector.QuotaReservePercent, quotaReservePercent)
	}

	updatedQuotaReservePercent := 30.0
	updatedCommit := service.commitConfigUpdate(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:            "quota-priority",
			QuotaPriorityWindow: "168h",
			QuotaReservePercent: &updatedQuotaReservePercent,
		},
	})
	if !service.applyManagerConfig(context.Background(), updatedCommit) {
		t.Fatal("apply updated quota-priority routing config failed")
	}

	updatedSelector, ok := manager.Selector().(*coreauth.QuotaPrioritySelector)
	if !ok {
		t.Fatalf("updated selector type = %T, want *auth.QuotaPrioritySelector", manager.Selector())
	}
	if updatedSelector.QuotaReservePercent != updatedQuotaReservePercent {
		t.Fatalf("updated selector quota reserve percent = %v, want %v", updatedSelector.QuotaReservePercent, updatedQuotaReservePercent)
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

type trackingStoppableSelector struct {
	stopped bool
}

func (s *trackingStoppableSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*coreauth.Auth) (*coreauth.Auth, error) {
	return nil, nil
}

func (s *trackingStoppableSelector) Stop() {
	s.stopped = true
}

func TestApplyManagerConfigStopsReplacedServiceAffinitySelector(t *testing.T) {
	tracking := &trackingStoppableSelector{}
	service := &Service{
		coreManager: coreauth.NewManager(nil, tracking, nil),
	}

	newCfg := &internalconfig.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy: "round-robin",
		},
	}
	commit := configCommit{cfg: newCfg, sequence: 1}
	if !service.applyManagerConfig(context.Background(), commit) {
		t.Fatal("applyManagerConfig failed")
	}

	if !tracking.stopped {
		t.Fatal("expected replaced selector to be stopped during routing config apply")
	}
}
