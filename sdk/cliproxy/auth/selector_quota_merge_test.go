package auth

import (
	"context"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestQuotaPriorityPrevalidatedCandidatesPreserveAliasAvailability(t *testing.T) {
	now := time.Now()
	selector := NewQuotaPrioritySelector(5 * time.Hour)
	manager := NewManager(nil, selector, nil)
	auths := []*Auth{
		{ID: "high-exhausted", Provider: "codex", Attributes: map[string]string{"priority": "10"}, RuntimeMetadata: quotaWindowMetadata(now, map[string]quotaWindowTestSpec{
			"5h": {remainingPercent: 0, resetIn: time.Hour},
		})},
		{ID: "low-ready", Provider: "codex", RuntimeMetadata: quotaWindowMetadata(now, map[string]quotaWindowTestSpec{
			"5h": {remainingPercent: 80, resetIn: time.Hour},
		}), ModelStates: map[string]*ModelState{
			"unrelated": {Unavailable: true, NextRetryAfter: now.Add(time.Hour)},
		}},
	}
	_, candidates, err := manager.availableAuthsForSelector(selector, auths, "codex", "route", now)
	if err != nil {
		t.Fatal(err)
	}
	// Built-in selectors receive an empty model after the manager resolves the route.
	ctx := selectorContextForAvailableAuths(context.Background(), selector, "route")
	picked, err := selector.Pick(ctx, "codex", "", cliproxyexecutor.Options{}, candidates)
	if err != nil {
		t.Fatal(err)
	}
	if picked == nil || picked.ID != "low-ready" {
		t.Fatalf("Pick() = %v, want low-ready despite the unrelated model cooldown", picked)
	}
}

func TestSessionAffinityLCPReleasesAuthBelowQuotaReserve(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{QuotaReservePercent: 20},
		TTL:      time.Minute,
	})
	defer selector.Stop()
	auths := []*Auth{
		{ID: "a-sticky", Metadata: map[string]any{"remaining_percent": 50}},
		{ID: "b-ready", Metadata: map[string]any{"remaining_percent": 80}},
	}
	pick := func() *Auth {
		t.Helper()
		opts := cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FormatOpenAI,
			OriginalRequest: []byte(`{"messages":[{"role":"user","content":"shared conversation"}]}`),
			Metadata:        map[string]any{cliproxyexecutor.CallerScopeMetadataKey: "quota-caller"},
		}
		auth, err := selector.Pick(context.Background(), "codex", "model", opts, auths)
		if err != nil {
			t.Fatal(err)
		}
		if auth == nil {
			t.Fatal("Pick() returned no auth")
		}
		if opts.Metadata[cliproxyexecutor.LCPAffinitySessionIDMetadataKey] == nil {
			t.Fatal("Pick() did not bind an LCP session")
		}
		return auth
	}
	if first := pick(); first.ID != "a-sticky" {
		t.Fatalf("first Pick() = %q, want a-sticky", first.ID)
	}
	auths[0].Metadata["remaining_percent"] = 10
	if next := pick(); next.ID != "b-ready" {
		t.Fatalf("Pick() after quota drop = %q, want b-ready", next.ID)
	}
}
