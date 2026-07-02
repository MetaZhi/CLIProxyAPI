package auth

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type countingStore struct {
	saveCount atomic.Int32
}

func (s *countingStore) List(context.Context) ([]*Auth, error) { return nil, nil }

func (s *countingStore) Save(context.Context, *Auth) (string, error) {
	s.saveCount.Add(1)
	return "", nil
}

func (s *countingStore) Delete(context.Context, string) error { return nil }

func TestWithSkipPersist_DisablesUpdatePersistence(t *testing.T) {
	store := &countingStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "auth-1",
		Provider: "antigravity",
		Metadata: map[string]any{"type": "antigravity"},
	}

	if _, err := mgr.Register(WithSkipPersist(context.Background()), auth); err != nil {
		t.Fatalf("Register(skipPersist) returned error: %v", err)
	}
	if got := store.saveCount.Load(); got != 0 {
		t.Fatalf("expected 0 Save calls, got %d", got)
	}

	if _, err := mgr.Update(context.Background(), auth); err != nil {
		t.Fatalf("Update returned error: %v", err)
	}
	if got := store.saveCount.Load(); got != 1 {
		t.Fatalf("expected 1 Save call, got %d", got)
	}

	ctxSkip := WithSkipPersist(context.Background())
	if _, err := mgr.Update(ctxSkip, auth); err != nil {
		t.Fatalf("Update(skipPersist) returned error: %v", err)
	}
	if got := store.saveCount.Load(); got != 1 {
		t.Fatalf("expected Save call count to remain 1, got %d", got)
	}
}

func TestWithSkipPersist_DisablesRegisterPersistence(t *testing.T) {
	store := &countingStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "auth-1",
		Provider: "antigravity",
		Metadata: map[string]any{"type": "antigravity"},
	}

	if _, err := mgr.Register(WithSkipPersist(context.Background()), auth); err != nil {
		t.Fatalf("Register(skipPersist) returned error: %v", err)
	}
	if got := store.saveCount.Load(); got != 0 {
		t.Fatalf("expected 0 Save calls, got %d", got)
	}
}

func TestPersist_SkipsConfigAPIKeyAuth(t *testing.T) {
	store := &countingStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "codex:apikey:abc",
		Provider: "codex",
		Attributes: map[string]string{
			"api_key": "secret",
			"source":  "config:codex[abc]",
		},
		Metadata: map[string]any{"disable_cooling": true},
	}
	if _, err := mgr.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if got := store.saveCount.Load(); got != 0 {
		t.Fatalf("expected 0 Save calls for config api key, got %d", got)
	}
	mgr.MarkResult(context.Background(), Result{AuthID: auth.ID, Provider: "codex", Model: "gpt-5", Success: true})
	if got := store.saveCount.Load(); got != 0 {
		t.Fatalf("expected MarkResult to skip persist for config api key, got %d Save calls", got)
	}
}

func TestMarkResult_CodexSuccessPersistsRecoveredCooldown(t *testing.T) {
	store := &countingStore{}
	mgr := NewManager(store, nil, nil)
	auth := &Auth{
		ID:       "codex-recovered",
		Provider: "codex",
		Status:   StatusActive,
		Metadata: map[string]any{"type": "codex"},
	}
	model := "gpt-5-recovered"

	if _, errRegister := mgr.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register() returned error: %v", errRegister)
	}

	mgr.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "codex",
		Model:    model,
		Error: &Error{
			Code:       "rate_limit_exceeded",
			Message:    "rate limit exceeded",
			HTTPStatus: http.StatusTooManyRequests,
		},
	})
	if got := store.saveCount.Load(); got != 1 {
		t.Fatalf("cooldown Save calls = %d, want 1", got)
	}

	store.saveCount.Store(0)
	mgr.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "codex",
		Model:    model,
		Success:  true,
	})

	if got := store.saveCount.Load(); got != 1 {
		t.Fatalf("recovery Save calls = %d, want 1", got)
	}
	updated, ok := mgr.GetByID(auth.ID)
	if !ok {
		t.Fatalf("GetByID(%s) ok = false, want true", auth.ID)
	}
	state := updated.ModelStates[model]
	if state == nil {
		t.Fatalf("recovered model state missing")
	}
	if updated.Status != StatusActive || updated.StatusMessage != "" || updated.Unavailable || !updated.NextRetryAfter.IsZero() {
		t.Fatalf("recovered auth state = status %q message %q unavailable %v next %v", updated.Status, updated.StatusMessage, updated.Unavailable, updated.NextRetryAfter)
	}
	if state.Status != StatusActive || state.StatusMessage != "" || state.Unavailable || !state.NextRetryAfter.IsZero() || state.LastError != nil {
		t.Fatalf("recovered model state = status %q message %q unavailable %v next %v error %v", state.Status, state.StatusMessage, state.Unavailable, state.NextRetryAfter, state.LastError)
	}
}

func TestMarkResult_CodexCleanSuccessDoesNotPersistForOtherModelCooldown(t *testing.T) {
	store := &countingStore{}
	mgr := NewManager(store, nil, nil)
	modelCooling := "gpt-5-cooling"
	modelClean := "gpt-5-clean"
	nextRetry := time.Now().Add(30 * time.Minute)
	auth := &Auth{
		ID:            "codex-partial-cooldown",
		Provider:      "codex",
		Status:        StatusError,
		StatusMessage: "rate limit exceeded",
		LastError: &Error{
			Code:       "rate_limit_exceeded",
			Message:    "rate limit exceeded",
			HTTPStatus: http.StatusTooManyRequests,
		},
		Metadata: map[string]any{"type": "codex"},
		ModelStates: map[string]*ModelState{
			modelCooling: {
				Status:         StatusError,
				StatusMessage:  "rate limit exceeded",
				Unavailable:    true,
				NextRetryAfter: nextRetry,
				LastError: &Error{
					Code:       "rate_limit_exceeded",
					Message:    "rate limit exceeded",
					HTTPStatus: http.StatusTooManyRequests,
				},
			},
			modelClean: {
				Status: StatusActive,
			},
		},
	}

	if _, errRegister := mgr.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register() returned error: %v", errRegister)
	}

	mgr.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "codex",
		Model:    modelClean,
		Success:  true,
	})

	if got := store.saveCount.Load(); got != 0 {
		t.Fatalf("clean success Save calls = %d, want 0", got)
	}
	updated, ok := mgr.GetByID(auth.ID)
	if !ok {
		t.Fatalf("GetByID(%s) ok = false, want true", auth.ID)
	}
	if updated.Status != StatusError || updated.LastError == nil {
		t.Fatalf("auth state = status %q error %v, want other model cooldown preserved", updated.Status, updated.LastError)
	}
	if state := updated.ModelStates[modelCooling]; state == nil || state.Status != StatusError || !state.Unavailable {
		t.Fatalf("cooling model state = %+v, want preserved cooldown", state)
	}
}
