package auth

import (
	"context"
	"testing"
)

type listOnlyStore struct {
	auths []*Auth
}

func (s *listOnlyStore) List(context.Context) ([]*Auth, error) {
	return s.auths, nil
}

func (s *listOnlyStore) Save(context.Context, *Auth) (string, error) {
	return "", nil
}

func (s *listOnlyStore) Delete(context.Context, string) error {
	return nil
}

func TestManagerLoadAppliesOAuthMinimumQuotaPercentFromStoreMetadata(t *testing.T) {
	t.Parallel()

	storeAuth := &Auth{
		ID:       "codex.json",
		Provider: "codex",
		Metadata: map[string]any{
			"type": "codex",
			"minimum_quota_percent": map[string]any{
				"5h":   10,
				"week": "20%",
			},
		},
	}
	manager := NewManager(&listOnlyStore{auths: []*Auth{storeAuth}}, &RoundRobinSelector{}, nil)

	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	loaded := manager.List()
	if len(loaded) != 1 {
		t.Fatalf("List() len = %d, want 1", len(loaded))
	}
	got := OAuthMinimumQuotaPercentFromAttributes(loaded[0].Attributes)
	if got["5h"] != 10 || got["week"] != 20 || len(got) != 2 {
		t.Fatalf("minimum_quota_percent = %#v, want 5h=10 week=20", got)
	}
}

func TestManagerRegisterAppliesOAuthMinimumQuotaPercentFromMetadata(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	registered, err := manager.Register(context.Background(), &Auth{
		ID:       "codex.json",
		Provider: "codex",
		Metadata: map[string]any{
			"type": "codex",
			"minimum_quota_percent": map[string]any{
				"5h": 15,
			},
		},
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	got := OAuthMinimumQuotaPercentFromAttributes(registered.Attributes)
	if got["5h"] != 15 || len(got) != 1 {
		t.Fatalf("registered minimum_quota_percent = %#v, want 5h=15", got)
	}
}

func TestManagerUpdateAppliesOAuthMinimumQuotaPercentFromMetadata(t *testing.T) {
	t.Parallel()

	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	if _, err := manager.Register(context.Background(), &Auth{
		ID:       "codex.json",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex"},
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	updated, err := manager.Update(context.Background(), &Auth{
		ID:       "codex.json",
		Provider: "codex",
		Metadata: map[string]any{
			"type": "codex",
			"minimum-quota-percent": map[string]any{
				"week": "30%",
			},
		},
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	got := OAuthMinimumQuotaPercentFromAttributes(updated.Attributes)
	if got["week"] != 30 || len(got) != 1 {
		t.Fatalf("updated minimum_quota_percent = %#v, want week=30", got)
	}

	listed := manager.List()
	if len(listed) != 1 {
		t.Fatalf("List() len = %d, want 1", len(listed))
	}
	got = OAuthMinimumQuotaPercentFromAttributes(listed[0].Attributes)
	if got["week"] != 30 || len(got) != 1 {
		t.Fatalf("stored minimum_quota_percent = %#v, want week=30", got)
	}
}
