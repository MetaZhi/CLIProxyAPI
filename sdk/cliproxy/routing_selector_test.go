package cliproxy

import (
	"strings"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestNewRoutingSelector_UsesExpiryPrioritySelector(t *testing.T) {
	t.Parallel()

	selector := newRoutingSelector(&config.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:             "expiry-priority",
			ExpiryPriorityWindow: "6h",
		},
	}, nil)

	expirySelector, ok := selector.(*coreauth.ExpiryPrioritySelector)
	if !ok {
		t.Fatalf("selector = %T, want *coreauth.ExpiryPrioritySelector", selector)
	}
	if expirySelector.Window != 6*time.Hour {
		t.Fatalf("expirySelector.Window = %v, want %v", expirySelector.Window, 6*time.Hour)
	}
}

func TestNewRoutingSelector_InvalidExpiryWindowFallsBackToDefault(t *testing.T) {
	t.Parallel()

	var warnings []string
	selector := newRoutingSelector(&config.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:             "expiry-priority",
			ExpiryPriorityWindow: "nope",
		},
	}, func(format string, args ...any) {
		warnings = append(warnings, format)
	})

	expirySelector, ok := selector.(*coreauth.ExpiryPrioritySelector)
	if !ok {
		t.Fatalf("selector = %T, want *coreauth.ExpiryPrioritySelector", selector)
	}
	if expirySelector.Window != coreauth.DefaultExpiryPriorityWindow {
		t.Fatalf("expirySelector.Window = %v, want %v", expirySelector.Window, coreauth.DefaultExpiryPriorityWindow)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "invalid routing.expiry-priority-window") {
		t.Fatalf("warnings = %#v, want invalid window warning", warnings)
	}
}
