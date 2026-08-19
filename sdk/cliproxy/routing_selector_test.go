package cliproxy

import (
	"strings"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func routingTestFloat64Ptr(value float64) *float64 {
	return &value
}

func TestNewRoutingSelector_UsesQuotaPrioritySelector(t *testing.T) {
	t.Parallel()

	selector := newRoutingSelector(&config.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:            "quota-priority",
			QuotaPriorityWindow: "6h",
		},
	}, nil)

	quotaSelector, ok := selector.(*coreauth.QuotaPrioritySelector)
	if !ok {
		t.Fatalf("selector = %T, want *coreauth.QuotaPrioritySelector", selector)
	}
	if quotaSelector.Window != 6*time.Hour {
		t.Fatalf("quotaSelector.Window = %v, want %v", quotaSelector.Window, 6*time.Hour)
	}
}

func TestNewRoutingSelector_InvalidQuotaWindowFallsBackToDefault(t *testing.T) {
	t.Parallel()

	var warnings []string
	selector := newRoutingSelector(&config.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:            "quota-priority",
			QuotaPriorityWindow: "nope",
		},
	}, func(format string, args ...any) {
		warnings = append(warnings, format)
	})

	quotaSelector, ok := selector.(*coreauth.QuotaPrioritySelector)
	if !ok {
		t.Fatalf("selector = %T, want *coreauth.QuotaPrioritySelector", selector)
	}
	if quotaSelector.Window != coreauth.DefaultQuotaPriorityWindow {
		t.Fatalf("quotaSelector.Window = %v, want %v", quotaSelector.Window, coreauth.DefaultQuotaPriorityWindow)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "invalid routing.quota-priority-window") {
		t.Fatalf("warnings = %#v, want invalid window warning", warnings)
	}
}

func TestNewRoutingSelector_QuotaReservePercentDefaultsToZero(t *testing.T) {
	t.Parallel()

	selector := newRoutingSelector(&config.Config{}, nil)

	roundRobin, ok := selector.(*coreauth.RoundRobinSelector)
	if !ok {
		t.Fatalf("selector = %T, want *coreauth.RoundRobinSelector", selector)
	}
	if roundRobin.QuotaReservePercent != coreauth.DefaultQuotaReservePercent {
		t.Fatalf("QuotaReservePercent = %v, want %v", roundRobin.QuotaReservePercent, coreauth.DefaultQuotaReservePercent)
	}
	if roundRobin.QuotaReservePercent != 0 {
		t.Fatalf("QuotaReservePercent = %v, want 0", roundRobin.QuotaReservePercent)
	}
}

func TestNewRoutingSelector_QuotaReservePercentCanBeDisabled(t *testing.T) {
	t.Parallel()

	selector := newRoutingSelector(&config.Config{
		Routing: internalconfig.RoutingConfig{
			QuotaReservePercent: routingTestFloat64Ptr(0),
		},
	}, nil)

	roundRobin, ok := selector.(*coreauth.RoundRobinSelector)
	if !ok {
		t.Fatalf("selector = %T, want *coreauth.RoundRobinSelector", selector)
	}
	if roundRobin.QuotaReservePercent != 0 {
		t.Fatalf("QuotaReservePercent = %v, want 0", roundRobin.QuotaReservePercent)
	}
}

func TestNewRoutingSelector_InvalidQuotaReservePercentFallsBackToDefault(t *testing.T) {
	t.Parallel()

	var warnings []string
	selector := newRoutingSelector(&config.Config{
		Routing: internalconfig.RoutingConfig{
			Strategy:            "quota-priority",
			QuotaReservePercent: routingTestFloat64Ptr(101),
		},
	}, func(format string, args ...any) {
		warnings = append(warnings, format)
	})

	quotaSelector, ok := selector.(*coreauth.QuotaPrioritySelector)
	if !ok {
		t.Fatalf("selector = %T, want *coreauth.QuotaPrioritySelector", selector)
	}
	if quotaSelector.QuotaReservePercent != coreauth.DefaultQuotaReservePercent {
		t.Fatalf("QuotaReservePercent = %v, want %v", quotaSelector.QuotaReservePercent, coreauth.DefaultQuotaReservePercent)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "invalid routing.quota-reserve-percent") {
		t.Fatalf("warnings = %#v, want invalid quota reserve warning", warnings)
	}
}
