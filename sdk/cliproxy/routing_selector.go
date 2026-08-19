package cliproxy

import (
	"strings"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func normalizeRoutingStrategyValue(strategy string) string {
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "fill-first", "fillfirst", "ff":
		return "fill-first"
	case "quota-priority", "quotapriority", "qp":
		return "quota-priority"
	default:
		return "round-robin"
	}
}

func routingQuotaPriorityWindow(cfg *config.Config, warnf func(string, ...any)) time.Duration {
	if cfg == nil {
		return coreauth.DefaultQuotaPriorityWindow
	}
	window, err := coreauth.ParseQuotaPriorityWindow(cfg.Routing.QuotaPriorityWindow)
	if err == nil {
		return window
	}
	if warnf != nil {
		warnf("invalid routing.quota-priority-window %q, using default %s: %v", strings.TrimSpace(cfg.Routing.QuotaPriorityWindow), coreauth.DefaultQuotaPriorityWindowString, err)
	}
	return coreauth.DefaultQuotaPriorityWindow
}

func routingQuotaReservePercent(cfg *config.Config, warnf func(string, ...any)) float64 {
	if cfg == nil {
		return coreauth.DefaultQuotaReservePercent
	}
	percent, err := coreauth.QuotaReservePercentFromConfig(cfg.Routing.QuotaReservePercent)
	if err == nil {
		return percent
	}
	if warnf != nil {
		warnf("invalid routing.quota-reserve-percent, using default %.0f: %v", coreauth.DefaultQuotaReservePercent, err)
	}
	return coreauth.DefaultQuotaReservePercent
}

func routingSessionAffinityTTL(cfg *config.Config) time.Duration {
	if cfg == nil {
		return time.Hour
	}
	if ttlStr := strings.TrimSpace(cfg.Routing.SessionAffinityTTL); ttlStr != "" {
		if parsed, err := time.ParseDuration(ttlStr); err == nil && parsed > 0 {
			return parsed
		}
	}
	return time.Hour
}

func newRoutingSelector(cfg *config.Config, warnf func(string, ...any)) coreauth.Selector {
	strategy := normalizeRoutingStrategyValue("")
	if cfg != nil {
		strategy = normalizeRoutingStrategyValue(cfg.Routing.Strategy)
	}
	quotaReservePercent := routingQuotaReservePercent(cfg, warnf)

	var selector coreauth.Selector
	switch strategy {
	case "fill-first":
		selector = &coreauth.FillFirstSelector{QuotaReservePercent: quotaReservePercent}
	case "quota-priority":
		selector = coreauth.NewQuotaPrioritySelector(routingQuotaPriorityWindow(cfg, warnf))
		if quotaSelector, ok := selector.(*coreauth.QuotaPrioritySelector); ok {
			quotaSelector.QuotaReservePercent = quotaReservePercent
		}
	default:
		selector = &coreauth.RoundRobinSelector{QuotaReservePercent: quotaReservePercent}
	}

	if cfg != nil && cfg.Routing.SessionAffinity {
		selector = coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{
			Fallback: selector,
			TTL:      routingSessionAffinityTTL(cfg),
		})
	}
	return selector
}
