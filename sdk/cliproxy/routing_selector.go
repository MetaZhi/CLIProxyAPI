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
	case "expiry-priority", "expirypriority", "ep":
		return "expiry-priority"
	default:
		return "round-robin"
	}
}

func routingExpiryPriorityWindow(cfg *config.Config, warnf func(string, ...any)) time.Duration {
	if cfg == nil {
		return coreauth.DefaultExpiryPriorityWindow
	}
	window, err := coreauth.ParseExpiryPriorityWindow(cfg.Routing.ExpiryPriorityWindow)
	if err == nil {
		return window
	}
	if warnf != nil {
		warnf("invalid routing.expiry-priority-window %q, using default %s: %v", strings.TrimSpace(cfg.Routing.ExpiryPriorityWindow), coreauth.DefaultExpiryPriorityWindowString, err)
	}
	return coreauth.DefaultExpiryPriorityWindow
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

	var selector coreauth.Selector
	switch strategy {
	case "fill-first":
		selector = &coreauth.FillFirstSelector{}
	case "expiry-priority":
		selector = coreauth.NewExpiryPrioritySelector(routingExpiryPriorityWindow(cfg, warnf))
	default:
		selector = &coreauth.RoundRobinSelector{}
	}

	if cfg != nil && cfg.Routing.SessionAffinity {
		selector = coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{
			Fallback: selector,
			TTL:      routingSessionAffinityTTL(cfg),
		})
	}
	return selector
}
