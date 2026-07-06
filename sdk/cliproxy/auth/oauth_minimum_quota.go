package auth

import (
	"encoding/json"
	"strings"
)

const oauthMinimumQuotaPercentAttributeKey = "minimum_quota_percent"

// OAuthMinimumQuotaPercentFromMetadata returns sanitized per-auth quota thresholds
// from OAuth JSON metadata. It supports both snake_case and kebab-case keys.
func OAuthMinimumQuotaPercentFromMetadata(metadata map[string]any) map[string]float64 {
	if len(metadata) == 0 {
		return nil
	}
	raw, ok := metadata["minimum_quota_percent"]
	if !ok {
		raw, ok = metadata["minimum-quota-percent"]
	}
	if !ok || raw == nil {
		return nil
	}
	rawMap, ok := nestedAnyMap(raw)
	if !ok {
		return nil
	}
	return normalizeOAuthMinimumQuotaPercent(rawMap)
}

// OAuthMinimumQuotaPercentMetadataPresent reports whether OAuth JSON metadata
// explicitly contains a per-auth quota threshold field.
func OAuthMinimumQuotaPercentMetadataPresent(metadata map[string]any) bool {
	if len(metadata) == 0 {
		return false
	}
	if _, ok := metadata["minimum_quota_percent"]; ok {
		return true
	}
	_, ok := metadata["minimum-quota-percent"]
	return ok
}

// ApplyOAuthMinimumQuotaPercentFromMetadata applies an explicitly configured
// OAuth JSON quota threshold from auth metadata to auth attributes.
func ApplyOAuthMinimumQuotaPercentFromMetadata(auth *Auth) {
	if auth == nil || !OAuthMinimumQuotaPercentMetadataPresent(auth.Metadata) {
		return
	}
	SetOAuthMinimumQuotaPercentAttribute(auth, OAuthMinimumQuotaPercentFromMetadata(auth.Metadata))
}

// SetOAuthMinimumQuotaPercentAttribute stores sanitized per-auth quota thresholds
// as JSON in auth attributes. Empty or disabled thresholds remove the attribute.
func SetOAuthMinimumQuotaPercentAttribute(auth *Auth, thresholds map[string]float64) {
	if auth == nil {
		return
	}
	normalized := normalizeOAuthMinimumQuotaPercentFloatMap(thresholds)
	if len(normalized) == 0 {
		if auth.Attributes != nil {
			delete(auth.Attributes, oauthMinimumQuotaPercentAttributeKey)
		}
		return
	}
	data, errMarshal := json.Marshal(normalized)
	if errMarshal != nil {
		return
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes[oauthMinimumQuotaPercentAttributeKey] = string(data)
}

// OAuthMinimumQuotaPercentFromAttributes returns sanitized per-auth quota
// thresholds from auth attributes.
func OAuthMinimumQuotaPercentFromAttributes(attributes map[string]string) map[string]float64 {
	if len(attributes) == 0 {
		return nil
	}
	raw := strings.TrimSpace(attributes[oauthMinimumQuotaPercentAttributeKey])
	if raw == "" {
		return nil
	}
	var thresholds map[string]any
	if errUnmarshal := json.Unmarshal([]byte(raw), &thresholds); errUnmarshal != nil {
		return nil
	}
	return normalizeOAuthMinimumQuotaPercent(thresholds)
}

func normalizeOAuthMinimumQuotaPercent(raw map[string]any) map[string]float64 {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]float64)
	for name, value := range raw {
		window, okWindow := canonicalOAuthMinimumQuotaWindow(name)
		if !okWindow {
			continue
		}
		percent, okPercent := parseQuotaFloat(value)
		if !okPercent {
			continue
		}
		percent = normalizeMinimumQuotaPercent(percent)
		if percent <= 0 {
			continue
		}
		out[window] = percent
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeOAuthMinimumQuotaPercentFloatMap(raw map[string]float64) map[string]float64 {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]float64)
	for name, value := range raw {
		window, okWindow := canonicalOAuthMinimumQuotaWindow(name)
		if !okWindow {
			continue
		}
		percent := normalizeMinimumQuotaPercent(value)
		if percent <= 0 {
			continue
		}
		out[window] = percent
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func canonicalOAuthMinimumQuotaWindow(name string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "5h":
		return "5h", true
	case "week":
		return "week", true
	default:
		return "", false
	}
}
