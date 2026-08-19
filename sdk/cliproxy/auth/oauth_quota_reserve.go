package auth

import (
	"encoding/json"
	"strings"
)

const oauthQuotaReservePercentAttributeKey = "quota_reserve_percent"

// OAuthQuotaReservePercentFromMetadata returns the sanitized weekly per-auth quota threshold
// from OAuth JSON metadata.
func OAuthQuotaReservePercentFromMetadata(metadata map[string]any) map[string]float64 {
	if len(metadata) == 0 {
		return nil
	}
	raw, ok := metadata["quota_reserve_percent"]
	if !ok || raw == nil {
		return nil
	}
	rawMap, ok := nestedAnyMap(raw)
	if !ok {
		return nil
	}
	return normalizeOAuthQuotaReservePercent(rawMap)
}

// OAuthQuotaReservePercentMetadataPresent reports whether OAuth JSON metadata
// explicitly contains a per-auth quota threshold field.
func OAuthQuotaReservePercentMetadataPresent(metadata map[string]any) bool {
	if len(metadata) == 0 {
		return false
	}
	_, ok := metadata["quota_reserve_percent"]
	return ok
}

// ApplyOAuthQuotaReservePercentFromMetadata applies an explicitly configured
// OAuth JSON quota threshold from auth metadata to auth attributes.
func ApplyOAuthQuotaReservePercentFromMetadata(auth *Auth) {
	if auth == nil || !OAuthQuotaReservePercentMetadataPresent(auth.Metadata) {
		return
	}
	SetOAuthQuotaReservePercentAttribute(auth, OAuthQuotaReservePercentFromMetadata(auth.Metadata))
}

// SetOAuthQuotaReservePercentAttribute stores the sanitized weekly per-auth quota threshold
// as JSON in auth attributes. An explicit 0% threshold is preserved to override the global threshold.
func SetOAuthQuotaReservePercentAttribute(auth *Auth, thresholds map[string]float64) {
	if auth == nil {
		return
	}
	normalized := normalizeOAuthQuotaReservePercentFloatMap(thresholds)
	if len(normalized) == 0 {
		if auth.Attributes != nil {
			delete(auth.Attributes, oauthQuotaReservePercentAttributeKey)
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
	auth.Attributes[oauthQuotaReservePercentAttributeKey] = string(data)
}

// OAuthQuotaReservePercentFromAttributes returns the sanitized weekly per-auth quota
// threshold from auth attributes.
func OAuthQuotaReservePercentFromAttributes(attributes map[string]string) map[string]float64 {
	if len(attributes) == 0 {
		return nil
	}
	raw := strings.TrimSpace(attributes[oauthQuotaReservePercentAttributeKey])
	if raw == "" {
		return nil
	}
	var thresholds map[string]any
	if errUnmarshal := json.Unmarshal([]byte(raw), &thresholds); errUnmarshal != nil {
		return nil
	}
	return normalizeOAuthQuotaReservePercent(thresholds)
}

func oauthWeeklyQuotaReservePercent(attributes map[string]string) (float64, bool) {
	threshold, ok := OAuthQuotaReservePercentFromAttributes(attributes)["week"]
	return threshold, ok
}

func normalizeOAuthQuotaReservePercent(raw map[string]any) map[string]float64 {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]float64)
	for name, value := range raw {
		window, okWindow := canonicalOAuthQuotaReserveWindow(name)
		if !okWindow {
			continue
		}
		percent, okPercent := parseQuotaFloat(value)
		if !okPercent || percent < 0 || percent > 100 {
			continue
		}
		out[window] = percent
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeOAuthQuotaReservePercentFloatMap(raw map[string]float64) map[string]float64 {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]float64)
	for name, value := range raw {
		window, okWindow := canonicalOAuthQuotaReserveWindow(name)
		if !okWindow {
			continue
		}
		if _, okFinite := finiteQuotaFloat(value); !okFinite || value < 0 || value > 100 {
			continue
		}
		out[window] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func canonicalOAuthQuotaReserveWindow(name string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "week":
		return "week", true
	default:
		return "", false
	}
}
