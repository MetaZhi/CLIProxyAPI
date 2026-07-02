package auth

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const (
	codexPrimaryQuotaWindowName   = "5h"
	codexSecondaryQuotaWindowName = "week"
)

type codexQuotaWindowUpdate struct {
	Name             string
	RemainingPercent float64
	UsedPercent      float64
	ResetAt          time.Time
	WindowMinutes    int
}

type codexQuotaUpdateSummary struct {
	PlanType string
	Windows  []codexQuotaWindowUpdate
}

func updateCodexQuotaFromHeaders(auth *Auth, headers http.Header, now time.Time) (codexQuotaUpdateSummary, bool) {
	if auth == nil || headers == nil {
		return codexQuotaUpdateSummary{}, false
	}
	summary := codexQuotaUpdateSummary{
		PlanType: strings.TrimSpace(headers.Get("X-Codex-Plan-Type")),
		Windows:  parseCodexQuotaWindows(headers, now),
	}
	if summary.PlanType == "" && len(summary.Windows) == 0 {
		return summary, false
	}

	if auth.RuntimeMetadata == nil {
		auth.RuntimeMetadata = make(map[string]any)
	}

	changed := false
	if summary.PlanType != "" {
		if current, _ := auth.RuntimeMetadata["plan_type"].(string); strings.TrimSpace(current) != summary.PlanType {
			auth.RuntimeMetadata["plan_type"] = summary.PlanType
			changed = true
		}
	}

	if len(summary.Windows) == 0 {
		return summary, changed
	}

	if clearQuotaProbeGuard(auth) {
		changed = true
	}

	windows := cloneQuotaWindowsMetadata(auth.RuntimeMetadata[quotaWindowsMetadataKey])
	updatedAt := now.UTC().Format(time.RFC3339Nano)
	for _, window := range summary.Windows {
		windowMeta := map[string]any{
			"remaining_percent": normalizeQuotaHeaderPercent(window.RemainingPercent),
			"used_percent":      normalizeQuotaHeaderPercent(window.UsedPercent),
			"reset_at":          window.ResetAt.UTC().Format(time.RFC3339Nano),
			"window_minutes":    window.WindowMinutes,
			"updated_at":        updatedAt,
		}
		if !reflect.DeepEqual(windows[window.Name], windowMeta) {
			windows[window.Name] = windowMeta
			changed = true
		}
	}
	if changed || !reflect.DeepEqual(auth.RuntimeMetadata[quotaWindowsMetadataKey], windows) {
		auth.RuntimeMetadata[quotaWindowsMetadataKey] = windows
		changed = true
	}
	return summary, changed
}

func cloneQuotaWindowsMetadata(raw any) map[string]any {
	existing, ok := nestedAnyMap(raw)
	if !ok || existing == nil {
		return make(map[string]any)
	}
	out := make(map[string]any, len(existing))
	for key, value := range existing {
		if nested, okNested := nestedAnyMap(value); okNested {
			copied := make(map[string]any, len(nested))
			for nestedKey, nestedValue := range nested {
				copied[nestedKey] = nestedValue
			}
			out[key] = copied
			continue
		}
		out[key] = value
	}
	return out
}

func parseCodexQuotaWindows(headers http.Header, now time.Time) []codexQuotaWindowUpdate {
	if headers == nil {
		return nil
	}
	windows := make([]codexQuotaWindowUpdate, 0, 2)
	if window, ok := parseCodexQuotaWindow(headers, now, "Primary", codexPrimaryQuotaWindowName); ok {
		windows = append(windows, window)
	}
	if window, ok := parseCodexQuotaWindow(headers, now, "Secondary", codexSecondaryQuotaWindowName); ok {
		windows = append(windows, window)
	}
	return windows
}

func parseCodexQuotaWindow(headers http.Header, now time.Time, prefix, fallbackName string) (codexQuotaWindowUpdate, bool) {
	usedPercent, okUsed := parseCodexHeaderPercent(headers.Get("X-Codex-" + prefix + "-Used-Percent"))
	if !okUsed {
		return codexQuotaWindowUpdate{}, false
	}
	windowMinutes, okWindow := parseCodexHeaderInt(headers.Get("X-Codex-" + prefix + "-Window-Minutes"))
	if !okWindow || windowMinutes <= 0 {
		return codexQuotaWindowUpdate{}, false
	}
	name := codexQuotaWindowName(windowMinutes, fallbackName)
	if name == "" {
		return codexQuotaWindowUpdate{}, false
	}
	resetAt, okReset := parseCodexQuotaResetAt(headers, prefix, now)
	if !okReset || !resetAt.After(now) {
		return codexQuotaWindowUpdate{}, false
	}
	return codexQuotaWindowUpdate{
		Name:             name,
		RemainingPercent: normalizeQuotaHeaderPercent(100 - usedPercent),
		UsedPercent:      usedPercent,
		ResetAt:          resetAt,
		WindowMinutes:    windowMinutes,
	}, true
}

func codexQuotaWindowName(windowMinutes int, fallbackName string) string {
	switch windowMinutes {
	case 300:
		return codexPrimaryQuotaWindowName
	case 10080:
		return codexSecondaryQuotaWindowName
	default:
		return strings.TrimSpace(fallbackName)
	}
}

func parseCodexQuotaResetAt(headers http.Header, prefix string, now time.Time) (time.Time, bool) {
	if resetAt, ok := parseCodexUnixSeconds(headers.Get("X-Codex-" + prefix + "-Reset-At")); ok {
		return resetAt, true
	}
	resetAfter, ok := parseCodexHeaderInt(headers.Get("X-Codex-" + prefix + "-Reset-After-Seconds"))
	if !ok || resetAfter <= 0 {
		return time.Time{}, false
	}
	return now.Add(time.Duration(resetAfter) * time.Second), true
}

func parseCodexUnixSeconds(raw string) (time.Time, bool) {
	seconds, ok := parseCodexHeaderInt(raw)
	if !ok || seconds <= 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(seconds), 0), true
}

func parseCodexHeaderPercent(raw string) (float64, bool) {
	value, ok := parseCodexHeaderFloat(raw)
	if !ok || value < 0 || value > 100 {
		return 0, false
	}
	return value, true
}

func parseCodexHeaderFloat(raw string) (float64, bool) {
	raw = strings.TrimSpace(strings.TrimSuffix(raw, "%"))
	if raw == "" {
		return 0, false
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, false
	}
	return value, true
}

func parseCodexHeaderInt(raw string) (int, bool) {
	value, ok := parseCodexHeaderFloat(raw)
	if !ok {
		return 0, false
	}
	rounded := math.Round(value)
	if math.Abs(value-rounded) > 0.000001 {
		return 0, false
	}
	return int(rounded), true
}

func normalizeQuotaHeaderPercent(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func logCodexQuotaUpdate(ctx context.Context, authID string, summary codexQuotaUpdateSummary) {
	if len(summary.Windows) == 0 && strings.TrimSpace(summary.PlanType) == "" {
		return
	}
	parts := make([]string, 0, len(summary.Windows))
	now := time.Now()
	for _, window := range summary.Windows {
		resetIn := window.ResetAt.Sub(now)
		if resetIn < 0 {
			resetIn = 0
		}
		parts = append(parts, fmt.Sprintf("%s=%.2f%% reset_in=%s", window.Name, window.RemainingPercent, resetIn.Round(time.Second)))
	}
	entry := logEntryWithRequestID(ctx).WithField("auth", authID)
	entry.Infof("codex quota updated | plan_type=%s windows=%s", summary.PlanType, strings.Join(parts, " "))
}
