package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/credentialweight"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
)

const DefaultQuotaPriorityWindowString = "168h"

var DefaultQuotaPriorityWindow = mustParseQuotaPriorityDefaultWindow()

const DefaultMinimumQuotaPercent = 0.0
const quotaPriorityScoreMinMinutes = 1.0
const quotaWarmupInFlightCooldown = 2 * time.Minute
const quotaWarmupMissingHeadersCooldown = time.Minute
const selectionCandidateLogLimit = 12
const quotaWindowsMetadataKey = "quota_windows"
const quotaProbeAfterMetadataKey = "quota_probe_after"

// RoundRobinSelector provides a simple provider scoped round-robin selection strategy.
type RoundRobinSelector struct {
	mu                  sync.Mutex
	cursors             map[string]int
	maxKeys             int
	MinimumQuotaPercent float64
}

// WeightedRoundRobinSelector provides smooth weighted round-robin selection.
type WeightedRoundRobinSelector struct {
	mu      sync.Mutex
	states  map[string]*smoothWeightedState
	maxKeys int
}

type smoothWeightedState struct {
	current map[string]int64
	weights map[string]int64
}

type weightedSelectorStateModelKey struct{}

func withWeightedSelectorStateModel(ctx context.Context, selector Selector, routeModel string) context.Context {
	if _, ok := selector.(*WeightedRoundRobinSelector); !ok || strings.TrimSpace(routeModel) == "" {
		return ctx
	}
	return context.WithValue(ctx, weightedSelectorStateModelKey{}, routeModel)
}

func weightedSelectorStateModel(ctx context.Context, availabilityModel string) string {
	if ctx != nil {
		if routeModel, ok := ctx.Value(weightedSelectorStateModelKey{}).(string); ok && strings.TrimSpace(routeModel) != "" {
			return routeModel
		}
	}
	return availabilityModel
}

// FillFirstSelector selects the first available credential (deterministic ordering).
// This "burns" one account before moving to the next, which can help stagger
// rolling-window subscription caps (e.g. chat message limits).
type FillFirstSelector struct {
	MinimumQuotaPercent float64
}

// QuotaPrioritySelector prioritizes credentials with quota window metadata.
// Selection uses the highest remaining-quota-per-reset-minute score from
// runtime quota_windows observed from upstream response headers.
// If no credential has scoreable quota window data, selection falls back to round-robin.
type QuotaPrioritySelector struct {
	Window              time.Duration
	MinimumQuotaPercent float64
	roundRobin          RoundRobinSelector
}

type blockReason int

const (
	blockReasonNone blockReason = iota
	blockReasonCooldown
	blockReasonDisabled
	blockReasonOther
)

type modelCooldownError struct {
	model    string
	resetIn  time.Duration
	provider string
}

func newModelCooldownError(model, provider string, resetIn time.Duration) *modelCooldownError {
	if resetIn < 0 {
		resetIn = 0
	}
	return &modelCooldownError{
		model:    model,
		provider: provider,
		resetIn:  resetIn,
	}
}

func (e *modelCooldownError) Error() string {
	modelName := e.model
	if modelName == "" {
		modelName = "requested model"
	}
	message := fmt.Sprintf("All credentials for model %s are cooling down", modelName)
	if e.provider != "" {
		message = fmt.Sprintf("%s via provider %s", message, e.provider)
	}
	resetSeconds := int(math.Ceil(e.resetIn.Seconds()))
	if resetSeconds < 0 {
		resetSeconds = 0
	}
	displayDuration := e.resetIn
	if displayDuration > 0 && displayDuration < time.Second {
		displayDuration = time.Second
	} else {
		displayDuration = displayDuration.Round(time.Second)
	}
	errorBody := map[string]any{
		"code":          "model_cooldown",
		"message":       message,
		"model":         e.model,
		"reset_time":    displayDuration.String(),
		"reset_seconds": resetSeconds,
	}
	if e.provider != "" {
		errorBody["provider"] = e.provider
	}
	payload := map[string]any{"error": errorBody}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf(`{"error":{"code":"model_cooldown","message":"%s"}}`, message)
	}
	return string(data)
}

func (e *modelCooldownError) StatusCode() int {
	return http.StatusTooManyRequests
}

func (e *modelCooldownError) Headers() http.Header {
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	resetSeconds := int(math.Ceil(e.resetIn.Seconds()))
	if resetSeconds < 0 {
		resetSeconds = 0
	}
	headers.Set("Retry-After", strconv.Itoa(resetSeconds))
	return headers
}

func authPriority(auth *Auth) int {
	if auth == nil || auth.Attributes == nil {
		return 0
	}
	raw := strings.TrimSpace(auth.Attributes["priority"])
	if raw == "" {
		return 0
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return parsed
}

func authWeight(auth *Auth) int64 {
	if auth == nil {
		return credentialweight.Default
	}
	if rawWeight, ok := auth.Attributes[AttributeWeight]; ok && strings.TrimSpace(rawWeight) != "" {
		weight, errParse := credentialweight.ParseString(rawWeight)
		if errParse != nil {
			return 0
		}
		return weight
	}
	if rawWeight, ok := auth.Metadata[AttributeWeight]; ok {
		weight, errParse := credentialweight.ParseValue(rawWeight)
		if errParse != nil {
			return 0
		}
		return weight
	}
	return credentialweight.Default
}

func canonicalModelKey(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return ""
	}
	parsed := thinking.ParseSuffix(model)
	modelName := strings.TrimSpace(parsed.ModelName)
	if modelName == "" {
		return model
	}
	return modelName
}

func authWebsocketsEnabled(auth *Auth) bool {
	if auth == nil {
		return false
	}
	if len(auth.Attributes) > 0 {
		if raw := strings.TrimSpace(auth.Attributes["websockets"]); raw != "" {
			parsed, errParse := strconv.ParseBool(raw)
			if errParse == nil {
				return parsed
			}
		}
	}
	if len(auth.Metadata) == 0 {
		return false
	}
	raw, ok := auth.Metadata["websockets"]
	if !ok || raw == nil {
		return false
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		parsed, errParse := strconv.ParseBool(strings.TrimSpace(v))
		if errParse == nil {
			return parsed
		}
	default:
	}
	return false
}

func preferCodexWebsocketAuths(ctx context.Context, provider string, available []*Auth) []*Auth {
	if len(available) == 0 {
		return available
	}
	if !cliproxyexecutor.DownstreamWebsocket(ctx) {
		return available
	}
	if !strings.EqualFold(strings.TrimSpace(provider), "codex") {
		return available
	}

	wsEnabled := make([]*Auth, 0, len(available))
	for i := 0; i < len(available); i++ {
		candidate := available[i]
		if authWebsocketsEnabled(candidate) {
			wsEnabled = append(wsEnabled, candidate)
		}
	}
	if len(wsEnabled) > 0 {
		return wsEnabled
	}
	return available
}

func quotaPriorityWindowExhaustedUntil(auth *Auth, now time.Time, window time.Duration) (time.Time, bool) {
	return quotaPriorityTargetWindowExhaustedUntil(auth, now, window)
}

func quotaPriorityTargetWindowExhaustedUntil(auth *Auth, now time.Time, window time.Duration) (time.Time, bool) {
	windowScore, ok := bestQuotaWindowScore(auth, now, window)
	if !ok || !windowScore.ResetAt.After(now) {
		return time.Time{}, false
	}
	if windowScore.RemainingPercent > 0 {
		return time.Time{}, false
	}
	return windowScore.ResetAt, true
}

func quotaAvailabilityBlockedUntil(auth *Auth, now time.Time, quotaExhaustionWindow time.Duration) (time.Time, bool) {
	if auth == nil {
		return time.Time{}, false
	}
	var latest time.Time
	if quotaExhaustionWindow > 0 {
		if resetAt, exhausted := quotaPriorityTargetWindowExhaustedUntil(auth, now, quotaExhaustionWindow); exhausted {
			latest = laterTime(latest, resetAt)
		}
	}
	for windowName, threshold := range OAuthMinimumQuotaPercentFromAttributes(auth.Attributes) {
		duration, okDuration := oauthMinimumQuotaWindowDuration(windowName)
		if !okDuration || threshold <= 0 {
			continue
		}
		windowScore, okScore := bestQuotaWindowScore(auth, now, duration)
		if !okScore || !windowScore.ResetAt.After(now) {
			continue
		}
		if windowScore.RemainingPercent < threshold {
			latest = laterTime(latest, windowScore.ResetAt)
		}
	}
	return latest, !latest.IsZero()
}

func oauthMinimumQuotaWindowDuration(window string) (time.Duration, bool) {
	switch window {
	case "5h":
		return 5 * time.Hour, true
	case "week":
		return 7 * 24 * time.Hour, true
	default:
		return 0, false
	}
}

func laterTime(current, candidate time.Time) time.Time {
	if candidate.IsZero() {
		return current
	}
	if current.IsZero() || candidate.After(current) {
		return candidate
	}
	return current
}

func isCodexAuth(auth *Auth) bool {
	return auth != nil && strings.EqualFold(strings.TrimSpace(auth.Provider), "codex")
}

func targetQuotaWindowResetAt(auth *Auth, window time.Duration) (time.Time, bool) {
	if auth == nil {
		return time.Time{}, false
	}
	windows, ok := quotaWindowsFromRuntimeMetadata(auth)
	if !ok {
		return time.Time{}, false
	}
	for name, raw := range windows {
		windowMeta, okMap := nestedAnyMap(raw)
		if !okMap {
			continue
		}
		if !quotaWindowMatchesDuration(name, windowMeta, window) {
			continue
		}
		if resetAt, okReset := quotaWindowResetAtFromMap(windowMeta); okReset {
			return resetAt, true
		}
	}
	return time.Time{}, false
}

func quotaProbeAfter(auth *Auth) (time.Time, bool) {
	if auth == nil || auth.RuntimeMetadata == nil {
		return time.Time{}, false
	}
	raw, ok := auth.RuntimeMetadata[quotaProbeAfterMetadataKey]
	if !ok {
		return time.Time{}, false
	}
	return parseQuotaWindowResetAt(raw)
}

func quotaProbeCoolingDown(auth *Auth, now time.Time) bool {
	probeAfter, ok := quotaProbeAfter(auth)
	return ok && probeAfter.After(now)
}

func markQuotaProbeCooldown(auth *Auth, now time.Time, cooldown time.Duration) {
	if auth == nil {
		return
	}
	if cooldown <= 0 {
		cooldown = quotaWarmupInFlightCooldown
	}
	if auth.RuntimeMetadata == nil {
		auth.RuntimeMetadata = make(map[string]any)
	}
	auth.RuntimeMetadata[quotaProbeAfterMetadataKey] = now.Add(cooldown).UTC().Format(time.RFC3339Nano)
}

func markQuotaProbeAttempt(auth *Auth, now time.Time) {
	markQuotaProbeCooldown(auth, now, quotaWarmupInFlightCooldown)
}

func markQuotaProbeMissingHeaders(auth *Auth, now time.Time) {
	markQuotaProbeCooldown(auth, now, quotaWarmupMissingHeadersCooldown)
}

func clearQuotaProbeGuard(auth *Auth) bool {
	if auth == nil || auth.RuntimeMetadata == nil {
		return false
	}
	if _, ok := auth.RuntimeMetadata[quotaProbeAfterMetadataKey]; !ok {
		return false
	}
	delete(auth.RuntimeMetadata, quotaProbeAfterMetadataKey)
	return true
}

func clearRuntimeQuotaProbeState(auth *Auth) bool {
	if auth == nil || auth.RuntimeMetadata == nil {
		return false
	}
	changed := false
	for _, key := range []string{quotaWindowsMetadataKey, quotaProbeAfterMetadataKey} {
		if _, ok := auth.RuntimeMetadata[key]; ok {
			delete(auth.RuntimeMetadata, key)
			changed = true
		}
	}
	return changed
}

func needsQuotaWarmup(auth *Auth, now time.Time, window time.Duration) bool {
	if !isCodexAuth(auth) || quotaProbeCoolingDown(auth, now) {
		return false
	}
	return lacksQuotaWindowScore(auth, now, window)
}

func lacksQuotaWindowScore(auth *Auth, now time.Time, window time.Duration) bool {
	if !isCodexAuth(auth) {
		return false
	}
	_, ok := bestQuotaWindowScore(auth, now, window)
	return !ok
}

func pickQuotaWarmupAuth(auths []*Auth, now time.Time, window time.Duration) (*Auth, bool) {
	for _, auth := range auths {
		if !needsQuotaWarmup(auth, now, window) {
			continue
		}
		markQuotaProbeAttempt(auth, now)
		return auth, true
	}
	return nil, false
}

func isQuotaWarmupProbeSelection(auth *Auth, now time.Time, window time.Duration) bool {
	if window <= 0 || !isCodexAuth(auth) || !quotaProbeCoolingDown(auth, now) {
		return false
	}
	_, ok := bestQuotaWindowScore(auth, now, window)
	return !ok
}

func selectorQuotaPriorityExhaustionWindow(selector Selector) (time.Duration, bool) {
	switch current := selector.(type) {
	case *QuotaPrioritySelector:
		if current == nil {
			return 0, false
		}
		return current.quotaPriorityWindow(), true
	case *SessionAffinitySelector:
		if current == nil {
			return 0, false
		}
		return selectorQuotaPriorityExhaustionWindow(current.fallback)
	default:
		return 0, false
	}
}

func collectAvailableByPriority(auths []*Auth, model string, now time.Time, quotaExhaustionWindow time.Duration) (available map[int][]*Auth, cooldownCount int, earliest time.Time) {
	available = make(map[int][]*Auth)
	for i := 0; i < len(auths); i++ {
		candidate := auths[i]
		blocked, reason, next := isAuthBlockedForModel(candidate, model, now)
		if !blocked {
			if resetAt, quotaBlocked := quotaAvailabilityBlockedUntil(candidate, now, quotaExhaustionWindow); quotaBlocked {
				cooldownCount++
				if earliest.IsZero() || resetAt.Before(earliest) {
					earliest = resetAt
				}
				continue
			}
			priority := authPriority(candidate)
			available[priority] = append(available[priority], candidate)
			continue
		}
		if reason == blockReasonCooldown {
			cooldownCount++
			if !next.IsZero() && (earliest.IsZero() || next.Before(earliest)) {
				earliest = next
			}
		}
	}
	return available, cooldownCount, earliest
}

func getAvailableAuths(auths []*Auth, provider, model string, now time.Time, quotaExhaustionWindow time.Duration) ([]*Auth, error) {
	return getAvailableAuthsWithPriorityMode(auths, provider, model, now, quotaExhaustionWindow, false)
}

func getAvailableAuthsAcrossPriorities(auths []*Auth, provider, model string, now time.Time, quotaExhaustionWindow time.Duration) ([]*Auth, error) {
	return getAvailableAuthsWithPriorityMode(auths, provider, model, now, quotaExhaustionWindow, true)
}

func getAvailableAuthsWithPriorityMode(auths []*Auth, provider, model string, now time.Time, quotaExhaustionWindow time.Duration, allPriorities bool) ([]*Auth, error) {
	if len(auths) == 0 {
		return nil, &Error{Code: "auth_not_found", Message: "no auth candidates"}
	}

	availableByPriority, cooldownCount, earliest := collectAvailableByPriority(auths, model, now, quotaExhaustionWindow)
	if len(availableByPriority) == 0 {
		if cooldownCount == len(auths) && !earliest.IsZero() {
			providerForError := provider
			if providerForError == "mixed" {
				providerForError = ""
			}
			resetIn := earliest.Sub(now)
			if resetIn < 0 {
				resetIn = 0
			}
			return nil, newModelCooldownError(model, providerForError, resetIn)
		}
		return nil, &Error{Code: "auth_unavailable", Message: "no auth available"}
	}

	return availableAuthsFromPriorityBuckets(availableByPriority, allPriorities), nil
}

// availableAuthsFromPriorityBuckets flattens availability buckets into a stable, ID-sorted slice.
// When allPriorities is false only the highest available priority tier is returned.
// When allPriorities is true every tier is merged, so the result carries no priority ordering:
// use it for membership checks or feed it to highestPriorityAuths, never as a priority-ordered
// selection order.
func availableAuthsFromPriorityBuckets(availableByPriority map[int][]*Auth, allPriorities bool) []*Auth {
	var candidates []*Auth
	if allPriorities {
		total := 0
		for _, bucket := range availableByPriority {
			total += len(bucket)
		}
		candidates = make([]*Auth, 0, total)
		for _, bucket := range availableByPriority {
			candidates = append(candidates, bucket...)
		}
	} else {
		bestPriority := 0
		found := false
		for priority := range availableByPriority {
			if !found || priority > bestPriority {
				bestPriority = priority
				found = true
			}
		}
		bucket := availableByPriority[bestPriority]
		candidates = make([]*Auth, 0, len(bucket))
		candidates = append(candidates, bucket...)
	}
	if len(candidates) > 1 {
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	}
	return candidates
}

// highestPriorityAuths narrows an availability slice to its highest priority tier while
// preserving the input order. The input slice is returned unchanged when every candidate
// already shares the highest priority, so the common single-tier case allocates nothing.
func highestPriorityAuths(auths []*Auth) []*Auth {
	if len(auths) <= 1 {
		return auths
	}
	bestPriority := 0
	bestCount := 0
	for _, auth := range auths {
		priority := authPriority(auth)
		switch {
		case bestCount == 0 || priority > bestPriority:
			bestPriority = priority
			bestCount = 1
		case priority == bestPriority:
			bestCount++
		}
	}
	if bestCount == len(auths) {
		return auths
	}
	highest := make([]*Auth, 0, bestCount)
	for _, auth := range auths {
		if authPriority(auth) == bestPriority {
			highest = append(highest, auth)
		}
	}
	return highest
}

func getSelectableAuths(ctx context.Context, auths []*Auth, provider, model string, now time.Time, minimumQuotaPercent float64, quotaExhaustionWindow time.Duration) ([]*Auth, error) {
	return getSelectableAuthsWithPriorityMode(ctx, auths, provider, model, now, minimumQuotaPercent, quotaExhaustionWindow, false)
}

func getSelectableAuthsWithPriorityMode(ctx context.Context, auths []*Auth, provider, model string, now time.Time, minimumQuotaPercent float64, quotaExhaustionWindow time.Duration, allPriorities bool) ([]*Auth, error) {
	available, err := getAvailableAuthsWithPriorityMode(auths, provider, model, now, quotaExhaustionWindow, allPriorities)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	available = filterAuthsByMinimumQuota(available, minimumQuotaPercent, now, quotaExhaustionWindow)
	entry := selectorLogEntry(ctx)
	if entry.Logger.IsLevelEnabled(log.DebugLevel) {
		logWindow := quotaExhaustionWindow
		if logWindow <= 0 {
			logWindow = DefaultQuotaPriorityWindow
		}
		entry.Debugf("routing selectable auths | provider=%s model=%s candidates=%d selectable=%d minimum_quota_percent=%.2f quota_exhaustion_window=%s auths=%s",
			provider, model, len(auths), len(available), normalizeMinimumQuotaPercent(minimumQuotaPercent), logWindow, formatAuthSelectionCandidates(available, now, logWindow))
	}
	return available, nil
}

func MinimumQuotaPercentFromConfig(value *float64) (float64, error) {
	if value == nil {
		return DefaultMinimumQuotaPercent, nil
	}
	percent := *value
	if math.IsNaN(percent) || math.IsInf(percent, 0) {
		return 0, fmt.Errorf("minimum quota percent must be finite")
	}
	if percent < 0 || percent > 100 {
		return 0, fmt.Errorf("minimum quota percent must be between 0 and 100")
	}
	return percent, nil
}

func normalizeMinimumQuotaPercent(percent float64) float64 {
	if math.IsNaN(percent) || math.IsInf(percent, 0) || percent < 0 || percent > 100 {
		return DefaultMinimumQuotaPercent
	}
	return percent
}

var quotaPercentKeys = [...]string{"remaining_percent", "quota_percent", "quota_remaining_percent", "remainingQuotaPercent"}
var quotaRatioKeys = [...]string{"remaining_ratio", "quota_ratio", "quota_remaining_ratio"}

type quotaWindowScore struct {
	Name             string
	RemainingPercent float64
	ResetAt          time.Time
	ResetIn          time.Duration
	Window           time.Duration
	Score            float64
	Multiplier       float64
}

func remainingQuotaPercent(auth *Auth) (float64, bool) {
	return remainingQuotaPercentAt(auth, time.Now())
}

func remainingQuotaPercentAt(auth *Auth, now time.Time) (float64, bool) {
	if auth == nil {
		return 0, false
	}
	if percent, ok := highestQuotaWindowRemainingPercent(auth, now); ok {
		return percent, true
	}
	return remainingQuotaPercentFromMap(auth.Metadata)
}

func quotaCapacityMultiplier(auth *Auth) float64 {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return 1
	}
	planType := ""
	if auth.RuntimeMetadata != nil {
		if runtimePlanType, ok := auth.RuntimeMetadata["plan_type"].(string); ok {
			planType = runtimePlanType
		}
	}
	if strings.TrimSpace(planType) == "" && auth.Attributes != nil {
		planType = auth.Attributes["plan_type"]
	}
	if strings.TrimSpace(planType) == "" && auth.Metadata != nil {
		if metadataPlanType, ok := auth.Metadata["plan_type"].(string); ok {
			planType = metadataPlanType
		}
	}
	switch normalizePlanTypeForQuotaMultiplier(planType) {
	case "prolite":
		return 5
	case "pro":
		return 20
	default:
		return 1
	}
}

func normalizePlanTypeForQuotaMultiplier(planType string) string {
	planType = strings.ToLower(strings.TrimSpace(planType))
	if planType == "" {
		return ""
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return -1
	}, planType)
}

func remainingQuotaPercentFromMap(meta map[string]any) (float64, bool) {
	if meta == nil {
		return 0, false
	}
	if percent, ok := quotaPercentFromMap(meta); ok {
		return percent, true
	}
	for _, nestedKey := range []string{"quota", "usage"} {
		nested, ok := nestedAnyMap(meta[nestedKey])
		if !ok {
			continue
		}
		if percent, ok := remainingQuotaPercentFromMap(nested); ok {
			return percent, true
		}
	}
	return 0, false
}

func quotaWindowsFromRuntimeMetadata(auth *Auth) (map[string]any, bool) {
	if auth == nil {
		return nil, false
	}
	return quotaWindowsFromMetadata(auth.RuntimeMetadata)
}

func quotaWindowsFromMetadata(meta map[string]any) (map[string]any, bool) {
	if meta == nil {
		return nil, false
	}
	raw, ok := meta[quotaWindowsMetadataKey]
	if !ok {
		return nil, false
	}
	return nestedAnyMap(raw)
}

func parseQuotaWindowResetAt(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		if typed.IsZero() {
			return time.Time{}, false
		}
		return typed, true
	case string:
		raw := strings.TrimSpace(typed)
		if raw == "" {
			return time.Time{}, false
		}
		if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			return parsed, true
		}
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			return parsed, true
		}
	case json.Number:
		seconds, err := typed.Int64()
		if err == nil && seconds > 0 {
			return time.Unix(seconds, 0), true
		}
	case int64:
		if typed > 0 {
			return time.Unix(typed, 0), true
		}
	case int:
		if typed > 0 {
			return time.Unix(int64(typed), 0), true
		}
	case float64:
		if typed > 0 && !math.IsNaN(typed) && !math.IsInf(typed, 0) {
			return time.Unix(int64(typed), 0), true
		}
	}
	return time.Time{}, false
}

func quotaWindowResetAtFromMap(meta map[string]any) (time.Time, bool) {
	for _, key := range []string{"reset_at", "resetAt", "resets_at", "resetsAt"} {
		if value, ok := meta[key]; ok {
			if resetAt, ok := parseQuotaWindowResetAt(value); ok {
				return resetAt, true
			}
		}
	}
	return time.Time{}, false
}

func bestQuotaWindowScore(auth *Auth, now time.Time, window time.Duration) (quotaWindowScore, bool) {
	if auth == nil {
		return quotaWindowScore{}, false
	}
	windows, ok := quotaWindowsFromRuntimeMetadata(auth)
	if !ok {
		return quotaWindowScore{}, false
	}
	multiplier := quotaCapacityMultiplier(auth)
	var best quotaWindowScore
	found := false
	for name, raw := range windows {
		windowMeta, okMap := nestedAnyMap(raw)
		if !okMap {
			continue
		}
		windowDuration, okDuration := quotaWindowDuration(name, windowMeta)
		if !okDuration || windowDuration != normalizeQuotaPriorityWindow(window) {
			continue
		}
		resetAt, okReset := quotaWindowResetAtFromMap(windowMeta)
		if !okReset || !resetAt.After(now) {
			continue
		}
		percent, okPercent := quotaPercentFromMap(windowMeta)
		if !okPercent {
			continue
		}
		resetIn := resetAt.Sub(now)
		remainingMinutes := resetIn.Minutes()
		if remainingMinutes < quotaPriorityScoreMinMinutes {
			remainingMinutes = quotaPriorityScoreMinMinutes
		}
		score := percent * multiplier / remainingMinutes
		current := quotaWindowScore{
			Name:             strings.TrimSpace(name),
			RemainingPercent: percent,
			ResetAt:          resetAt,
			ResetIn:          resetIn,
			Window:           windowDuration,
			Score:            score,
			Multiplier:       multiplier,
		}
		if !found || quotaWindowScoreBefore(current, best) {
			best = current
			found = true
		}
	}
	return best, found
}

func quotaWindowMatchesDuration(name string, meta map[string]any, window time.Duration) bool {
	window = normalizeQuotaPriorityWindow(window)
	if window <= 0 {
		return false
	}
	duration, ok := quotaWindowDuration(name, meta)
	return ok && duration == window
}

func quotaWindowDuration(name string, meta map[string]any) (time.Duration, bool) {
	for _, key := range []string{"window_minutes", "windowMinutes"} {
		if value, ok := meta[key]; ok {
			minutes, okParse := parseQuotaFloat(value)
			if okParse && minutes > 0 {
				return time.Duration(minutes * float64(time.Minute)), true
			}
		}
	}
	return quotaWindowDurationFromName(name)
}

func quotaWindowDurationFromName(name string) (time.Duration, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return 0, false
	}
	switch name {
	case "week", "weekly", "7d":
		return 7 * 24 * time.Hour, true
	}
	duration, err := time.ParseDuration(name)
	if err != nil || duration <= 0 {
		return 0, false
	}
	return duration, true
}

func quotaWindowScoreBefore(candidate quotaWindowScore, picked quotaWindowScore) bool {
	if candidate.Score != picked.Score {
		return candidate.Score > picked.Score
	}
	if !candidate.ResetAt.Equal(picked.ResetAt) {
		return candidate.ResetAt.Before(picked.ResetAt)
	}
	return candidate.Name < picked.Name
}

func highestQuotaWindowRemainingPercent(auth *Auth, now time.Time) (float64, bool) {
	if auth == nil {
		return 0, false
	}
	windows, ok := quotaWindowsFromRuntimeMetadata(auth)
	if !ok {
		return 0, false
	}
	highest := 0.0
	found := false
	for _, raw := range windows {
		windowMeta, okMap := nestedAnyMap(raw)
		if !okMap {
			continue
		}
		resetAt, okReset := quotaWindowResetAtFromMap(windowMeta)
		if !okReset || !resetAt.After(now) {
			continue
		}
		percent, okPercent := quotaPercentFromMap(windowMeta)
		if !okPercent {
			continue
		}
		if !found || percent > highest {
			highest = percent
			found = true
		}
	}
	return highest, found
}

func quotaPercentFromMap(meta map[string]any) (float64, bool) {
	for _, key := range quotaPercentKeys {
		if value, ok := meta[key]; ok {
			if percent, ok := parseQuotaFloat(value); ok && percent >= 0 && percent <= 100 {
				return percent, true
			}
		}
	}
	for _, key := range quotaRatioKeys {
		if value, ok := meta[key]; ok {
			if ratio, ok := parseQuotaFloat(value); ok && ratio >= 0 && ratio <= 1 {
				return ratio * 100, true
			}
		}
	}
	return 0, false
}

func nestedAnyMap(value any) (map[string]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		return typed, true
	case map[string]string:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			out[key] = value
		}
		return out, true
	default:
		return nil, false
	}
}

func parseQuotaFloat(value any) (float64, bool) {
	switch typed := value.(type) {
	case string:
		raw := strings.TrimSpace(strings.TrimSuffix(typed, "%"))
		if raw == "" {
			return 0, false
		}
		parsed, err := strconv.ParseFloat(raw, 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return 0, false
		}
		return parsed, true
	case float64:
		return finiteQuotaFloat(typed)
	case float32:
		return finiteQuotaFloat(float64(typed))
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return 0, false
		}
		return finiteQuotaFloat(parsed)
	default:
		return 0, false
	}
}

func finiteQuotaFloat(value float64) (float64, bool) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, false
	}
	return value, true
}

func minimumQuotaAllowedAuthIDs(auths []*Auth, threshold float64) map[string]struct{} {
	return minimumQuotaAllowedAuthIDsAt(auths, threshold, time.Now(), 0)
}

func minimumQuotaAllowedAuthIDsAt(auths []*Auth, threshold float64, now time.Time, quotaWindow time.Duration) map[string]struct{} {
	threshold = normalizeMinimumQuotaPercent(threshold)
	if threshold <= 0 || len(auths) == 0 {
		return nil
	}
	eligible := make(map[string]struct{})
	unknown := make(map[string]struct{})
	low := make(map[string]float64)
	maxLow := -1.0
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		percent, effectiveThreshold, ok := minimumQuotaForAuth(auth, now, threshold, quotaWindow)
		if !ok {
			unknown[auth.ID] = struct{}{}
			continue
		}
		if percent >= effectiveThreshold {
			eligible[auth.ID] = struct{}{}
			continue
		}
		low[auth.ID] = percent
		if percent > maxLow {
			maxLow = percent
		}
	}
	if len(eligible) > 0 {
		for id := range unknown {
			eligible[id] = struct{}{}
		}
		return eligible
	}
	if len(low) == 0 {
		if len(unknown) > 0 {
			return unknown
		}
		return nil
	}
	allowed := make(map[string]struct{})
	for id := range unknown {
		allowed[id] = struct{}{}
	}
	for id, percent := range low {
		if percent == maxLow {
			allowed[id] = struct{}{}
		}
	}
	return allowed
}

func minimumQuotaForAuth(auth *Auth, now time.Time, threshold float64, quotaWindow time.Duration) (remainingPercent, effectiveThreshold float64, ok bool) {
	if quotaWindow > 0 {
		if score, okScore := bestQuotaWindowScore(auth, now, quotaWindow); okScore && score.Window > 0 {
			return score.RemainingPercent, scaleMinimumQuotaPercent(threshold, score.ResetIn, score.Window), true
		}
	}

	percent, okPercent := remainingQuotaPercentAt(auth, now)
	return percent, threshold, okPercent
}

func scaleMinimumQuotaPercent(threshold float64, resetIn, window time.Duration) float64 {
	threshold = normalizeMinimumQuotaPercent(threshold)
	if threshold <= 0 || resetIn <= 0 {
		return 0
	}
	if window <= 0 || resetIn >= window {
		return threshold
	}
	return threshold * float64(resetIn) / float64(window)
}

func filterAuthsByMinimumQuota(auths []*Auth, threshold float64, now time.Time, quotaWindow time.Duration) []*Auth {
	allowed := minimumQuotaAllowedAuthIDsAt(auths, threshold, now, quotaWindow)
	if allowed == nil {
		return auths
	}
	out := make([]*Auth, 0, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		if _, ok := allowed[auth.ID]; ok {
			out = append(out, auth)
		}
	}
	if len(out) == 0 {
		return auths
	}
	return out
}

func mustParseQuotaPriorityDefaultWindow() time.Duration {
	window, err := time.ParseDuration(DefaultQuotaPriorityWindowString)
	if err != nil {
		panic(fmt.Sprintf("invalid default quota priority window: %v", err))
	}
	return window
}

func normalizeQuotaPriorityWindow(window time.Duration) time.Duration {
	if window <= 0 {
		return DefaultQuotaPriorityWindow
	}
	return window
}

func ParseQuotaPriorityWindow(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultQuotaPriorityWindow, nil
	}
	window, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	if window <= 0 {
		return 0, fmt.Errorf("duration must be greater than zero")
	}
	return window, nil
}

func quotaPriorityCandidateBefore(candidate *Auth, candidateWindow quotaWindowScore, picked *Auth, pickedWindow quotaWindowScore) bool {
	if picked == nil {
		return true
	}
	if candidateWindow.Score != pickedWindow.Score {
		return candidateWindow.Score > pickedWindow.Score
	}
	if !candidateWindow.ResetAt.Equal(pickedWindow.ResetAt) {
		return candidateWindow.ResetAt.Before(pickedWindow.ResetAt)
	}
	return candidate.ID < picked.ID
}

func pickQuotaPriorityAuth(auths []*Auth, now time.Time, window time.Duration) (*Auth, bool) {
	var picked *Auth
	var pickedWindow quotaWindowScore
	for i := 0; i < len(auths); i++ {
		candidate := auths[i]
		windowScore, ok := bestQuotaWindowScore(candidate, now, window)
		if !ok {
			continue
		}
		if quotaPriorityCandidateBefore(candidate, windowScore, picked, pickedWindow) {
			picked = candidate
			pickedWindow = windowScore
		}
	}
	return picked, picked != nil
}

func quotaPrioritySelectionScore(auth *Auth, now time.Time, window time.Duration) (float64, bool, time.Duration, bool) {
	windowScore, ok := bestQuotaWindowScore(auth, now, window)
	if !ok {
		return 0, false, 0, false
	}
	return windowScore.Score, true, windowScore.ResetIn, true
}

func formatAuthSelectionCandidates(auths []*Auth, now time.Time, window time.Duration) string {
	if len(auths) == 0 {
		return "[]"
	}
	limit := len(auths)
	if limit > selectionCandidateLogLimit {
		limit = selectionCandidateLogLimit
	}
	parts := make([]string, 0, limit+1)
	for i := 0; i < limit; i++ {
		auth := auths[i]
		if auth == nil {
			parts = append(parts, "{auth=<nil>}")
			continue
		}
		quota := "unknown"
		if percent, ok := remainingQuotaPercentAt(auth, now); ok {
			quota = fmt.Sprintf("%.2f", percent)
		}
		winningWindow := "none"
		resetIn := "unknown"
		score := "n/a"
		if windowScore, ok := bestQuotaWindowScore(auth, now, window); ok {
			winningWindow = windowScore.Name
			resetIn = windowScore.ResetIn.Round(time.Second).String()
			quota = fmt.Sprintf("%.2f", windowScore.RemainingPercent)
			score = fmt.Sprintf("%.6f", windowScore.Score)
		}
		parts = append(parts, fmt.Sprintf("{auth=%s winning_window=%s reset_in=%s quota_percent=%s multiplier=%.2f score=%s}",
			auth.ID, winningWindow, resetIn, quota, quotaCapacityMultiplier(auth), score))
	}
	if len(auths) > limit {
		parts = append(parts, fmt.Sprintf("...+%d", len(auths)-limit))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func quotaPrioritySelectedLogFields(auth *Auth, now time.Time, window time.Duration) (string, string, string, string, string) {
	if auth == nil {
		return "none", "unknown", "unknown", "n/a", "1.00"
	}
	quota := "unknown"
	if percent, ok := remainingQuotaPercentAt(auth, now); ok {
		quota = fmt.Sprintf("%.2f", percent)
	}
	winningWindow := "none"
	resetIn := "unknown"
	score := "n/a"
	multiplier := fmt.Sprintf("%.2f", quotaCapacityMultiplier(auth))
	if windowScore, ok := bestQuotaWindowScore(auth, now, window); ok {
		winningWindow = windowScore.Name
		resetIn = windowScore.ResetIn.Round(time.Second).String()
		quota = fmt.Sprintf("%.2f", windowScore.RemainingPercent)
		score = fmt.Sprintf("%.6f", windowScore.Score)
		multiplier = fmt.Sprintf("%.2f", windowScore.Multiplier)
	}
	return winningWindow, resetIn, quota, score, multiplier
}

// Pick selects the next available auth for the provider in a round-robin manner.
func (s *RoundRobinSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	available, err := getSelectableAuths(ctx, auths, provider, model, now, s.MinimumQuotaPercent, 0)
	if err != nil {
		return nil, err
	}
	return s.pickAvailable(ctx, provider, model, available, s.MinimumQuotaPercent)
}

func (s *RoundRobinSelector) pickAvailable(ctx context.Context, provider, model string, available []*Auth, minimumQuotaPercent float64) (*Auth, error) {
	if len(available) == 0 {
		return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	key := provider + ":" + canonicalModelKey(model)
	s.mu.Lock()
	if s.cursors == nil {
		s.cursors = make(map[string]int)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = 4096
	}

	s.ensureCursorKey(key, limit)
	index := s.cursors[key]
	if index >= 2_147_483_640 {
		index = 0
	}
	s.cursors[key] = index + 1
	s.mu.Unlock()
	selected := available[index%len(available)]
	selectorLogEntry(ctx).Infof("routing selector: selected | strategy=round-robin auth=%s provider=%s model=%s selectable=%d cursor=%d minimum_quota_percent=%.2f",
		selected.ID, provider, model, len(available), index, normalizeMinimumQuotaPercent(minimumQuotaPercent))
	return selected, nil
}

// ensureCursorKey ensures the cursor map has capacity for the given key.
// Must be called with s.mu held.
func (s *RoundRobinSelector) ensureCursorKey(key string, limit int) {
	if _, ok := s.cursors[key]; !ok && len(s.cursors) >= limit {
		s.cursors = make(map[string]int)
	}
}

func positiveWeightAuths(auths []*Auth) []*Auth {
	weightedCandidates := make([]*Auth, 0, len(auths))
	for _, auth := range auths {
		if authWeight(auth) > 0 {
			weightedCandidates = append(weightedCandidates, auth)
		}
	}
	return weightedCandidates
}

// Pick selects the next available auth using smooth weighted round-robin.
func (s *WeightedRoundRobinSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	available, errAvailable := getAvailableAuths(positiveWeightAuths(auths), provider, model, time.Now(), 0)
	if errAvailable != nil {
		return nil, errAvailable
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	stateModel := weightedSelectorStateModel(ctx, model)
	key := provider + ":" + canonicalModelKey(stateModel)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states == nil {
		s.states = make(map[string]*smoothWeightedState)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = 4096
	}
	if _, ok := s.states[key]; !ok && len(s.states) >= limit {
		s.states = make(map[string]*smoothWeightedState)
	}
	state := s.states[key]
	if state == nil {
		state = &smoothWeightedState{}
		s.states[key] = state
	}
	weights := authWeightVector(available)
	state.prepare(weights)
	picked := pickSmoothWeightedAuth(available, state.current)
	if picked == nil {
		return nil, &Error{Code: "auth_unavailable", Message: "no auth available with positive weight"}
	}
	return picked, nil
}

func (s *smoothWeightedState) prepare(weights map[string]int64) {
	if s.current == nil || !weightVectorsEqual(s.weights, weights) {
		s.current = make(map[string]int64)
	}
	s.weights = weights
}

func weightVectorsEqual(left, right map[string]int64) bool {
	if len(left) != len(right) {
		return false
	}
	for authID, weight := range left {
		if right[authID] != weight {
			return false
		}
	}
	return true
}

func authWeightVector(auths []*Auth) map[string]int64 {
	weights := make(map[string]int64, len(auths))
	for _, auth := range auths {
		if auth != nil {
			if weight := authWeight(auth); weight > 0 {
				weights[auth.ID] = weight
			}
		}
	}
	return weights
}

func pickSmoothWeightedAuth(auths []*Auth, current map[string]int64) *Auth {
	active := make(map[string]struct{}, len(auths))
	var picked *Auth
	var pickedCurrent int64
	var totalWeight int64
	for _, auth := range auths {
		weight := authWeight(auth)
		if auth == nil || weight <= 0 {
			continue
		}
		active[auth.ID] = struct{}{}
		current[auth.ID] = saturatingAddInt64(current[auth.ID], weight)
		totalWeight = saturatingAddInt64(totalWeight, weight)
		if picked == nil || current[auth.ID] > pickedCurrent {
			picked = auth
			pickedCurrent = current[auth.ID]
		}
	}
	for authID := range current {
		if _, ok := active[authID]; !ok {
			delete(current, authID)
		}
	}
	if picked == nil {
		return nil
	}
	current[picked.ID] = saturatingAddInt64(current[picked.ID], -totalWeight)
	return picked
}

func saturatingAddInt64(value, delta int64) int64 {
	if delta > 0 && value > math.MaxInt64-delta {
		return math.MaxInt64
	}
	if delta < 0 && value < math.MinInt64-delta {
		return math.MinInt64
	}
	return value + delta
}

// Pick selects the first available auth for the provider in a deterministic manner.
func (s *FillFirstSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	available, err := getSelectableAuths(ctx, auths, provider, model, now, s.MinimumQuotaPercent, 0)
	if err != nil {
		return nil, err
	}
	selected := available[0]
	selectorLogEntry(ctx).Infof("routing selector: selected | strategy=fill-first auth=%s provider=%s model=%s selectable=%d minimum_quota_percent=%.2f",
		selected.ID, provider, model, len(available), normalizeMinimumQuotaPercent(s.MinimumQuotaPercent))
	return selected, nil
}

func NewQuotaPrioritySelector(window time.Duration) *QuotaPrioritySelector {
	return &QuotaPrioritySelector{Window: normalizeQuotaPriorityWindow(window)}
}

func (s *QuotaPrioritySelector) quotaPriorityWindow() time.Duration {
	if s == nil {
		return DefaultQuotaPriorityWindow
	}
	return normalizeQuotaPriorityWindow(s.Window)
}

func (s *QuotaPrioritySelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	now := time.Now()
	quotaWindow := s.quotaPriorityWindow()
	available, err := getSelectableAuths(ctx, auths, provider, model, now, s.MinimumQuotaPercent, quotaWindow)
	if err != nil {
		return nil, err
	}
	if picked, ok := pickQuotaWarmupAuth(available, now, quotaWindow); ok {
		winningWindow, resetIn, quota, score, multiplier := quotaPrioritySelectedLogFields(picked, now, quotaWindow)
		selectorLogEntry(ctx).Infof("routing selector: selected | strategy=quota-priority reason=quota-warmup auth=%s provider=%s model=%s selectable=%d winning_window=%s reset_in=%s quota_percent=%s score=%s plan_multiplier=%s probe_cooldown=%s minimum_quota_percent=%.2f",
			picked.ID, provider, model, len(available), winningWindow, resetIn, quota, score, multiplier, quotaWarmupInFlightCooldown, normalizeMinimumQuotaPercent(s.MinimumQuotaPercent))
		return picked, nil
	}
	if picked, ok := pickQuotaPriorityAuth(available, now, quotaWindow); ok {
		winningWindow, resetIn, quota, score, multiplier := quotaPrioritySelectedLogFields(picked, now, quotaWindow)
		selectorLogEntry(ctx).Infof("routing selector: selected | strategy=quota-priority reason=quota-window auth=%s provider=%s model=%s selectable=%d winning_window=%s reset_in=%s quota_percent=%s score=%s plan_multiplier=%s minimum_quota_percent=%.2f",
			picked.ID, provider, model, len(available), winningWindow, resetIn, quota, score, multiplier, normalizeMinimumQuotaPercent(s.MinimumQuotaPercent))
		return picked, nil
	}
	entry := selectorLogEntry(ctx)
	if entry.Logger.IsLevelEnabled(log.DebugLevel) {
		entry.Debugf("routing selector: no quota-priority candidates, falling back to round-robin | provider=%s model=%s selectable=%d quota_priority_window=%s auths=%s",
			provider, model, len(available), quotaWindow, formatAuthSelectionCandidates(available, now, quotaWindow))
	}
	return (&s.roundRobin).pickAvailable(ctx, provider, model, available, s.MinimumQuotaPercent)
}

func isAuthBlockedForModel(auth *Auth, model string, now time.Time) (bool, blockReason, time.Time) {
	if auth == nil {
		return true, blockReasonOther, time.Time{}
	}
	if auth.Disabled || auth.Status == StatusDisabled {
		return true, blockReasonDisabled, time.Time{}
	}
	if model != "" {
		if len(auth.ModelStates) > 0 {
			modelKey := canonicalModelKey(model)
			matched := false
			blocked := false
			blockedReason := blockReasonNone
			nextRetry := time.Time{}
			for stateModel, state := range auth.ModelStates {
				if state == nil || canonicalModelKey(stateModel) != modelKey {
					continue
				}
				matched = true
				if state.Status == StatusDisabled {
					return true, blockReasonDisabled, time.Time{}
				}
				stateBlocked, reason, next := availabilityBlock(state.Unavailable, state.Quota.Exceeded, state.NextRetryAfter, state.Quota.NextRecoverAt, now)
				if !stateBlocked {
					continue
				}
				if next.IsZero() {
					return true, reason, time.Time{}
				}
				if !blocked || next.After(nextRetry) || (next.Equal(nextRetry) && reason == blockReasonCooldown) {
					blocked = true
					blockedReason = reason
					nextRetry = next
				}
			}
			if matched {
				return blocked, blockedReason, nextRetry
			}
			// Auth-level availability can aggregate failures from other models.
			return false, blockReasonNone, time.Time{}
		}
		return availabilityBlock(auth.Unavailable, auth.Quota.Exceeded, auth.NextRetryAfter, auth.Quota.NextRecoverAt, now)
	}
	return availabilityBlock(auth.Unavailable, auth.Quota.Exceeded, auth.NextRetryAfter, auth.Quota.NextRecoverAt, now)
}

func availabilityBlock(unavailable, quotaExceeded bool, nextRetryAfter, nextRecoverAt, now time.Time) (bool, blockReason, time.Time) {
	if !unavailable && !quotaExceeded {
		return false, blockReasonNone, time.Time{}
	}

	hasRecoveryTime := !nextRetryAfter.IsZero() || !nextRecoverAt.IsZero()
	var next time.Time
	for _, candidate := range []time.Time{nextRetryAfter, nextRecoverAt} {
		if candidate.After(now) && (next.IsZero() || candidate.After(next)) {
			next = candidate
		}
	}
	if !next.IsZero() {
		if quotaExceeded {
			return true, blockReasonCooldown, next
		}
		return true, blockReasonOther, next
	}
	if hasRecoveryTime {
		return false, blockReasonNone, time.Time{}
	}
	return true, blockReasonOther, time.Time{}
}

// SessionAffinitySelector wraps another selector with session-sticky behavior.
// It extracts session ID from multiple sources and maintains session-to-auth
// mappings with automatic failover when the bound auth becomes unavailable.
type SessionAffinitySelector struct {
	fallback Selector
	cache    *SessionCache
}

// SessionAffinityConfig configures the session affinity selector.
type SessionAffinityConfig struct {
	Fallback Selector
	TTL      time.Duration
}

// NewSessionAffinitySelector creates a new session-aware selector.
func NewSessionAffinitySelector(fallback Selector) *SessionAffinitySelector {
	return NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: fallback,
		TTL:      time.Hour,
	})
}

// NewSessionAffinitySelectorWithConfig creates a selector with custom configuration.
func NewSessionAffinitySelectorWithConfig(cfg SessionAffinityConfig) *SessionAffinitySelector {
	if cfg.Fallback == nil {
		cfg.Fallback = &RoundRobinSelector{}
	}
	if cfg.TTL <= 0 {
		cfg.TTL = time.Hour
	}
	return &SessionAffinitySelector{
		fallback: cfg.Fallback,
		cache:    NewSessionCache(cfg.TTL),
	}
}

// Pick selects an auth with session affinity when possible.
// Explicit Claude Code, Codex, OpenCode, pi, and request-body session signals
// precede execution metadata, stable derived identity, and the legacy hash fallback.
//
// An established binding outranks credential priority: a bound credential that is still
// available is reused even when a higher-priority credential recovers. Credential priority
// applies to cold bindings, requests without a session, and genuine bound-credential
// failover, so the fallback selector only ever receives the highest available priority tier.
//
// Note: The cache key includes provider, session ID, and model to handle cases where
// a session uses multiple models (e.g., gemini-2.5-pro and gemini-3-flash-preview)
// that may be supported by different auth credentials, and to avoid cross-provider conflicts.
func (s *SessionAffinitySelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	entry := selectorLogEntry(ctx)
	primaryID, fallbackID := extractSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
	now := time.Now()
	quotaWindow, _ := selectorQuotaPriorityExhaustionWindow(s.fallback)
	availabilityCandidates := auths
	if _, weighted := s.fallback.(*WeightedRoundRobinSelector); weighted {
		availabilityCandidates = positiveWeightAuths(auths)
	}
	if primaryID == "" {
		fallbackAuths, errAvailable := getSelectableAuths(ctx, availabilityCandidates, provider, model, now, selectorMinimumQuotaPercent(s.fallback), quotaWindow)
		if errAvailable != nil {
			return nil, errAvailable
		}
		entry.Debugf("session-affinity: no session ID extracted, falling back to default selector | provider=%s model=%s", provider, model)
		return s.fallback.Pick(ctx, provider, model, opts, fallbackAuths)
	}

	// A single availability pass serves both lookups: the bound credential is validated against
	// every priority tier, while the fallback selector keeps seeing only the highest tier.
	available, err := getSelectableAuthsWithPriorityMode(ctx, availabilityCandidates, provider, model, now, selectorMinimumQuotaPercent(s.fallback), quotaWindow, true)
	if err != nil {
		return nil, err
	}
	fallbackAuths := highestPriorityAuths(available)

	cacheKey := provider + "::" + primaryID + "::" + model
	fallbackKey := ""
	if fallbackID != "" && fallbackID != primaryID {
		fallbackKey = provider + "::" + fallbackID + "::" + model
	}
	bind := func(authID string) {
		if fallbackKey != "" {
			s.cache.SetAliases(authID, cacheKey, fallbackKey)
			return
		}
		s.cache.Set(cacheKey, authID)
	}

	if cachedAuthID, ok := s.cache.GetAndRefresh(cacheKey); ok {
		for _, auth := range available {
			if auth.ID == cachedAuthID {
				bind(auth.ID)
				entry.Infof("session-affinity: cache hit | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), auth.ID, provider, model)
				return auth, nil
			}
		}
		if entry.Logger.IsLevelEnabled(log.DebugLevel) {
			entry.Debugf("session-affinity: cached auth not selectable | session=%s cached_auth=%s provider=%s model=%s selectable=%d minimum_quota_percent=%.2f selectable_auths=%s",
				truncateSessionID(primaryID), cachedAuthID, provider, model, len(available), selectorMinimumQuotaPercent(s.fallback), formatAuthSelectionCandidates(available, now, quotaWindow))
		}
		// Cached auth not selectable, reselect via fallback selector for even distribution.
		auth, err := s.fallback.Pick(ctx, provider, model, opts, fallbackAuths)
		if err != nil {
			return nil, err
		}
		if isQuotaWarmupProbeSelection(auth, now, quotaWindow) {
			entry.Infof("session-affinity: skipped cache for quota warmup | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), auth.ID, provider, model)
			return auth, nil
		}
		bind(auth.ID)
		entry.Infof("session-affinity: cache hit but auth not selectable, reselected | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), auth.ID, provider, model)
		return auth, nil
	}

	if fallbackKey != "" {
		if cachedAuthID, ok := s.cache.Get(fallbackKey); ok {
			for _, auth := range available {
				if auth.ID == cachedAuthID {
					bind(auth.ID)
					entry.Infof("session-affinity: fallback cache hit | session=%s fallback=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), truncateSessionID(fallbackID), auth.ID, provider, model)
					return auth, nil
				}
			}
		}
	}

	auth, err := s.fallback.Pick(ctx, provider, model, opts, fallbackAuths)
	if err != nil {
		return nil, err
	}
	if isQuotaWarmupProbeSelection(auth, now, quotaWindow) {
		entry.Infof("session-affinity: skipped cache for quota warmup | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), auth.ID, provider, model)
		return auth, nil
	}
	bind(auth.ID)
	entry.Infof("session-affinity: cache miss, new binding | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), auth.ID, provider, model)
	return auth, nil
}

func selectorLogEntry(ctx context.Context) *log.Entry {
	if ctx == nil {
		return log.NewEntry(log.StandardLogger())
	}
	if reqID := logging.GetRequestID(ctx); reqID != "" {
		return log.WithField("request_id", reqID)
	}
	return log.NewEntry(log.StandardLogger())
}

// truncateSessionID shortens session ID for logging (first 8 chars + "...")
func truncateSessionID(id string) string {
	if len(id) <= 20 {
		return id
	}
	return id[:8] + "..."
}

// Stop releases resources held by the selector.
func (s *SessionAffinitySelector) Stop() {
	if s.cache != nil {
		s.cache.Stop()
	}
}

// InvalidateAuth removes all session bindings for a specific auth.
// Called when an auth becomes rate-limited or unavailable.
func (s *SessionAffinitySelector) InvalidateAuth(authID string) {
	if s.cache != nil {
		s.cache.InvalidateAuth(authID)
	}
}

// normalizedSessionCandidate validates an explicit client-provided session signal.
// It keeps opaque printable IDs intact while rejecting values that are unsafe or
// implausibly large for routing keys and logs.
func normalizedSessionCandidate(raw string) string {
	return cliproxysession.NormalizeExplicitID(raw)
}

func sessionHeaderValue(headers http.Header, name string) string {
	if headers == nil {
		return ""
	}
	if value := normalizedSessionCandidate(headers.Get(name)); value != "" {
		return value
	}
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, raw := range values {
			if value := normalizedSessionCandidate(raw); value != "" {
				return value
			}
		}
	}
	return ""
}

// ExtractSessionID extracts a session identifier from explicit client signals,
// then falls back to execution metadata, derived identity, and message history.
func ExtractSessionID(headers http.Header, payload []byte, metadata map[string]any) string {
	primary, _ := extractSessionIDs(headers, payload, metadata)
	return primary
}

// extractSessionIDs returns (primaryID, fallbackID) for session affinity.
// fallbackID preserves an earlier binding when a stronger body identifier appears
// later, and lets callers bind both identifiers when both are present.
func extractSessionIDs(headers http.Header, payload []byte, metadata map[string]any) (string, string) {
	if sid := sessionHeaderValue(headers, "X-Claude-Code-Session-Id"); sid != "" {
		return "claude:" + sid, ""
	}
	if sid := cliproxysession.ClaudeMetadataSessionID(payload); sid != "" {
		return "claude:" + sid, ""
	}
	if sid := sessionHeaderValue(headers, "Session-Id"); sid != "" {
		return "codex:" + sid, ""
	}
	if sid := sessionHeaderValue(headers, "Session_id"); sid != "" {
		return "codex:" + sid, ""
	}
	if sid := sessionHeaderValue(headers, "X-Session-ID"); sid != "" {
		return "header:" + sid, ""
	}
	if sid := sessionHeaderValue(headers, "X-Session-Affinity"); sid != "" {
		return "affinity:" + sid, ""
	}
	if sid := sessionHeaderValue(headers, "X-Client-Request-Id"); sid != "" {
		return "clientreq:" + sid, ""
	}

	if len(payload) > 0 {
		for _, path := range []string{"session_id", "sessionId"} {
			if sid := normalizedSessionCandidate(gjson.GetBytes(payload, path).String()); sid != "" {
				return "session:" + sid, ""
			}
		}

		conversationID := ""
		conversation := gjson.GetBytes(payload, "conversation")
		if sid := normalizedSessionCandidate(conversation.Get("id").String()); sid != "" {
			conversationID = "conv:" + sid
		} else if conversation.Type == gjson.String {
			if sid := normalizedSessionCandidate(conversation.String()); sid != "" {
				conversationID = "conv:" + sid
			}
		}
		if sid := normalizedSessionCandidate(gjson.GetBytes(payload, "prompt_cache_key").String()); sid != "" {
			return "pck:" + sid, conversationID
		}
		if conversationID != "" {
			return conversationID, ""
		}

		if userID := normalizedSessionCandidate(gjson.GetBytes(payload, "metadata.user_id").String()); userID != "" {
			return "user:" + userID, ""
		}
		if conversationID := normalizedSessionCandidate(gjson.GetBytes(payload, "conversation_id").String()); conversationID != "" {
			return "conv:" + conversationID, ""
		}
	}

	if executionID, ok := metadata[cliproxyexecutor.ExecutionSessionMetadataKey].(string); ok {
		if executionID = normalizedSessionCandidate(executionID); executionID != "" {
			return "execution:" + executionID, ""
		}
	}
	if derivedID := normalizedSessionCandidate(cliproxysession.DerivedID(metadata)); derivedID != "" {
		return "derived:" + derivedID, ""
	}
	if len(payload) == 0 {
		return "", ""
	}
	return extractMessageHashIDs(payload)
}

func extractMessageHashIDs(payload []byte) (primaryID, fallbackID string) {
	var systemPrompt, firstUserMsg, firstAssistantMsg string

	// OpenAI/Claude messages format
	messages := gjson.GetBytes(payload, "messages")
	if messages.Exists() && messages.IsArray() {
		messages.ForEach(func(_, msg gjson.Result) bool {
			role := msg.Get("role").String()
			content := extractMessageContent(msg.Get("content"))
			if content == "" {
				return true
			}

			switch role {
			case "system":
				if systemPrompt == "" {
					systemPrompt = truncateString(content, 100)
				}
			case "user":
				if firstUserMsg == "" {
					firstUserMsg = truncateString(content, 100)
				}
			case "assistant":
				if firstAssistantMsg == "" {
					firstAssistantMsg = truncateString(content, 100)
				}
			}

			if systemPrompt != "" && firstUserMsg != "" && firstAssistantMsg != "" {
				return false
			}
			return true
		})
	}

	// Claude API: top-level "system" field (array or string)
	if systemPrompt == "" {
		topSystem := gjson.GetBytes(payload, "system")
		if topSystem.Exists() {
			if topSystem.IsArray() {
				topSystem.ForEach(func(_, part gjson.Result) bool {
					if text := part.Get("text").String(); text != "" && systemPrompt == "" {
						systemPrompt = truncateString(text, 100)
						return false
					}
					return true
				})
			} else if topSystem.Type == gjson.String {
				systemPrompt = truncateString(topSystem.String(), 100)
			}
		}
	}

	// Gemini format
	if systemPrompt == "" && firstUserMsg == "" {
		sysInstr := gjson.GetBytes(payload, "systemInstruction.parts")
		if sysInstr.Exists() && sysInstr.IsArray() {
			sysInstr.ForEach(func(_, part gjson.Result) bool {
				if text := part.Get("text").String(); text != "" && systemPrompt == "" {
					systemPrompt = truncateString(text, 100)
					return false
				}
				return true
			})
		}

		contents := gjson.GetBytes(payload, "contents")
		if contents.Exists() && contents.IsArray() {
			contents.ForEach(func(_, msg gjson.Result) bool {
				role := msg.Get("role").String()
				msg.Get("parts").ForEach(func(_, part gjson.Result) bool {
					text := part.Get("text").String()
					if text == "" {
						return true
					}
					switch role {
					case "user":
						if firstUserMsg == "" {
							firstUserMsg = truncateString(text, 100)
						}
					case "model":
						if firstAssistantMsg == "" {
							firstAssistantMsg = truncateString(text, 100)
						}
					}
					return false
				})
				if firstUserMsg != "" && firstAssistantMsg != "" {
					return false
				}
				return true
			})
		}
	}

	// OpenAI Responses API format (v1/responses)
	if systemPrompt == "" && firstUserMsg == "" {
		if instr := gjson.GetBytes(payload, "instructions").String(); instr != "" {
			systemPrompt = truncateString(instr, 100)
		}

		input := gjson.GetBytes(payload, "input")
		if input.Exists() && input.IsArray() {
			input.ForEach(func(_, item gjson.Result) bool {
				itemType := item.Get("type").String()
				if itemType == "reasoning" {
					return true
				}
				// Skip non-message typed items (function_call, function_call_output, etc.)
				// but allow items with no type that have a role (inline message format).
				if itemType != "" && itemType != "message" {
					return true
				}

				role := item.Get("role").String()
				if itemType == "" && role == "" {
					return true
				}

				// Handle both string content and array content (multimodal).
				content := item.Get("content")
				var text string
				if content.Type == gjson.String {
					text = content.String()
				} else {
					text = extractResponsesAPIContent(content)
				}
				if text == "" {
					return true
				}

				switch role {
				case "developer", "system":
					if systemPrompt == "" {
						systemPrompt = truncateString(text, 100)
					}
				case "user":
					if firstUserMsg == "" {
						firstUserMsg = truncateString(text, 100)
					}
				case "assistant":
					if firstAssistantMsg == "" {
						firstAssistantMsg = truncateString(text, 100)
					}
				}

				if firstUserMsg != "" && firstAssistantMsg != "" {
					return false
				}
				return true
			})
		}
	}

	if systemPrompt == "" && firstUserMsg == "" {
		return "", ""
	}

	shortHash := computeSessionHash(systemPrompt, firstUserMsg, "")
	if firstAssistantMsg == "" {
		return shortHash, ""
	}

	fullHash := computeSessionHash(systemPrompt, firstUserMsg, firstAssistantMsg)
	return fullHash, shortHash
}

func computeSessionHash(systemPrompt, userMsg, assistantMsg string) string {
	h := fnv.New64a()
	if systemPrompt != "" {
		h.Write([]byte("sys:" + systemPrompt + "\n"))
	}
	if userMsg != "" {
		h.Write([]byte("usr:" + userMsg + "\n"))
	}
	if assistantMsg != "" {
		h.Write([]byte("ast:" + assistantMsg + "\n"))
	}
	return fmt.Sprintf("msg:%016x", h.Sum64())
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

// extractMessageContent extracts text content from a message content field.
// Handles both string content and array content (multimodal messages).
// For array content, extracts text from all text-type elements.
func extractMessageContent(content gjson.Result) string {
	// String content: "Hello world"
	if content.Type == gjson.String {
		return content.String()
	}

	// Array content: [{"type":"text","text":"Hello"},{"type":"image",...}]
	if content.IsArray() {
		var texts []string
		content.ForEach(func(_, part gjson.Result) bool {
			// Handle Claude format: {"type":"text","text":"content"}
			if part.Get("type").String() == "text" {
				if text := part.Get("text").String(); text != "" {
					texts = append(texts, text)
				}
			}
			// Handle OpenAI format: {"type":"text","text":"content"}
			// Same structure as Claude, already handled above
			return true
		})
		if len(texts) > 0 {
			return strings.Join(texts, " ")
		}
	}

	return ""
}

func extractResponsesAPIContent(content gjson.Result) string {
	if !content.IsArray() {
		return ""
	}
	var texts []string
	content.ForEach(func(_, part gjson.Result) bool {
		partType := part.Get("type").String()
		if partType == "input_text" || partType == "output_text" || partType == "text" {
			if text := part.Get("text").String(); text != "" {
				texts = append(texts, text)
			}
		}
		return true
	})
	if len(texts) > 0 {
		return strings.Join(texts, " ")
	}
	return ""
}

// extractSessionID is kept for backward compatibility.
// Deprecated: Use ExtractSessionID instead.
func extractSessionID(payload []byte) string {
	return ExtractSessionID(nil, payload, nil)
}
