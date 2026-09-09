package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"net/http"
	"regexp"
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

const DefaultQuotaReservePercent = 0.0
const quotaPriorityScoreMinMinutes = 1.0
const quotaWarmupInFlightCooldown = 2 * time.Minute
const quotaWarmupMissingHeadersCooldown = time.Minute
const selectionCandidateLogLimit = 12
const quotaWindowsMetadataKey = "quota_windows"
const quotaProbeAfterMetadataKey = "quota_probe_after"

// RoundRobinSelector provides a simple provider scoped round-robin selection strategy.
//
// Rotation continues from the identity of the previous pick rather than from a numeric
// index. Candidate slices shrink whenever a retry excludes already tried credentials or a
// credential enters cooldown, and indexing a monotonic counter into a shrinking slice
// silently re-seats the rotation, which starves some credentials and hammers others.
type RoundRobinSelector struct {
	mu                  sync.Mutex
	lastPicked          map[string]string
	maxKeys             int
	QuotaReservePercent float64
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
	QuotaReservePercent float64
}

// QuotaPrioritySelector prioritizes credentials with quota window metadata.
// Selection uses the highest spendable-quota-per-reset-minute score from
// runtime quota_windows observed from upstream response headers. Global and
// per-account weekly reserves are excluded from the spendable quota before scoring.
// If no credential has scoreable quota window data, selection falls back to round-robin.
type QuotaPrioritySelector struct {
	Window              time.Duration
	QuotaReservePercent float64
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
	cause    error
}

// NewModelCooldownError creates an error representing model-level cooldown.
func NewModelCooldownError(model, provider string, resetIn time.Duration) error {
	return newModelCooldownErrorWithCause(model, provider, resetIn, nil)
}

func newModelCooldownError(model, provider string, resetIn time.Duration) *modelCooldownError {
	return newModelCooldownErrorWithCause(model, provider, resetIn, nil)
}

func newModelCooldownErrorWithCause(model, provider string, resetIn time.Duration, cause error) *modelCooldownError {
	if resetIn < 0 {
		resetIn = 0
	}
	return &modelCooldownError{
		model:    model,
		provider: provider,
		resetIn:  resetIn,
		cause:    cause,
	}
}

func (e *modelCooldownError) IsModelCooldown() bool {
	return true
}

func (e *modelCooldownError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
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
	if e.cause != nil {
		if causeText := ExtractUpstreamErrorSummary(e.cause.Error()); causeText != "" {
			errorBody["last_upstream_error"] = causeText
			message += fmt.Sprintf(" (last error: %s)", causeText)
			errorBody["message"] = message
		}
	}
	payload := map[string]any{"error": errorBody}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf(`{"error":{"code":"model_cooldown","message":"%s"}}`, message)
	}
	return string(data)
}

var (
	sanitizerSchemeAuthPattern             = regexp.MustCompile(`(?i)((?:[A-Za-z0-9.+_\-]+:)?//)(?:[^:\s/@]+:[^@\s]+|[^@\s/]+)@`)
	sanitizerQueryParamPattern             = regexp.MustCompile(`(?i)([?&][A-Za-z0-9_.-]*(?:key|token|secret|password|auth|sig|signature)=)[^&\s,\r\n;]+`)
	sanitizerCookiePattern                 = regexp.MustCompile(`(?i)\b(?:set-)?cookie\s*:[^\r\n]+`)
	sanitizerAuthHeaderPattern             = regexp.MustCompile(`(?i)\bauthorization\s*[:=]\s*[^\r\n]+`)
	sanitizerNaturalSecretPattern          = regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]*(?:api[ _-]?key|access[ _-]?token|client[ _-]?secret|private[ _-]?key|secret[ _-]?key|password|secret|token|credentials?|sessionid))\s*(?:(?:is|was|provided|used)?\s*[:= ]\s*|\s+is\s+|\s+was\s+|\s+provided\s+|\s+)(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|(?:[^\r\n;,|]+?(?:\s+(?:and|with|for|via)\s+|[,;|]|\r|\n|$)|[^\r\n;,|]+))`)
	sanitizerKVPattern                     = regexp.MustCompile(`(?i)((?:'|")?(?:[A-Za-z0-9_.-]*(?:key|token|secret|password|credential|credentials|bearer|sessionid|auth|signature|sig))(?:'|")?\s*[=:]\s*)(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|(?:[^\r\n;,|]+?(?:\s+(?:and|with|for|via)\s+|[,;|]|\r|\n|$)|[^\r\n;,|]+))`)
	sanitizerInvalidTokenPattern           = regexp.MustCompile(`(?i)\b(invalid|bad|expired|unknown)\s+(?:api\s+key|access\s+token|refresh\s+token|token|key|secret|password|credentials?|bearer)\s*(?:[:= ]\s*)?(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,\r\n;]+)`)
	sanitizerSKKeyPattern                  = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9._~+/=-]{6,}|ghp_[A-Za-z0-9._~+/=-]{6,})\b`)
	sanitizerBearerPattern                 = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+`)
	sanitizerDoubleQuotedPathPattern       = regexp.MustCompile(`"/[^"\r\n]+"`)
	sanitizerSingleQuotedPathPattern       = regexp.MustCompile(`'/[^'\r\n]+'`)
	sanitizerBacktickQuotedPathPattern     = regexp.MustCompile("`/[^`\r\n]+`")
	sanitizerPathConnectorPattern          = regexp.MustCompile(`(?i)\s+(to|from|into|onto|for|via|with|and)\s+/`)
	sanitizerUnixPathBeforeColonPattern    = regexp.MustCompile(`(^|[\s\(\[\{<"';,=])(/(?:[^/\s\r\n"',;?#()<>{}\[\]]+(?:\s+[^/\s\r\n"',;?#()<>{}\[\]]+)*/)*[^/:\s\r\n"',;?#()<>{}\[\]]+(?:\s+[^/:\s\r\n"',;?#()<>{}\[\]]+)*):\s+[A-Za-z0-9]`)
	sanitizerUnixPathBeforeNextPathPattern = regexp.MustCompile(`(^|[\s\(\[\{<"';,=])(/(?:[^/\s\r\n"',;?#()<>{}\[\]]+(?:\s+[^/\s\r\n"',;?#()<>{}\[\]]+)*/)*[^/:\s\r\n"',;?#()<>{}\[\]]+(?::[^/\s\r\n"',;?#()<>{}\[\]]+|\s+[^/:\s\r\n"',;?#()<>{}\[\]]+)*)(\s+/)`)
	sanitizerUnixPathStandardPattern       = regexp.MustCompile(`(^|[\s\(\[\{<"';,=])(/(?:[^/\s\r\n"',;?#()<>{}\[\]]+(?:\s+[^/\s\r\n"',;?#()<>{}\[\]]+)*/)*[^/:\s\r\n"',;?#()<>{}\[\]]+(?::[^/:\s\r\n"',;?#()<>{}\[\]]+)?)`)
	sanitizerFileExtPathPattern            = regexp.MustCompile(`(^|[\s"'` + "`" + `(\[,;=])(/[^\s:\r\n"'` + "`" + `,;\])>]+(?:\s+[^\s:\r\n"'` + "`" + `,;\])>]+)*\.(?:json|yaml|yml|key|pem|txt|log|toml|conf|env|crt|cer))`)
	sanitizerWindowsPathPattern            = regexp.MustCompile(`(?i)\b[A-Za-z]:\\[^\r\n:,;'"<>]+`)
	sanitizerWindowsUNCPathPattern         = regexp.MustCompile(`\\\\[^\r\n:,;'"<>]+\\[^\r\n:,;'"<>]+`)
)

// ExtractUpstreamErrorSummary extracts and sanitizes a concise error summary from upstream error strings.
func ExtractUpstreamErrorSummary(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	jsonPart := raw
	if idx := strings.Index(raw, ": {"); idx != -1 && idx < 50 {
		jsonPart = strings.TrimSpace(raw[idx+2:])
	}
	if gjson.Valid(jsonPart) {
		parsed := gjson.Parse(jsonPart)
		var code, message string
		if errNode := parsed.Get("error"); errNode.Exists() {
			if errNode.IsObject() {
				code = strings.TrimSpace(errNode.Get("code").String())
				if code == "" {
					code = strings.TrimSpace(errNode.Get("type").String())
				}
				message = strings.TrimSpace(errNode.Get("message").String())
			} else if errNode.Type == gjson.String {
				message = strings.TrimSpace(errNode.String())
			}
		}
		if code == "" && message == "" {
			code = strings.TrimSpace(parsed.Get("code").String())
			if code == "" {
				code = strings.TrimSpace(parsed.Get("type").String())
			}
			message = strings.TrimSpace(parsed.Get("message").String())
		}
		var summary string
		if code != "" && message != "" {
			if strings.EqualFold(code, message) || strings.Contains(strings.ToLower(message), strings.ToLower(code)) {
				summary = message
			} else {
				summary = code + ": " + message
			}
		} else if message != "" {
			summary = message
		} else if code != "" {
			summary = code
		}
		if summary != "" {
			return SanitizeUpstreamErrorSummary(summary)
		}
	}
	return SanitizeUpstreamErrorSummary(raw)
}

func sanitizeUpstreamErrorSummaryNoTruncate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = sanitizerSchemeAuthPattern.ReplaceAllString(s, "${1}[REDACTED_AUTH]@")
	s = sanitizerQueryParamPattern.ReplaceAllString(s, "${1}[REDACTED]")
	s = sanitizerDoubleQuotedPathPattern.ReplaceAllString(s, `"[REDACTED_PATH]"`)
	s = sanitizerSingleQuotedPathPattern.ReplaceAllString(s, `'[REDACTED_PATH]'`)
	s = sanitizerBacktickQuotedPathPattern.ReplaceAllString(s, "`[REDACTED_PATH]`")
	s = sanitizerWindowsPathPattern.ReplaceAllString(s, "[REDACTED_PATH]")
	s = sanitizerWindowsUNCPathPattern.ReplaceAllString(s, "[REDACTED_PATH]")

	// Handle connector-separated paths like "copy /tmp/a TO /tmp/b: denied"
	if loc := sanitizerPathConnectorPattern.FindStringSubmatchIndex(s); loc != nil {
		firstPart := s[:loc[0]]
		connRaw := s[loc[0] : loc[1]-1]
		secondPart := "/" + s[loc[1]:]
		return sanitizeUpstreamErrorSummaryNoTruncate(firstPart) + connRaw + sanitizeUpstreamErrorSummaryNoTruncate(secondPart)
	}

	// Handle path before colon error delimiter, finding the first known error or first colon
	var colonIdx = -1
	knownErrorPrefixes := []string{
		"permission denied", "no such file", "file not found", "access denied",
		"operation not permitted", "denied", "read-only", "is a directory",
		"not a directory", "cannot find", "no space", "connection refused",
		"timeout", "failed", "error", "not supported", "invalid argument",
	}
	for _, errWord := range knownErrorPrefixes {
		target := ": " + errWord
		if idx := strings.Index(strings.ToLower(s), target); idx != -1 {
			if colonIdx == -1 || idx < colonIdx {
				colonIdx = idx
			}
		}
	}
	if colonIdx == -1 {
		colonIdx = strings.Index(s, ": ")
	}

	if colonIdx != -1 {
		prefix := s[:colonIdx]
		suffix := s[colonIdx:]
		slashIdx := -1
		for i := 0; i < len(prefix); i++ {
			if prefix[i] == '/' {
				if i > 0 && prefix[i-1] == '/' {
					continue
				}
				if i >= 6 && (strings.HasSuffix(prefix[:i], "http:/") || strings.HasSuffix(prefix[:i], "https:/") || strings.HasSuffix(prefix[:i], "://")) {
					continue
				}
				if i == 0 || prefix[i-1] == ' ' || prefix[i-1] == '\t' || prefix[i-1] == '(' || prefix[i-1] == '[' || prefix[i-1] == '{' || prefix[i-1] == '<' || prefix[i-1] == '"' || prefix[i-1] == '\'' || prefix[i-1] == '`' || prefix[i-1] == '=' {
					slashIdx = i
					break
				}
			}
		}
		if slashIdx != -1 {
			lead := prefix[:slashIdx]
			pathPart := prefix[slashIdx:]
			trailPunct := ""
			for len(pathPart) > 0 && (pathPart[len(pathPart)-1] == ')' || pathPart[len(pathPart)-1] == ']' || pathPart[len(pathPart)-1] == '}' || pathPart[len(pathPart)-1] == '>') {
				trailPunct = string(pathPart[len(pathPart)-1]) + trailPunct
				pathPart = pathPart[:len(pathPart)-1]
			}
			if strings.Contains(pathPart, " /") {
				segments := strings.Split(pathPart, " /")
				for j := range segments {
					segments[j] = "[REDACTED_PATH]"
				}
				pathPart = strings.Join(segments, " ")
			} else {
				pathPart = "[REDACTED_PATH]"
			}
			s = lead + pathPart + trailPunct + suffix
		}
	}

	for i := 0; i < 3; i++ {
		prev := s
		s = sanitizerUnixPathStandardPattern.ReplaceAllString(s, "${1}[REDACTED_PATH]")
		if s == prev {
			break
		}
	}
	s = sanitizerFileExtPathPattern.ReplaceAllString(s, "${1}[REDACTED_PATH]")
	s = sanitizerCookiePattern.ReplaceAllString(s, "Cookie: [REDACTED]")
	s = sanitizerAuthHeaderPattern.ReplaceAllString(s, "Authorization: [REDACTED]")
	s = sanitizerSKKeyPattern.ReplaceAllString(s, "sk-[REDACTED]")
	s = sanitizerBearerPattern.ReplaceAllString(s, "Bearer [REDACTED]")
	s = sanitizerInvalidTokenPattern.ReplaceAllString(s, `${1} token [REDACTED]`)
	s = sanitizerNaturalSecretPattern.ReplaceAllString(s, `${1}: [REDACTED]`)
	s = sanitizerKVPattern.ReplaceAllString(s, `${1}[REDACTED]`)
	return s
}

// SanitizeUpstreamErrorSummary removes sensitive credentials, tokens, and paths, and bounds length.
func SanitizeUpstreamErrorSummary(s string) string {
	s = sanitizeUpstreamErrorSummaryNoTruncate(s)
	runes := []rune(s)
	if len(runes) > 256 {
		if len(runes) > 253 {
			return string(runes[:253]) + "..."
		}
		return string(runes) + "..."
	}
	return s
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
	if threshold, configured := oauthWeeklyQuotaReservePercent(auth.Attributes); configured {
		windowScore, okScore := bestQuotaWindowScore(auth, now, 7*24*time.Hour)
		if okScore && windowScore.ResetAt.After(now) &&
			windowScore.RemainingPercent < scaleQuotaReservePercent(threshold, windowScore.ResetIn, windowScore.Window) {
			if availableAt, blocked := quotaReserveAvailableAt(now, windowScore, threshold); blocked {
				latest = laterTime(latest, availableAt)
			}
		}
	}
	return latest, !latest.IsZero()
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

type prevalidatedAuthCandidatesKey struct{}

func getSelectorAvailableAuths(ctx context.Context, auths []*Auth, provider, model string, now time.Time) ([]*Auth, error) {
	return getSelectorAvailableAuthsWithPriorityMode(ctx, auths, provider, model, now, false)
}

func getSelectorAvailableAuthsAcrossPriorities(ctx context.Context, auths []*Auth, provider, model string, now time.Time) ([]*Auth, error) {
	return getSelectorAvailableAuthsWithPriorityMode(ctx, auths, provider, model, now, true)
}

func getSelectorAvailableAuthsWithPriorityMode(ctx context.Context, auths []*Auth, provider, model string, now time.Time, allPriorities bool) ([]*Auth, error) {
	if ctx != nil {
		if validated, _ := ctx.Value(prevalidatedAuthCandidatesKey{}).(bool); validated && len(auths) > 0 {
			// The manager already resolved each credential's upstream model and supplied
			// ID-sorted candidates. Rechecking the alias or an empty model would apply
			// unrelated cooldowns. Affinity bindings may span all priority tiers, but
			// fallback selection must still use the highest available tier.
			if !allPriorities {
				return highestPriorityAuths(auths), nil
			}
			return auths, nil
		}
	}
	return getAvailableAuthsWithPriorityMode(auths, provider, model, now, 0, allPriorities)
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

// quotaAvailableAuths applies quota gates without rechecking an unresolved route alias.
func quotaAvailableAuths(auths []*Auth, provider, model string, now time.Time, window time.Duration) ([]*Auth, error) {
	available := make([]*Auth, 0, len(auths))
	var earliest time.Time
	for _, auth := range auths {
		if resetAt, blocked := quotaAvailabilityBlockedUntil(auth, now, window); blocked {
			if earliest.IsZero() || resetAt.Before(earliest) {
				earliest = resetAt
			}
			continue
		}
		available = append(available, auth)
	}
	if len(available) == 0 && !earliest.IsZero() {
		if provider == "mixed" {
			provider = ""
		}
		return nil, newModelCooldownError(model, provider, earliest.Sub(now))
	}
	return available, nil
}

func getSelectableAuths(ctx context.Context, auths []*Auth, provider, model string, now time.Time, quotaReservePercent float64, quotaExhaustionWindow time.Duration) ([]*Auth, error) {
	return getSelectableAuthsWithPriorityMode(ctx, auths, provider, model, now, quotaReservePercent, quotaExhaustionWindow, false)
}

func getSelectableAuthsWithPriorityMode(ctx context.Context, auths []*Auth, provider, model string, now time.Time, quotaReservePercent float64, quotaExhaustionWindow time.Duration, allPriorities bool) ([]*Auth, error) {
	auths, err := quotaAvailableAuths(auths, provider, model, now, quotaExhaustionWindow)
	if err != nil {
		return nil, err
	}
	available, err := getSelectorAvailableAuthsWithPriorityMode(ctx, auths, provider, model, now, allPriorities)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	available = filterAuthsByQuotaReserve(available, quotaReservePercent, now, quotaExhaustionWindow)
	entry := selectorLogEntry(ctx)
	if entry.Logger.IsLevelEnabled(log.DebugLevel) {
		logWindow := quotaExhaustionWindow
		if logWindow <= 0 {
			logWindow = DefaultQuotaPriorityWindow
		}
		entry.Debugf("routing selectable auths | provider=%s model=%s candidates=%d selectable=%d quota_reserve_percent=%.2f quota_exhaustion_window=%s auths=%s",
			provider, model, len(auths), len(available), normalizeQuotaReservePercent(quotaReservePercent), logWindow, formatAuthSelectionCandidates(available, now, logWindow, quotaReservePercent))
	}
	return available, nil
}

func QuotaReservePercentFromConfig(value *float64) (float64, error) {
	if value == nil {
		return DefaultQuotaReservePercent, nil
	}
	percent := *value
	if math.IsNaN(percent) || math.IsInf(percent, 0) {
		return 0, fmt.Errorf("quota reserve percent must be finite")
	}
	if percent < 0 || percent > 100 {
		return 0, fmt.Errorf("quota reserve percent must be between 0 and 100")
	}
	return percent, nil
}

func normalizeQuotaReservePercent(percent float64) float64 {
	if math.IsNaN(percent) || math.IsInf(percent, 0) || percent < 0 || percent > 100 {
		return DefaultQuotaReservePercent
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
	return bestQuotaWindowScoreWithReserve(auth, now, window, 0)
}

func bestQuotaWindowScoreWithReserve(auth *Auth, now time.Time, window time.Duration, defaultReservePercent float64) (quotaWindowScore, bool) {
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
		spendablePercent := percent
		reservePercent := normalizeQuotaReservePercent(defaultReservePercent)
		if threshold, configured := oauthWeeklyQuotaReservePercent(auth.Attributes); configured && windowDuration == 7*24*time.Hour {
			reservePercent = threshold
		}
		if reservePercent > 0 {
			spendablePercent -= scaleQuotaReservePercent(reservePercent, resetIn, windowDuration)
			if spendablePercent < 0 {
				spendablePercent = 0
			}
		}
		score := spendablePercent * multiplier / remainingMinutes
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

func quotaReserveAllowedAuthIDs(auths []*Auth, threshold float64) map[string]struct{} {
	return quotaReserveAllowedAuthIDsAt(auths, threshold, time.Now(), 0)
}

func quotaReserveAllowedAuthIDsAt(auths []*Auth, threshold float64, now time.Time, quotaWindow time.Duration) map[string]struct{} {
	threshold = normalizeQuotaReservePercent(threshold)
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
		if _, configured := oauthWeeklyQuotaReservePercent(auth.Attributes); configured {
			eligible[auth.ID] = struct{}{}
			continue
		}
		percent, effectiveThreshold, ok := quotaReserveForAuth(auth, now, threshold, quotaWindow)
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

func quotaReserveForAuth(auth *Auth, now time.Time, threshold float64, quotaWindow time.Duration) (remainingPercent, effectiveThreshold float64, ok bool) {
	if quotaWindow > 0 {
		if score, okScore := bestQuotaWindowScore(auth, now, quotaWindow); okScore && score.Window > 0 {
			return score.RemainingPercent, scaleQuotaReservePercent(threshold, score.ResetIn, score.Window), true
		}
	}

	percent, okPercent := remainingQuotaPercentAt(auth, now)
	return percent, threshold, okPercent
}

func scaleQuotaReservePercent(threshold float64, resetIn, window time.Duration) float64 {
	threshold = normalizeQuotaReservePercent(threshold)
	if threshold <= 0 || resetIn <= 0 {
		return 0
	}
	if window <= 0 || resetIn >= window {
		return threshold
	}
	return threshold * float64(resetIn) / float64(window)
}

func quotaReserveAvailableAt(now time.Time, windowScore quotaWindowScore, threshold float64) (time.Time, bool) {
	threshold = normalizeQuotaReservePercent(threshold)
	if threshold <= 0 || windowScore.Window <= 0 || windowScore.ResetIn <= 0 {
		return time.Time{}, false
	}
	if windowScore.RemainingPercent >= scaleQuotaReservePercent(threshold, windowScore.ResetIn, windowScore.Window) {
		return time.Time{}, false
	}
	remainingResetIn := time.Duration(float64(windowScore.Window) * windowScore.RemainingPercent / threshold)
	if remainingResetIn < 0 {
		remainingResetIn = 0
	}
	availableAt := windowScore.ResetAt.Add(-remainingResetIn)
	if !availableAt.After(now) {
		return time.Time{}, false
	}
	return availableAt, true
}

func filterAuthsByQuotaReserve(auths []*Auth, threshold float64, now time.Time, quotaWindow time.Duration) []*Auth {
	allowed := quotaReserveAllowedAuthIDsAt(auths, threshold, now, quotaWindow)
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

func pickQuotaPriorityAuth(auths []*Auth, now time.Time, window time.Duration, quotaReservePercent float64) (*Auth, bool) {
	var picked *Auth
	var pickedWindow quotaWindowScore
	for i := 0; i < len(auths); i++ {
		candidate := auths[i]
		windowScore, ok := bestQuotaWindowScoreWithReserve(candidate, now, window, quotaReservePercent)
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

func quotaPrioritySelectionScore(auth *Auth, now time.Time, window time.Duration, quotaReservePercent float64) (float64, bool, time.Duration, bool) {
	windowScore, ok := bestQuotaWindowScoreWithReserve(auth, now, window, quotaReservePercent)
	if !ok {
		return 0, false, 0, false
	}
	return windowScore.Score, true, windowScore.ResetIn, true
}

func formatAuthSelectionCandidates(auths []*Auth, now time.Time, window time.Duration, quotaReservePercent float64) string {
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
		if windowScore, ok := bestQuotaWindowScoreWithReserve(auth, now, window, quotaReservePercent); ok {
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

func quotaPrioritySelectedLogFields(auth *Auth, now time.Time, window time.Duration, quotaReservePercent float64) (string, string, string, string, string) {
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
	if windowScore, ok := bestQuotaWindowScoreWithReserve(auth, now, window, quotaReservePercent); ok {
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
	available, err := getSelectableAuths(ctx, auths, provider, model, now, s.QuotaReservePercent, 0)
	if err != nil {
		return nil, err
	}
	return s.pickAvailable(ctx, provider, model, available, s.QuotaReservePercent)
}

func (s *RoundRobinSelector) pickAvailable(ctx context.Context, provider, model string, available []*Auth, quotaReservePercent float64) (*Auth, error) {
	if len(available) == 0 {
		return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	key := provider + ":" + canonicalModelKey(model)
	s.mu.Lock()
	if s.lastPicked == nil {
		s.lastPicked = make(map[string]string)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = 4096
	}

	s.ensureRotationKey(key, limit)
	picked := available[successorIndex(available, s.lastPicked[key])]
	s.lastPicked[key] = picked.ID
	s.mu.Unlock()
	selectorLogEntry(ctx).Infof("routing selector: selected | strategy=round-robin auth=%s provider=%s model=%s selectable=%d quota_reserve_percent=%.2f",
		picked.ID, provider, model, len(available), normalizeQuotaReservePercent(quotaReservePercent))
	return picked, nil
}

// successorIndex returns the index of the first candidate ordered after lastID, wrapping to
// the start of the ring. Candidates arrive sorted by ID, so this resumes the rotation at the
// credential that follows the previous pick even when candidates were filtered out in
// between. An empty lastID starts at the head.
func successorIndex(available []*Auth, lastID string) int {
	if lastID == "" {
		return 0
	}
	index := sort.Search(len(available), func(i int) bool { return available[i].ID > lastID })
	if index >= len(available) {
		return 0
	}
	return index
}

// ensureRotationKey ensures the rotation map has capacity for the given key.
// Must be called with s.mu held.
func (s *RoundRobinSelector) ensureRotationKey(key string, limit int) {
	if _, ok := s.lastPicked[key]; !ok && len(s.lastPicked) >= limit {
		s.lastPicked = make(map[string]string)
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
	available, errAvailable := getSelectorAvailableAuths(ctx, positiveWeightAuths(auths), provider, model, time.Now())
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

// maxSmoothWeightedStateEntries bounds a single accumulator map so credentials that are
// removed permanently cannot leak entries. Real pools stay far below this bound, so the
// transient subsets produced by retry exclusions and cooldowns are never pruned.
const maxSmoothWeightedStateEntries = 1024

// prepare syncs the configured weights into the state without discarding accumulated
// credits. Credits are reset only when a credential's configured weight actually changes,
// never when the candidate set shrinks temporarily (retry exclusions, cooldowns, session
// affinity), because discarding credits there would collapse selection onto the first
// candidate in slice order.
func (s *smoothWeightedState) prepare(weights map[string]int64) {
	if s.current == nil || weightsConfigChanged(s.weights, weights) {
		s.current = make(map[string]int64, len(weights))
	}
	if s.weights == nil {
		s.weights = make(map[string]int64, len(weights))
	}
	for authID, weight := range weights {
		s.weights[authID] = weight
	}
	s.pruneStale(weights)
}

// pruneStale drops entries for credentials outside the current candidate set, but only
// once a map exceeds the safety bound, so ordinary transient exclusions keep their credits.
func (s *smoothWeightedState) pruneStale(weights map[string]int64) {
	if len(s.current) <= maxSmoothWeightedStateEntries && len(s.weights) <= maxSmoothWeightedStateEntries {
		return
	}
	for authID := range s.current {
		if _, ok := weights[authID]; !ok {
			delete(s.current, authID)
		}
	}
	for authID := range s.weights {
		if _, ok := weights[authID]; !ok {
			delete(s.weights, authID)
		}
	}
}

// weightsConfigChanged reports whether any credential present in both vectors has a
// different configured weight. Credentials that are merely missing from one side are
// ignored, since a candidate subset is not a configuration change.
func weightsConfigChanged(left, right map[string]int64) bool {
	if len(left) == 0 {
		return false
	}
	for authID, weight := range right {
		if previous, ok := left[authID]; ok && previous != weight {
			return true
		}
	}
	return false
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
	var picked *Auth
	var pickedCurrent int64
	var totalWeight int64
	for _, auth := range auths {
		weight := authWeight(auth)
		if auth == nil || weight <= 0 {
			continue
		}
		current[auth.ID] = saturatingAddInt64(current[auth.ID], weight)
		totalWeight = saturatingAddInt64(totalWeight, weight)
		if picked == nil || current[auth.ID] > pickedCurrent {
			picked = auth
			pickedCurrent = current[auth.ID]
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
	available, err := getSelectableAuths(ctx, auths, provider, model, now, s.QuotaReservePercent, 0)
	if err != nil {
		return nil, err
	}
	selected := available[0]
	selectorLogEntry(ctx).Infof("routing selector: selected | strategy=fill-first auth=%s provider=%s model=%s selectable=%d quota_reserve_percent=%.2f",
		selected.ID, provider, model, len(available), normalizeQuotaReservePercent(s.QuotaReservePercent))
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
	available, err := getSelectableAuths(ctx, auths, provider, model, now, s.QuotaReservePercent, quotaWindow)
	if err != nil {
		return nil, err
	}
	if picked, ok := pickQuotaWarmupAuth(available, now, quotaWindow); ok {
		winningWindow, resetIn, quota, score, multiplier := quotaPrioritySelectedLogFields(picked, now, quotaWindow, s.QuotaReservePercent)
		selectorLogEntry(ctx).Infof("routing selector: selected | strategy=quota-priority reason=quota-warmup auth=%s provider=%s model=%s selectable=%d winning_window=%s reset_in=%s quota_percent=%s score=%s plan_multiplier=%s probe_cooldown=%s quota_reserve_percent=%.2f",
			picked.ID, provider, model, len(available), winningWindow, resetIn, quota, score, multiplier, quotaWarmupInFlightCooldown, normalizeQuotaReservePercent(s.QuotaReservePercent))
		return picked, nil
	}
	if picked, ok := pickQuotaPriorityAuth(available, now, quotaWindow, s.QuotaReservePercent); ok {
		winningWindow, resetIn, quota, score, multiplier := quotaPrioritySelectedLogFields(picked, now, quotaWindow, s.QuotaReservePercent)
		selectorLogEntry(ctx).Infof("routing selector: selected | strategy=quota-priority reason=quota-window auth=%s provider=%s model=%s selectable=%d winning_window=%s reset_in=%s quota_percent=%s score=%s plan_multiplier=%s quota_reserve_percent=%.2f",
			picked.ID, provider, model, len(available), winningWindow, resetIn, quota, score, multiplier, normalizeQuotaReservePercent(s.QuotaReservePercent))
		return picked, nil
	}
	entry := selectorLogEntry(ctx)
	if entry.Logger.IsLevelEnabled(log.DebugLevel) {
		entry.Debugf("routing selector: no quota-priority candidates, falling back to round-robin | provider=%s model=%s selectable=%d quota_priority_window=%s auths=%s",
			provider, model, len(available), quotaWindow, formatAuthSelectionCandidates(available, now, quotaWindow, s.QuotaReservePercent))
	}
	return (&s.roundRobin).pickAvailable(ctx, provider, model, available, s.QuotaReservePercent)
}

func isAuthBlockedForModel(auth *Auth, model string, now time.Time) (bool, blockReason, time.Time) {
	if auth == nil {
		return true, blockReasonOther, time.Time{}
	}
	if auth.Disabled || auth.Status == StatusDisabled {
		return true, blockReasonDisabled, time.Time{}
	}
	if exp, ok := auth.AccessTokenExpirationTime(); ok && !exp.IsZero() && !exp.After(now) {
		return true, blockReasonOther, time.Time{}
	}
	if auth.Quota.Exceeded && auth.Quota.Reason == "credential_quota" && auth.Quota.NextRecoverAt.After(now) {
		return true, blockReasonCooldown, auth.Quota.NextRecoverAt
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
			return false, blockReasonNone, time.Time{}
		}
		return availabilityBlock(auth.Unavailable, auth.Quota.Exceeded, auth.NextRetryAfter, auth.Quota.NextRecoverAt, now)
	}
	quotaExceeded := auth.Quota.Exceeded
	// When model is empty and the credential has individual model states, auth.Quota.Exceeded
	// is an aggregate of single-model quota cooldowns (reason "quota"). As long as the credential
	// itself is not unavailable (not all models failed) and not under a credential-wide quota,
	// do not treat individual model cooldowns as blocking the entire credential.
	if len(auth.ModelStates) > 0 && auth.Quota.Reason != "credential_quota" && !auth.Unavailable {
		quotaExceeded = false
	}
	return availabilityBlock(auth.Unavailable, quotaExceeded, auth.NextRetryAfter, auth.Quota.NextRecoverAt, now)
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
	fallback         Selector
	cache            *SessionCache
	matcher          *cliproxysession.MerklePrefixMatcher
	subagentAffinity bool
}

// SessionAffinityConfig configures the session affinity selector.
type SessionAffinityConfig struct {
	Fallback         Selector
	TTL              time.Duration
	SubagentAffinity *bool
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
	subagentAffinity := true
	if cfg.SubagentAffinity != nil {
		subagentAffinity = *cfg.SubagentAffinity
	}
	return &SessionAffinitySelector{
		fallback:         cfg.Fallback,
		cache:            NewSessionCache(cfg.TTL),
		matcher:          cliproxysession.NewMerklePrefixMatcher(cfg.TTL),
		subagentAffinity: subagentAffinity,
	}
}

// Trees returns a backward-compatible in-memory session tree store.
// Deprecated: Session tree management has moved to Home.
func (s *SessionAffinitySelector) Trees() *cliproxysession.InMemorySessionTreeStore {
	return cliproxysession.NewInMemorySessionTreeStore(0, time.Hour)
}

// Pick selects an auth with session affinity when possible.
// Explicit Claude Code, Codex, OpenCode, pi, and request-body session signals
// are absolute authority. Requests without those signals use the Merkle LCP
// matcher before retaining the legacy derived/hash fallback behavior.
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
	if opts.Metadata == nil {
		opts.Metadata = make(map[string]any)
	}
	opts.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey] = provider
	opts.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey] = model

	// Explicit harness identities are absolute authority. The LCP matcher is only
	// consulted when no header, body, or execution-session identity is present.
	explicitID, explicitFallbackID := extractExplicitSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
	if explicitID == "" {
		if auth, handled, errLCP := s.pickLCP(ctx, provider, model, opts, auths, entry); handled || errLCP != nil {
			return auth, errLCP
		}
	} else if opts.Metadata != nil {
		delete(opts.Metadata, cliproxyexecutor.LCPAffinitySessionIDMetadataKey)
		delete(opts.Metadata, cliproxyexecutor.LCPAccessGenerationMetadataKey)
		if explicitFallbackID != "" {
			opts.Metadata[cliproxyexecutor.ParentSessionIDMetadataKey] = cliproxysession.BoundSessionIdentity(explicitFallbackID)
		} else {
			delete(opts.Metadata, cliproxyexecutor.ParentSessionIDMetadataKey)
		}
		if isFork, ok := opts.Metadata[cliproxyexecutor.IsForkMetadataKey].(bool); !ok || !isFork {
			delete(opts.Metadata, cliproxyexecutor.IsForkMetadataKey)
		}
	}

	primaryID, fallbackID := explicitID, explicitFallbackID
	if primaryID == "" {
		primaryID, fallbackID = extractSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
	}
	if primaryID != "" {
		primaryID = cliproxysession.BoundSessionIdentity(primaryID)
		if fallbackID != "" {
			fallbackID = cliproxysession.BoundSessionIdentity(fallbackID)
		}
		if opts.Metadata != nil {
			opts.Metadata[cliproxyexecutor.CanonicalSessionIDMetadataKey] = primaryID
		}
	}
	now := time.Now()
	quotaWindow, _ := selectorQuotaPriorityExhaustionWindow(s.fallback)
	availabilityCandidates := auths
	if _, weighted := s.fallback.(*WeightedRoundRobinSelector); weighted {
		availabilityCandidates = positiveWeightAuths(auths)
	}
	if primaryID == "" {
		fallbackAuths, errAvailable := getSelectableAuths(ctx, availabilityCandidates, provider, model, now, selectorQuotaReservePercent(s.fallback), quotaWindow)
		if errAvailable != nil {
			return nil, errAvailable
		}
		entry.Debugf("session-affinity: no session ID extracted, falling back to default selector | provider=%s model=%s", provider, model)
		return s.fallback.Pick(ctx, provider, model, opts, fallbackAuths)
	}

	// A single availability pass serves both lookups: the bound credential is validated against
	// every priority tier, while the fallback selector keeps seeing only the highest tier.
	available, err := getSelectableAuthsWithPriorityMode(ctx, availabilityCandidates, provider, model, now, selectorQuotaReservePercent(s.fallback), quotaWindow, true)
	if err != nil {
		return nil, err
	}
	fallbackAuths := highestPriorityAuths(available)

	modelKey := canonicalModelKey(model)
	cacheKey := provider + "::" + primaryID + "::" + modelKey
	isFork := false
	if opts.Metadata != nil {
		if forkFlag, ok := opts.Metadata[cliproxyexecutor.IsForkMetadataKey].(bool); ok && forkFlag {
			isFork = true
		}
	}
	isSubagent := !isFork && isSubagentSession(primaryID, fallbackID)
	fallbackKey := ""
	if fallbackID != "" && fallbackID != primaryID {
		fallbackKey = provider + "::" + fallbackID + "::" + modelKey
	}
	bind := func(authID string) {
		if fallbackKey != "" && !isSubagent && !isFork {
			s.cache.SetAliases(authID, cacheKey, fallbackKey)
		} else {
			s.cache.Set(cacheKey, authID)
		}
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
			entry.Debugf("session-affinity: cached auth not selectable | session=%s cached_auth=%s provider=%s model=%s selectable=%d quota_reserve_percent=%.2f selectable_auths=%s",
				truncateSessionID(primaryID), cachedAuthID, provider, model, len(available), selectorQuotaReservePercent(s.fallback), formatAuthSelectionCandidates(available, now, quotaWindow, selectorQuotaReservePercent(s.fallback)))
		}
		// Cached auth not selectable, reselect via fallback selector for even distribution.
		auth, err := s.fallback.Pick(ctx, provider, model, opts, fallbackAuths)
		if err != nil {
			return nil, err
		}
		if auth == nil {
			return nil, nil
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
					if !isSubagent || s.subagentAffinity {
						bind(auth.ID)
						if isFork {
							entry.Infof("session-affinity: fork cache hit | session=%s parent=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), truncateSessionID(fallbackID), auth.ID, provider, model)
						} else {
							entry.Infof("session-affinity: fallback cache hit | session=%s fallback=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), truncateSessionID(fallbackID), auth.ID, provider, model)
						}
						return auth, nil
					}
				}
			}
		}
	}

	auth, err := s.fallback.Pick(ctx, provider, model, opts, fallbackAuths)
	if err != nil {
		return nil, err
	}
	if auth == nil {
		return nil, nil
	}
	if isQuotaWarmupProbeSelection(auth, now, quotaWindow) {
		entry.Infof("session-affinity: skipped cache for quota warmup | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), auth.ID, provider, model)
		return auth, nil
	}
	bind(auth.ID)
	if isFork && fallbackID != "" {
		entry.Infof("session-affinity: fork bound to new auth | session=%s parent=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), truncateSessionID(fallbackID), auth.ID, provider, model)
	} else {
		entry.Infof("session-affinity: cache miss, new binding | session=%s auth=%s provider=%s model=%s", truncateSessionID(primaryID), auth.ID, provider, model)
	}
	return auth, nil
}

func (s *SessionAffinitySelector) pickLCP(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth, entry *log.Entry) (*Auth, bool, error) {
	if s == nil || s.matcher == nil {
		return nil, false, nil
	}
	namespace := lcpAffinityNamespace(provider, model, opts.Metadata)
	if namespace == "" {
		return nil, false, nil
	}
	turns := cliproxysession.ExtractCanonicalTurns(opts.SourceFormat, opts.OriginalRequest)
	if len(turns) == 0 {
		return nil, false, nil
	}
	fingerprints, minPrefixLength := s.matcher.Prepare(turns)
	if len(fingerprints) == 0 || minPrefixLength <= 0 || minPrefixLength > len(fingerprints) {
		return nil, false, nil
	}
	if opts.Metadata != nil {
		opts.Metadata[cliproxyexecutor.LCPFingerprintMetadataKey] = fingerprints
		opts.Metadata[cliproxyexecutor.LCPMinPrefixLengthMetadataKey] = minPrefixLength
	}

	availabilityCandidates := auths
	if _, weighted := s.fallback.(*WeightedRoundRobinSelector); weighted {
		availabilityCandidates = positiveWeightAuths(auths)
	}
	now := time.Now()
	quotaWindow, _ := selectorQuotaPriorityExhaustionWindow(s.fallback)
	available, errAvailable := getSelectableAuthsWithPriorityMode(ctx, availabilityCandidates, provider, model, now, selectorQuotaReservePercent(s.fallback), quotaWindow, true)
	if errAvailable != nil {
		return nil, true, errAvailable
	}

	if match, ok := s.matcher.MatchFingerprints(namespace, fingerprints, minPrefixLength); ok {
		for _, auth := range available {
			if auth == nil || auth.ID != match.AuthID {
				continue
			}
			if match.SessionID != "" {
				opts.Metadata[cliproxyexecutor.LCPAffinitySessionIDMetadataKey] = match.SessionID
				opts.Metadata[cliproxyexecutor.CanonicalSessionIDMetadataKey] = match.SessionID
			}
			if match.ParentSessionID != "" {
				opts.Metadata[cliproxyexecutor.ParentSessionIDMetadataKey] = match.ParentSessionID
			} else if opts.Metadata != nil {
				delete(opts.Metadata, cliproxyexecutor.ParentSessionIDMetadataKey)
			}
			if match.AccessNumber > 0 && opts.Metadata != nil {
				opts.Metadata[cliproxyexecutor.LCPAccessGenerationMetadataKey] = match.AccessNumber
			}
			if match.IsFork {
				if opts.Metadata != nil {
					opts.Metadata[cliproxyexecutor.IsForkMetadataKey] = true
				}
				entry.Infof("session-affinity: LCP fork hit | session=%s parent=%s prefix=%d auth=%s provider=%s model=%s", truncateSessionID(match.SessionID), truncateSessionID(match.ParentSessionID), match.PrefixLength, auth.ID, provider, model)
			} else {
				if opts.Metadata != nil {
					delete(opts.Metadata, cliproxyexecutor.IsForkMetadataKey)
				}
				entry.Infof("session-affinity: LCP cache hit | session=%s prefix=%d auth=%s provider=%s model=%s", truncateSessionID(match.SessionID), match.PrefixLength, auth.ID, provider, model)
			}
			return auth, true, nil
		}
	}

	fallbackAuths := highestPriorityAuths(available)
	auth, errPick := s.fallback.Pick(ctx, provider, model, opts, fallbackAuths)
	if errPick != nil {
		return nil, true, errPick
	}
	if auth == nil {
		return nil, true, &Error{Code: "auth_not_found", Message: "selector returned no auth"}
	}
	if isQuotaWarmupProbeSelection(auth, now, quotaWindow) {
		return auth, true, nil
	}
	if bindRes := s.matcher.BindFingerprintsWithResult(namespace, fingerprints, minPrefixLength, auth.ID); bindRes.SessionID != "" {
		opts.Metadata[cliproxyexecutor.LCPAffinitySessionIDMetadataKey] = bindRes.SessionID
		opts.Metadata[cliproxyexecutor.CanonicalSessionIDMetadataKey] = bindRes.SessionID
		if bindRes.ParentSessionID != "" {
			opts.Metadata[cliproxyexecutor.ParentSessionIDMetadataKey] = bindRes.ParentSessionID
		} else if opts.Metadata != nil {
			delete(opts.Metadata, cliproxyexecutor.ParentSessionIDMetadataKey)
		}
		if bindRes.AccessNumber > 0 && opts.Metadata != nil {
			opts.Metadata[cliproxyexecutor.LCPAccessGenerationMetadataKey] = bindRes.AccessNumber
		}
		if bindRes.IsFork {
			if opts.Metadata != nil {
				opts.Metadata[cliproxyexecutor.IsForkMetadataKey] = true
			}
			entry.Infof("session-affinity: LCP fork bound to new auth | session=%s parent=%s auth=%s provider=%s model=%s", truncateSessionID(bindRes.SessionID), truncateSessionID(bindRes.ParentSessionID), auth.ID, provider, model)
		} else {
			if opts.Metadata != nil {
				delete(opts.Metadata, cliproxyexecutor.IsForkMetadataKey)
			}
			entry.Infof("session-affinity: LCP cache miss, new binding | session=%s auth=%s provider=%s model=%s", truncateSessionID(bindRes.SessionID), auth.ID, provider, model)
		}
	}
	return auth, true, nil
}

func lcpAffinityNamespace(provider, model string, metadata map[string]any) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	model = canonicalModelKey(model)
	callerScope := sessionMetadataString(metadata, cliproxyexecutor.CallerScopeMetadataKey)
	if provider == "" || callerScope == "" {
		return ""
	}
	return strings.Join([]string{"lcp:v1", provider, model, callerScope}, "::")
}

func lcpFingerprintsFromMetadata(metadata map[string]any) ([]string, int) {
	if metadata == nil {
		return nil, 0
	}
	rawFingerprints, ok := metadata[cliproxyexecutor.LCPFingerprintMetadataKey]
	if !ok || rawFingerprints == nil {
		return nil, 0
	}
	var fingerprints []string
	switch v := rawFingerprints.(type) {
	case []string:
		fingerprints = v
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				fingerprints = append(fingerprints, s)
			}
		}
	}
	minPrefixLength, _ := metadata[cliproxyexecutor.LCPMinPrefixLengthMetadataKey].(int)
	return fingerprints, minPrefixLength
}

func sessionMetadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, ok := metadata[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
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
	if s == nil {
		return
	}
	if s.cache != nil {
		s.cache.Stop()
	}
	if s.matcher != nil {
		s.matcher.Clear()
	}
}

// InvalidateAuth removes all session bindings for a specific auth.
// Called when an auth becomes rate-limited or unavailable.
func (s *SessionAffinitySelector) InvalidateAuth(authID string) {
	if s == nil {
		return
	}
	if s.cache != nil {
		s.cache.InvalidateAuth(authID)
	}
	if s.matcher != nil {
		s.matcher.InvalidateAuth(authID)
	}
}

// OnResult handles session affinity binding or release based on execution outcome.
func (s *SessionAffinitySelector) OnResult(res Result) {
	if s == nil || res.AuthID == "" {
		return
	}

	explicitID, explicitFallbackID := extractExplicitSessionIDs(res.Options.Headers, res.Options.OriginalRequest, res.Options.Metadata)
	if explicitID != "" {
		explicitID = cliproxysession.BoundSessionIdentity(explicitID)
		if explicitFallbackID != "" {
			explicitFallbackID = cliproxysession.BoundSessionIdentity(explicitFallbackID)
		}
	}
	ns := res.Provider
	if raw, ok := res.Options.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey].(string); ok && raw != "" {
		ns = raw
	}
	nsModel := canonicalModelKey(res.Model)
	if raw, ok := res.Options.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey].(string); ok && raw != "" {
		nsModel = canonicalModelKey(raw)
	}

	if res.Error != nil && shouldSkipCredentialCooldown(res.Error) {
		// Request-scoped or caller-attributed failures are not evidence that the
		// selected credential is unhealthy, so preserve both explicit and LCP bindings.
		return
	}

	// LCP bindings are independent from explicit harness bindings. A successful
	// extension is recorded as a new sequence while credential-attributed failures
	// only remove the exact sequence that was attempted.
	if explicitID == "" && s.matcher != nil {
		if namespace := lcpAffinityNamespace(ns, nsModel, res.Options.Metadata); namespace != "" {
			fingerprints, minPrefixLength := lcpFingerprintsFromMetadata(res.Options.Metadata)
			if len(fingerprints) == 0 {
				turns := cliproxysession.ExtractCanonicalTurns(res.Options.SourceFormat, res.Options.OriginalRequest)
				fingerprints, minPrefixLength = s.matcher.Prepare(turns)
			}
			if len(fingerprints) > 0 && minPrefixLength > 0 && minPrefixLength <= len(fingerprints) {
				if res.Success {
					s.matcher.TouchFingerprints(namespace, fingerprints, minPrefixLength, res.AuthID)
				} else {
					var generation uint64
					if res.Options.Metadata != nil {
						if gen, ok := res.Options.Metadata[cliproxyexecutor.LCPAccessGenerationMetadataKey].(uint64); ok {
							generation = gen
						}
					}
					s.matcher.RemoveFingerprintsBefore(namespace, fingerprints, res.AuthID, generation)
				}
			}
		}
	}

	if s.cache == nil {
		return
	}
	if explicitID == "" && s.matcher != nil && res.Options.Metadata != nil {
		if _, isLCP := res.Options.Metadata[cliproxyexecutor.LCPAffinitySessionIDMetadataKey]; isLCP {
			return
		}
	}
	primaryID, fallbackID := explicitID, explicitFallbackID
	if primaryID == "" {
		primaryID, fallbackID = extractSessionIDs(res.Options.Headers, res.Options.OriginalRequest, res.Options.Metadata)
	}
	if primaryID == "" && fallbackID == "" {
		return
	}
	if primaryID != "" {
		primaryID = cliproxysession.BoundSessionIdentity(primaryID)
	}
	if fallbackID != "" {
		fallbackID = cliproxysession.BoundSessionIdentity(fallbackID)
	}

	cacheKey := ns + "::" + primaryID + "::" + nsModel
	var fallbackKey string
	if fallbackID != "" && fallbackID != primaryID && !isSubagentSession(primaryID, fallbackID) {
		fallbackKey = ns + "::" + fallbackID + "::" + nsModel
	}
	if res.Success {
		s.cache.Touch(cacheKey, res.AuthID)
		if fallbackKey != "" {
			s.cache.Touch(fallbackKey, res.AuthID)
		}
		return
	}

	s.cache.CompareAndDelete(cacheKey, res.AuthID)
	if fallbackKey != "" {
		s.cache.CompareAndDelete(fallbackKey, res.AuthID)
	}
}

// normalizedSessionCandidate validates an explicit client-provided session signal.
// It keeps opaque printable IDs intact while rejecting values that are unsafe or
// implausibly large for routing keys and logs.
func normalizedSessionCandidate(raw string) string {
	return cliproxysession.NormalizeExplicitID(raw)
}

func isSubagentSession(primaryID, fallbackID string) bool {
	if strings.Contains(primaryID, ":agent:") {
		return true
	}
	if fallbackID == "" || primaryID == "" || primaryID == fallbackID {
		return false
	}
	return isHierarchyParent(primaryID, fallbackID)
}

// CanonicalSessionID resolves the single authoritative session identity from request options and metadata.
func CanonicalSessionID(headers http.Header, payload []byte, metadata map[string]any) string {
	if explicitID, _ := extractExplicitSessionIDs(headers, payload, metadata); explicitID != "" {
		return cliproxysession.BoundSessionIdentity(explicitID)
	}
	if metadata != nil {
		if canonicalID, ok := metadata[cliproxyexecutor.CanonicalSessionIDMetadataKey].(string); ok && strings.TrimSpace(canonicalID) != "" {
			return cliproxysession.BoundSessionIdentity(strings.TrimSpace(canonicalID))
		}
		if lcpID, ok := metadata[cliproxyexecutor.LCPAffinitySessionIDMetadataKey].(string); ok && strings.TrimSpace(lcpID) != "" {
			return cliproxysession.BoundSessionIdentity(strings.TrimSpace(lcpID))
		}
	}
	return cliproxysession.BoundSessionIdentity(ExtractSessionID(headers, payload, metadata))
}

// ExtractSessionID extracts a session identifier from explicit client signals,
// then falls back to execution metadata, derived identity, and message history.
// Priority order:
//  1. X-Claude-Code-Session-Id
//  2. Claude Code metadata.user_id session
//  3. Session-Id / Session_id (Codex and compatible clients)
//  4. X-Session-ID
//  5. X-Session-Affinity (OpenCode)
//  6. X-Client-Request-Id (pi Responses)
//  7. session_id / sessionId
//  8. prompt_cache_key, with conversation / conversation.id as an alias
//  9. metadata.user_id and conversation_id legacy body fields
//  10. explicit execution session metadata
//  11. stable context-derived session identity
//  12. stable hash from initial message content
func ExtractSessionID(headers http.Header, payload []byte, metadata map[string]any) string {
	primary, _ := extractSessionIDs(headers, payload, metadata)
	return primary
}

func extractConversationAlias(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	root := gjson.ParseBytes(payload)
	conversation := root.Get("conversation")
	if !conversation.Exists() {
		req := root.Get("request")
		if req.Exists() && !root.Get("contents").Exists() {
			conversation = req.Get("conversation")
		}
	}
	if sid := normalizedSessionCandidate(conversation.Get("id").String()); sid != "" {
		return "conv:" + sid
	} else if conversation.Type == gjson.String {
		if sid := normalizedSessionCandidate(conversation.String()); sid != "" {
			return "conv:" + sid
		}
	}
	return ""
}

// extractExplicitSessionIDs returns only client- or execution-provided identities.
// LCP fallback must run after this function so explicit harness sessions remain authoritative.
func extractExplicitSessionIDs(headers http.Header, payload []byte, metadata map[string]any) (string, string) {
	info, ok := cliproxysession.ExtractSessionInfo(headers, payload, metadata)
	if !ok || info.ClientType == "lcp" {
		return "", ""
	}
	if metadata != nil {
		if info.IsFork {
			metadata[cliproxyexecutor.IsForkMetadataKey] = true
		}
		if info.ParentSessionID != "" {
			metadata[cliproxyexecutor.ParentSessionIDMetadataKey] = info.ParentSessionID
		}
	}
	fallback := info.ParentSessionID
	if fallback == "" && strings.HasPrefix(info.SessionID, "pck:") && len(payload) > 0 {
		fallback = extractConversationAlias(payload)
	}
	return info.SessionID, fallback
}

// extractSessionIDs returns (primaryID, fallbackID) for session affinity.
// fallbackID preserves an earlier binding when a stronger body identifier appears
// later, and lets callers bind both identifiers when both are present.
func extractSessionIDs(headers http.Header, payload []byte, metadata map[string]any) (string, string) {
	if primaryID, fallbackID := extractExplicitSessionIDs(headers, payload, metadata); primaryID != "" {
		return primaryID, fallbackID
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

	if firstUserMsg == "" {
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
