package auth

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// schedulerStrategy identifies which built-in routing semantics the scheduler should apply.
type schedulerStrategy int

const (
	schedulerStrategyCurrent    schedulerStrategy = -1
	schedulerStrategyCustom     schedulerStrategy = 0
	schedulerStrategyRoundRobin schedulerStrategy = 1
	schedulerStrategyFillFirst  schedulerStrategy = 2
	schedulerStrategyQuota      schedulerStrategy = 3
)

// scheduledState describes how an auth currently participates in a model shard.
type scheduledState int

const (
	scheduledStateReady scheduledState = iota
	scheduledStateCooldown
	scheduledStateBlocked
	scheduledStateDisabled
)

// authScheduler keeps the incremental provider/model scheduling state used by Manager.
type authScheduler struct {
	mu                  sync.Mutex
	strategy            schedulerStrategy
	quotaWindow         time.Duration
	minimumQuotaPercent float64
	providers           map[string]*providerScheduler
	authProviders       map[string]string
	mixedCursors        map[string]int
}

// providerScheduler stores auth metadata and model shards for a single provider.
type providerScheduler struct {
	providerKey string
	auths       map[string]*scheduledAuthMeta
	modelShards map[string]*modelScheduler
}

// scheduledAuthMeta stores the immutable scheduling fields derived from an auth snapshot.
type scheduledAuthMeta struct {
	auth              *Auth
	providerKey       string
	priority          int
	websocketEnabled  bool
	supportedModelSet map[string]struct{}
}

// modelScheduler tracks ready and blocked auths for one provider/model combination.
type modelScheduler struct {
	modelKey        string
	entries         map[string]*scheduledAuth
	priorityOrder   []int
	readyByPriority map[int]*readyBucket
	blocked         cooldownQueue
}

// scheduledAuth stores the runtime scheduling state for a single auth inside a model shard.
type scheduledAuth struct {
	meta        *scheduledAuthMeta
	auth        *Auth
	state       scheduledState
	nextRetryAt time.Time
}

// readyBucket keeps the ready views for one priority level.
type readyBucket struct {
	all readyView
	ws  readyView
}

// readyView holds the selection order for flat round-robin traversal.
type readyView struct {
	flat   []*scheduledAuth
	cursor int
}

// cooldownQueue is the blocked auth collection ordered by next retry time during rebuilds.
type cooldownQueue []*scheduledAuth

type readyViewCursorState struct {
	cursor int
}

type readyBucketCursorState struct {
	all readyViewCursorState
	ws  readyViewCursorState
}

func snapshotReadyViewCursors(view readyView) readyViewCursorState {
	return readyViewCursorState{cursor: view.cursor}
}

func restoreReadyViewCursors(view *readyView, state readyViewCursorState) {
	if view == nil {
		return
	}
	if len(view.flat) > 0 {
		view.cursor = normalizeCursor(state.cursor, len(view.flat))
	}
}

func normalizeCursor(cursor, size int) int {
	if size <= 0 || cursor <= 0 {
		return 0
	}
	cursor = cursor % size
	if cursor < 0 {
		cursor += size
	}
	return cursor
}

// newAuthScheduler constructs an empty scheduler configured for the supplied selector strategy.
func newAuthScheduler(selector Selector) *authScheduler {
	return &authScheduler{
		strategy:            selectorStrategy(selector),
		quotaWindow:         selectorQuotaPriorityWindow(selector),
		minimumQuotaPercent: selectorMinimumQuotaPercent(selector),
		providers:           make(map[string]*providerScheduler),
		authProviders:       make(map[string]string),
		mixedCursors:        make(map[string]int),
	}
}

// selectorStrategy maps a selector implementation to the scheduler semantics it should emulate.
func selectorStrategy(selector Selector) schedulerStrategy {
	switch selector.(type) {
	case *FillFirstSelector:
		return schedulerStrategyFillFirst
	case *QuotaPrioritySelector:
		return schedulerStrategyQuota
	case nil, *RoundRobinSelector:
		return schedulerStrategyRoundRobin
	default:
		return schedulerStrategyCustom
	}
}

func selectorQuotaPriorityWindow(selector Selector) time.Duration {
	switch current := selector.(type) {
	case *QuotaPrioritySelector:
		return current.quotaPriorityWindow()
	default:
		return DefaultQuotaPriorityWindow
	}
}

func selectorMinimumQuotaPercent(selector Selector) float64 {
	switch current := selector.(type) {
	case *RoundRobinSelector:
		return normalizeMinimumQuotaPercent(current.MinimumQuotaPercent)
	case *FillFirstSelector:
		return normalizeMinimumQuotaPercent(current.MinimumQuotaPercent)
	case *QuotaPrioritySelector:
		return normalizeMinimumQuotaPercent(current.MinimumQuotaPercent)
	case *SessionAffinitySelector:
		return selectorMinimumQuotaPercent(current.fallback)
	default:
		return 0
	}
}

// setSelector updates the active built-in strategy and resets mixed-provider cursors.
func (s *authScheduler) setSelector(selector Selector) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.strategy = selectorStrategy(selector)
	s.quotaWindow = selectorQuotaPriorityWindow(selector)
	s.minimumQuotaPercent = selectorMinimumQuotaPercent(selector)
	clear(s.mixedCursors)
}

func (s *authScheduler) setQuotaPriorityWindow(window time.Duration) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.quotaWindow = normalizeQuotaPriorityWindow(window)
	s.mu.Unlock()
}

func (s *authScheduler) setMinimumQuotaPercent(percent float64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.minimumQuotaPercent = normalizeMinimumQuotaPercent(percent)
	s.mu.Unlock()
}

// rebuild recreates the complete scheduler state from an auth snapshot.
func (s *authScheduler) rebuild(auths []*Auth) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.providers = make(map[string]*providerScheduler)
	s.authProviders = make(map[string]string)
	s.mixedCursors = make(map[string]int)
	now := time.Now()
	for _, auth := range auths {
		s.upsertAuthLocked(auth, now)
	}
}

// upsertAuth incrementally synchronizes one auth into the scheduler.
func (s *authScheduler) upsertAuth(auth *Auth) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upsertAuthLocked(auth, time.Now())
}

// removeAuth deletes one auth from every scheduler shard that references it.
func (s *authScheduler) removeAuth(authID string) {
	if s == nil {
		return
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeAuthLocked(authID)
}

// pickSingle returns the next auth for a single provider/model request using scheduler state.
func (s *authScheduler) pickSingle(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, error) {
	return s.pickSingleWithStrategy(ctx, provider, model, opts, tried, schedulerStrategyCurrent)
}

func (s *authScheduler) pickSingleWithStrategy(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, strategy schedulerStrategy) (*Auth, error) {
	if s == nil {
		return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	entry := selectorLogEntry(ctx)
	providerKey := strings.ToLower(strings.TrimSpace(provider))
	modelKey := canonicalModelKey(model)
	pinnedAuthID := pinnedAuthIDFromMetadata(opts.Metadata)
	preferWebsocket := cliproxyexecutor.DownstreamWebsocket(ctx) && providerPrefersWebsocketTransport(providerKey) && pinnedAuthID == ""

	s.mu.Lock()
	defer s.mu.Unlock()
	if strategy == schedulerStrategyCurrent {
		strategy = s.strategy
	}
	providerState := s.providers[providerKey]
	if providerState == nil {
		return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	shard := providerState.ensureModelLocked(modelKey, time.Now())
	if shard == nil {
		return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	predicate := func(entry *scheduledAuth) bool {
		if entry == nil || entry.auth == nil {
			return false
		}
		if pinnedAuthID != "" && entry.auth.ID != pinnedAuthID {
			return false
		}
		if len(tried) > 0 {
			if _, ok := tried[entry.auth.ID]; ok {
				return false
			}
		}
		return true
	}
	now := time.Now()
	shard.promoteExpiredLocked(now)
	selectionPredicate := predicate
	if strategy == schedulerStrategyQuota {
		selectionPredicate = quotaPriorityScheduledPredicate(now, s.quotaWindow, predicate)
	}
	priorityReady, okPriority := shard.highestReadyPriorityLocked(preferWebsocket, selectionPredicate)
	if okPriority && entry.Logger.IsLevelEnabled(log.DebugLevel) {
		entries := shard.entriesAtPriorityLocked(preferWebsocket, priorityReady)
		selectablePredicate := minimumQuotaScheduledPredicate(entries, s.minimumQuotaPercent, selectionPredicate)
		entry.Debugf("routing scheduler candidates | provider=%s model=%s strategy=%s priority=%d candidates=%d minimum_quota_percent=%.2f quota_priority_window=%s auths=%s",
			providerKey, model, schedulerStrategyLogName(strategy), priorityReady, len(entries), s.minimumQuotaPercent, s.quotaWindow, formatScheduledSelectionCandidates(entries, selectablePredicate, now, s.quotaWindow))
	}
	if okPriority {
		if picked := shard.pickReadyAtPriorityLocked(preferWebsocket, priorityReady, strategy, s.quotaWindow, s.minimumQuotaPercent, selectionPredicate); picked != nil {
			winningWindow, resetIn, quota, score, multiplier := quotaPrioritySelectedLogFields(picked, now, s.quotaWindow)
			entry.Infof("routing scheduler: selected | provider=%s model=%s strategy=%s auth=%s priority=%d minimum_quota_percent=%.2f winning_window=%s reset_in=%s quota_percent=%s score=%s plan_multiplier=%s",
				providerKey, model, schedulerStrategyLogName(strategy), picked.ID, priorityReady, s.minimumQuotaPercent, winningWindow, resetIn, quota, score, multiplier)
			return picked, nil
		}
	}
	if entry.Logger.IsLevelEnabled(log.DebugLevel) {
		entry.Debugf("routing scheduler: no ready auth selected | provider=%s model=%s strategy=%s minimum_quota_percent=%.2f", providerKey, model, schedulerStrategyLogName(strategy), s.minimumQuotaPercent)
	}
	return nil, shard.unavailableErrorLocked(provider, model, predicate)
}

func providerPrefersWebsocketTransport(providerKey string) bool {
	switch strings.ToLower(strings.TrimSpace(providerKey)) {
	case "codex", "xai":
		return true
	default:
		return false
	}
}

// pickMixed returns the next auth and provider for a mixed-provider request.
func (s *authScheduler) pickMixed(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, string, error) {
	return s.pickMixedWithStrategy(ctx, providers, model, opts, tried, schedulerStrategyCurrent)
}

func (s *authScheduler) pickMixedWithStrategy(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, strategy schedulerStrategy) (*Auth, string, error) {
	if s == nil {
		return nil, "", &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	entry := selectorLogEntry(ctx)
	normalized := normalizeProviderKeys(providers)
	if len(normalized) == 0 {
		return nil, "", &Error{Code: "provider_not_found", Message: "no provider supplied"}
	}
	if len(normalized) == 1 {
		// When a single provider is eligible, reuse pickSingle so provider-specific preferences
		// (for example Codex websocket transport) are applied consistently.
		providerKey := normalized[0]
		picked, errPick := s.pickSingleWithStrategy(ctx, providerKey, model, opts, tried, strategy)
		if errPick != nil {
			return nil, "", errPick
		}
		if picked == nil {
			return nil, "", &Error{Code: "auth_not_found", Message: "no auth available"}
		}
		return picked, providerKey, nil
	}
	pinnedAuthID := pinnedAuthIDFromMetadata(opts.Metadata)
	modelKey := canonicalModelKey(model)

	s.mu.Lock()
	defer s.mu.Unlock()
	if strategy == schedulerStrategyCurrent {
		strategy = s.strategy
	}
	if pinnedAuthID != "" {
		providerKey := s.authProviders[pinnedAuthID]
		if providerKey == "" || !containsProvider(normalized, providerKey) {
			return nil, "", &Error{Code: "auth_not_found", Message: "no auth available"}
		}
		providerState := s.providers[providerKey]
		if providerState == nil {
			return nil, "", &Error{Code: "auth_not_found", Message: "no auth available"}
		}
		shard := providerState.ensureModelLocked(modelKey, time.Now())
		predicate := func(entry *scheduledAuth) bool {
			if entry == nil || entry.auth == nil || entry.auth.ID != pinnedAuthID {
				return false
			}
			if len(tried) == 0 {
				return true
			}
			_, ok := tried[pinnedAuthID]
			return !ok
		}
		now := time.Now()
		shard.promoteExpiredLocked(now)
		selectionPredicate := predicate
		if strategy == schedulerStrategyQuota {
			selectionPredicate = quotaPriorityScheduledPredicate(now, s.quotaWindow, predicate)
		}
		priorityReady, okPriority := shard.highestReadyPriorityLocked(false, selectionPredicate)
		if okPriority && entry.Logger.IsLevelEnabled(log.DebugLevel) {
			entries := shard.entriesAtPriorityLocked(false, priorityReady)
			selectablePredicate := minimumQuotaScheduledPredicate(entries, s.minimumQuotaPercent, selectionPredicate)
			entry.Debugf("routing scheduler candidates | provider=%s model=%s strategy=%s priority=%d pinned_auth=%s candidates=%d minimum_quota_percent=%.2f quota_priority_window=%s auths=%s",
				providerKey, model, schedulerStrategyLogName(strategy), priorityReady, pinnedAuthID, len(entries), s.minimumQuotaPercent, s.quotaWindow, formatScheduledSelectionCandidates(entries, selectablePredicate, now, s.quotaWindow))
		}
		if okPriority {
			if picked := shard.pickReadyAtPriorityLocked(false, priorityReady, strategy, s.quotaWindow, s.minimumQuotaPercent, selectionPredicate); picked != nil {
				winningWindow, resetIn, quota, score, multiplier := quotaPrioritySelectedLogFields(picked, now, s.quotaWindow)
				entry.Infof("routing scheduler: selected | provider=%s model=%s strategy=%s auth=%s priority=%d pinned_auth=%s minimum_quota_percent=%.2f winning_window=%s reset_in=%s quota_percent=%s score=%s plan_multiplier=%s",
					providerKey, model, schedulerStrategyLogName(strategy), picked.ID, priorityReady, pinnedAuthID, s.minimumQuotaPercent, winningWindow, resetIn, quota, score, multiplier)
				return picked, providerKey, nil
			}
		}
		if entry.Logger.IsLevelEnabled(log.DebugLevel) {
			entry.Debugf("routing scheduler: no ready auth selected | provider=%s model=%s strategy=%s pinned_auth=%s minimum_quota_percent=%.2f",
				providerKey, model, schedulerStrategyLogName(strategy), pinnedAuthID, s.minimumQuotaPercent)
		}
		return nil, "", shard.unavailableErrorLocked("mixed", model, predicate)
	}

	predicate := triedPredicate(tried)
	candidateShards := make([]*modelScheduler, len(normalized))
	bestPriority := 0
	hasCandidate := false
	now := time.Now()
	selectionPredicate := predicate
	if strategy == schedulerStrategyQuota {
		selectionPredicate = quotaPriorityScheduledPredicate(now, s.quotaWindow, predicate)
	}
	for providerIndex, providerKey := range normalized {
		providerState := s.providers[providerKey]
		if providerState == nil {
			continue
		}
		shard := providerState.ensureModelLocked(modelKey, now)
		candidateShards[providerIndex] = shard
		if shard == nil {
			continue
		}
		priorityReady, okPriority := shard.highestReadyPriorityLocked(false, selectionPredicate)
		if !okPriority {
			continue
		}
		if !hasCandidate || priorityReady > bestPriority {
			bestPriority = priorityReady
			hasCandidate = true
		}
	}
	if !hasCandidate {
		return nil, "", s.mixedUnavailableErrorLocked(normalized, model, tried)
	}
	globalPredicate := s.mixedMinimumQuotaPredicateLocked(candidateShards, bestPriority, s.minimumQuotaPercent, selectionPredicate)
	if entry.Logger.IsLevelEnabled(log.DebugLevel) {
		entries := scheduledEntriesAtPriority(candidateShards, bestPriority)
		entry.Debugf("routing scheduler candidates | provider=mixed providers=%s model=%s strategy=%s priority=%d candidates=%d minimum_quota_percent=%.2f quota_priority_window=%s auths=%s",
			strings.Join(normalized, ","), model, schedulerStrategyLogName(strategy), bestPriority, len(entries), s.minimumQuotaPercent, s.quotaWindow, formatScheduledSelectionCandidates(entries, globalPredicate, now, s.quotaWindow))
	}

	if strategy == schedulerStrategyFillFirst {
		for providerIndex, providerKey := range normalized {
			shard := candidateShards[providerIndex]
			if shard == nil {
				continue
			}
			picked := shard.pickReadyAtPriorityLocked(false, bestPriority, strategy, s.quotaWindow, 0, globalPredicate)
			if picked != nil {
				winningWindow, resetIn, quota, score, multiplier := quotaPrioritySelectedLogFields(picked, now, s.quotaWindow)
				entry.Infof("routing scheduler: selected | provider=mixed selected_provider=%s model=%s strategy=%s auth=%s priority=%d minimum_quota_percent=%.2f winning_window=%s reset_in=%s quota_percent=%s score=%s plan_multiplier=%s",
					providerKey, model, schedulerStrategyLogName(strategy), picked.ID, bestPriority, s.minimumQuotaPercent, winningWindow, resetIn, quota, score, multiplier)
				return picked, providerKey, nil
			}
		}
		return nil, "", s.mixedUnavailableErrorLocked(normalized, model, tried)
	}

	if strategy == schedulerStrategyQuota {
		for providerIndex, providerKey := range normalized {
			shard := candidateShards[providerIndex]
			if shard == nil {
				continue
			}
			picked := shard.pickQuotaWarmupAtPriorityLocked(false, bestPriority, s.quotaWindow, 0, globalPredicate)
			if picked == nil {
				continue
			}
			winningWindow, resetIn, quota, score, multiplier := quotaPrioritySelectedLogFields(picked, now, s.quotaWindow)
			entry.Infof("routing scheduler: selected | provider=mixed selected_provider=%s model=%s strategy=%s reason=quota-warmup auth=%s priority=%d minimum_quota_percent=%.2f winning_window=%s reset_in=%s quota_percent=%s score=%s plan_multiplier=%s probe_cooldown=%s",
				providerKey, model, schedulerStrategyLogName(strategy), picked.ID, bestPriority, s.minimumQuotaPercent, winningWindow, resetIn, quota, score, multiplier, quotaWarmupInFlightCooldown)
			return picked, providerKey, nil
		}

		var pickedAuth *Auth
		pickedProvider := ""
		var pickedWindow quotaWindowScore
		for providerIndex, providerKey := range normalized {
			shard := candidateShards[providerIndex]
			if shard == nil {
				continue
			}
			candidate, windowScore, okWindow := shard.pickQuotaAtPriorityLocked(false, bestPriority, s.quotaWindow, 0, globalPredicate)
			if candidate == nil {
				continue
			}
			if !okWindow {
				continue
			}
			if quotaPriorityCandidateBefore(candidate, windowScore, pickedAuth, pickedWindow) {
				pickedAuth = candidate
				pickedProvider = providerKey
				pickedWindow = windowScore
			}
		}
		if pickedAuth != nil {
			winningWindow, resetIn, quota, score, multiplier := quotaPrioritySelectedLogFields(pickedAuth, now, s.quotaWindow)
			entry.Infof("routing scheduler: selected | provider=mixed selected_provider=%s model=%s strategy=%s reason=quota-window auth=%s priority=%d minimum_quota_percent=%.2f winning_window=%s reset_in=%s quota_percent=%s score=%s plan_multiplier=%s",
				pickedProvider, model, schedulerStrategyLogName(strategy), pickedAuth.ID, bestPriority, s.minimumQuotaPercent, winningWindow, resetIn, quota, score, multiplier)
			return pickedAuth, pickedProvider, nil
		}
	}

	cursorKey := strings.Join(normalized, ",") + ":" + modelKey
	weights := make([]int, len(normalized))
	segmentStarts := make([]int, len(normalized))
	segmentEnds := make([]int, len(normalized))
	totalWeight := 0
	for providerIndex, shard := range candidateShards {
		segmentStarts[providerIndex] = totalWeight
		if shard != nil {
			weights[providerIndex] = shard.readyCountAtPriorityLocked(false, bestPriority)
		}
		totalWeight += weights[providerIndex]
		segmentEnds[providerIndex] = totalWeight
	}
	if totalWeight == 0 {
		return nil, "", s.mixedUnavailableErrorLocked(normalized, model, tried)
	}

	startSlot := s.mixedCursors[cursorKey] % totalWeight
	startProviderIndex := -1
	for providerIndex := range normalized {
		if weights[providerIndex] == 0 {
			continue
		}
		if startSlot < segmentEnds[providerIndex] {
			startProviderIndex = providerIndex
			break
		}
	}
	if startProviderIndex < 0 {
		return nil, "", s.mixedUnavailableErrorLocked(normalized, model, tried)
	}

	slot := startSlot
	for offset := 0; offset < len(normalized); offset++ {
		providerIndex := (startProviderIndex + offset) % len(normalized)
		if weights[providerIndex] == 0 {
			continue
		}
		if providerIndex != startProviderIndex {
			slot = segmentStarts[providerIndex]
		}
		providerKey := normalized[providerIndex]
		shard := candidateShards[providerIndex]
		if shard == nil {
			continue
		}
		picked := shard.pickReadyAtPriorityLocked(false, bestPriority, schedulerStrategyRoundRobin, s.quotaWindow, 0, globalPredicate)
		if picked == nil {
			continue
		}
		s.mixedCursors[cursorKey] = slot + 1
		winningWindow, resetIn, quota, score, multiplier := quotaPrioritySelectedLogFields(picked, now, s.quotaWindow)
		entry.Infof("routing scheduler: selected | provider=mixed selected_provider=%s model=%s strategy=%s reason=round-robin auth=%s priority=%d cursor=%d minimum_quota_percent=%.2f winning_window=%s reset_in=%s quota_percent=%s score=%s plan_multiplier=%s",
			providerKey, model, schedulerStrategyLogName(strategy), picked.ID, bestPriority, slot, s.minimumQuotaPercent, winningWindow, resetIn, quota, score, multiplier)
		return picked, providerKey, nil
	}
	return nil, "", s.mixedUnavailableErrorLocked(normalized, model, tried)
}

func schedulerStrategyLogName(strategy schedulerStrategy) string {
	switch strategy {
	case schedulerStrategyRoundRobin:
		return "round-robin"
	case schedulerStrategyFillFirst:
		return "fill-first"
	case schedulerStrategyQuota:
		return "quota-priority"
	case schedulerStrategyCustom:
		return "custom"
	case schedulerStrategyCurrent:
		return "current"
	default:
		return fmt.Sprintf("unknown(%d)", strategy)
	}
}

func scheduledEntriesAtPriority(shards []*modelScheduler, priority int) []*scheduledAuth {
	entries := make([]*scheduledAuth, 0)
	for _, shard := range shards {
		if shard == nil {
			continue
		}
		entries = append(entries, shard.entriesAtPriorityLocked(false, priority)...)
	}
	return entries
}

func formatScheduledSelectionCandidates(entries []*scheduledAuth, predicate func(*scheduledAuth) bool, now time.Time, window time.Duration) string {
	auths := make([]*Auth, 0, len(entries))
	for _, entry := range entries {
		if entry == nil || entry.auth == nil {
			continue
		}
		if predicate != nil && !predicate(entry) {
			continue
		}
		auths = append(auths, entry.auth)
	}
	return formatAuthSelectionCandidates(auths, now, window)
}

func (s *authScheduler) mixedMinimumQuotaPredicateLocked(shards []*modelScheduler, priority int, threshold float64, predicate func(*scheduledAuth) bool) func(*scheduledAuth) bool {
	if normalizeMinimumQuotaPercent(threshold) <= 0 {
		return predicate
	}
	entries := make([]*scheduledAuth, 0)
	for _, shard := range shards {
		if shard == nil {
			continue
		}
		entries = append(entries, shard.entriesAtPriorityLocked(false, priority)...)
	}
	return minimumQuotaScheduledPredicate(entries, threshold, predicate)
}

// mixedUnavailableErrorLocked synthesizes the mixed-provider cooldown or unavailable error.
func (s *authScheduler) mixedUnavailableErrorLocked(providers []string, model string, tried map[string]struct{}) error {
	now := time.Now()
	total := 0
	cooldownCount := 0
	earliest := time.Time{}
	for _, providerKey := range providers {
		providerState := s.providers[providerKey]
		if providerState == nil {
			continue
		}
		shard := providerState.ensureModelLocked(canonicalModelKey(model), now)
		if shard == nil {
			continue
		}
		localTotal, localCooldownCount, localEarliest := shard.availabilitySummaryLocked(triedPredicate(tried))
		total += localTotal
		cooldownCount += localCooldownCount
		if !localEarliest.IsZero() && (earliest.IsZero() || localEarliest.Before(earliest)) {
			earliest = localEarliest
		}
	}
	if total == 0 {
		return &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	if cooldownCount == total && !earliest.IsZero() {
		resetIn := earliest.Sub(now)
		if resetIn < 0 {
			resetIn = 0
		}
		return newModelCooldownError(model, "", resetIn)
	}
	return &Error{Code: "auth_unavailable", Message: "no auth available"}
}

// triedPredicate builds a filter that excludes auths already attempted for the current request.
func triedPredicate(tried map[string]struct{}) func(*scheduledAuth) bool {
	if len(tried) == 0 {
		return func(entry *scheduledAuth) bool { return entry != nil && entry.auth != nil }
	}
	return func(entry *scheduledAuth) bool {
		if entry == nil || entry.auth == nil {
			return false
		}
		_, ok := tried[entry.auth.ID]
		return !ok
	}
}

// normalizeProviderKeys lowercases, trims, and de-duplicates provider keys while preserving order.
func normalizeProviderKeys(providers []string) []string {
	seen := make(map[string]struct{}, len(providers))
	out := make([]string, 0, len(providers))
	for _, provider := range providers {
		providerKey := strings.ToLower(strings.TrimSpace(provider))
		if providerKey == "" {
			continue
		}
		if _, ok := seen[providerKey]; ok {
			continue
		}
		seen[providerKey] = struct{}{}
		out = append(out, providerKey)
	}
	return out
}

// containsProvider reports whether provider is present in the normalized provider list.
func containsProvider(providers []string, provider string) bool {
	for _, candidate := range providers {
		if candidate == provider {
			return true
		}
	}
	return false
}

// upsertAuthLocked updates one auth in-place while the scheduler mutex is held.
func (s *authScheduler) upsertAuthLocked(auth *Auth, now time.Time) {
	if auth == nil {
		return
	}
	authID := strings.TrimSpace(auth.ID)
	providerKey := executorKeyFromAuth(auth)
	if authID == "" || providerKey == "" || auth.Disabled {
		s.removeAuthLocked(authID)
		return
	}
	if previousProvider := s.authProviders[authID]; previousProvider != "" && previousProvider != providerKey {
		if previousState := s.providers[previousProvider]; previousState != nil {
			previousState.removeAuthLocked(authID)
		}
	}
	meta := buildScheduledAuthMeta(auth)
	s.authProviders[authID] = providerKey
	s.ensureProviderLocked(providerKey).upsertAuthLocked(meta, now)
}

// removeAuthLocked removes one auth from the scheduler while the scheduler mutex is held.
func (s *authScheduler) removeAuthLocked(authID string) {
	if authID == "" {
		return
	}
	if providerKey := s.authProviders[authID]; providerKey != "" {
		if providerState := s.providers[providerKey]; providerState != nil {
			providerState.removeAuthLocked(authID)
		}
		delete(s.authProviders, authID)
	}
}

// ensureProviderLocked returns the provider scheduler for providerKey, creating it when needed.
func (s *authScheduler) ensureProviderLocked(providerKey string) *providerScheduler {
	if s.providers == nil {
		s.providers = make(map[string]*providerScheduler)
	}
	providerState := s.providers[providerKey]
	if providerState == nil {
		providerState = &providerScheduler{
			providerKey: providerKey,
			auths:       make(map[string]*scheduledAuthMeta),
			modelShards: make(map[string]*modelScheduler),
		}
		s.providers[providerKey] = providerState
	}
	return providerState
}

// buildScheduledAuthMeta extracts the scheduling metadata needed for shard bookkeeping.
func buildScheduledAuthMeta(auth *Auth) *scheduledAuthMeta {
	providerKey := executorKeyFromAuth(auth)
	return &scheduledAuthMeta{
		auth:              auth,
		providerKey:       providerKey,
		priority:          authPriority(auth),
		websocketEnabled:  authWebsocketsEnabled(auth),
		supportedModelSet: supportedModelSetForAuth(auth.ID),
	}
}

// supportedModelSetForAuth snapshots the registry models currently registered for an auth.
func supportedModelSetForAuth(authID string) map[string]struct{} {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return nil
	}
	models := registry.GetGlobalRegistry().GetModelsForClient(authID)
	if len(models) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(models))
	for _, model := range models {
		if model == nil {
			continue
		}
		modelKey := canonicalModelKey(model.ID)
		if modelKey == "" {
			continue
		}
		set[modelKey] = struct{}{}
	}
	return set
}

// upsertAuthLocked updates every existing model shard that can reference the auth metadata.
func (p *providerScheduler) upsertAuthLocked(meta *scheduledAuthMeta, now time.Time) {
	if p == nil || meta == nil || meta.auth == nil {
		return
	}
	p.auths[meta.auth.ID] = meta
	for modelKey, shard := range p.modelShards {
		if shard == nil {
			continue
		}
		if !meta.supportsModel(modelKey) {
			shard.removeEntryLocked(meta.auth.ID)
			continue
		}
		shard.upsertEntryLocked(meta, now)
	}
}

// removeAuthLocked removes an auth from all model shards owned by the provider scheduler.
func (p *providerScheduler) removeAuthLocked(authID string) {
	if p == nil || authID == "" {
		return
	}
	delete(p.auths, authID)
	for _, shard := range p.modelShards {
		if shard != nil {
			shard.removeEntryLocked(authID)
		}
	}
}

// ensureModelLocked returns the shard for modelKey, building it lazily from provider auths.
func (p *providerScheduler) ensureModelLocked(modelKey string, now time.Time) *modelScheduler {
	if p == nil {
		return nil
	}
	modelKey = canonicalModelKey(modelKey)
	if shard, ok := p.modelShards[modelKey]; ok && shard != nil {
		shard.promoteExpiredLocked(now)
		return shard
	}
	shard := &modelScheduler{
		modelKey:        modelKey,
		entries:         make(map[string]*scheduledAuth),
		readyByPriority: make(map[int]*readyBucket),
	}
	for _, meta := range p.auths {
		if meta == nil || !meta.supportsModel(modelKey) {
			continue
		}
		shard.upsertEntryLocked(meta, now)
	}
	p.modelShards[modelKey] = shard
	return shard
}

// supportsModel reports whether the auth metadata currently supports modelKey.
func (m *scheduledAuthMeta) supportsModel(modelKey string) bool {
	modelKey = canonicalModelKey(modelKey)
	if modelKey == "" {
		return true
	}
	if len(m.supportedModelSet) == 0 {
		return false
	}
	_, ok := m.supportedModelSet[modelKey]
	return ok
}

// upsertEntryLocked updates or inserts one auth entry and rebuilds indexes when ordering changes.
func (m *modelScheduler) upsertEntryLocked(meta *scheduledAuthMeta, now time.Time) {
	if m == nil || meta == nil || meta.auth == nil {
		return
	}
	entry, ok := m.entries[meta.auth.ID]
	if !ok || entry == nil {
		entry = &scheduledAuth{}
		m.entries[meta.auth.ID] = entry
	}
	previousState := entry.state
	previousNextRetryAt := entry.nextRetryAt
	previousPriority := 0
	previousWebsocketEnabled := false
	if entry.meta != nil {
		previousPriority = entry.meta.priority
		previousWebsocketEnabled = entry.meta.websocketEnabled
	}

	entry.meta = meta
	entry.auth = meta.auth
	entry.nextRetryAt = time.Time{}
	blocked, reason, next := isAuthBlockedForModel(meta.auth, m.modelKey, now)
	switch {
	case !blocked:
		entry.state = scheduledStateReady
	case reason == blockReasonCooldown:
		entry.state = scheduledStateCooldown
		entry.nextRetryAt = next
	case reason == blockReasonDisabled:
		entry.state = scheduledStateDisabled
	default:
		entry.state = scheduledStateBlocked
		entry.nextRetryAt = next
	}

	if ok && previousState == entry.state && previousNextRetryAt.Equal(entry.nextRetryAt) && previousPriority == meta.priority && previousWebsocketEnabled == meta.websocketEnabled {
		return
	}
	m.rebuildIndexesLocked()
}

// removeEntryLocked deletes one auth entry and rebuilds the shard indexes if needed.
func (m *modelScheduler) removeEntryLocked(authID string) {
	if m == nil || authID == "" {
		return
	}
	if _, ok := m.entries[authID]; !ok {
		return
	}
	delete(m.entries, authID)
	m.rebuildIndexesLocked()
}

// promoteExpiredLocked reevaluates blocked auths whose retry time has elapsed.
func (m *modelScheduler) promoteExpiredLocked(now time.Time) {
	if m == nil || len(m.blocked) == 0 {
		return
	}
	changed := false
	for _, entry := range m.blocked {
		if entry == nil || entry.auth == nil {
			continue
		}
		if entry.nextRetryAt.IsZero() || entry.nextRetryAt.After(now) {
			continue
		}
		blocked, reason, next := isAuthBlockedForModel(entry.auth, m.modelKey, now)
		switch {
		case !blocked:
			entry.state = scheduledStateReady
			entry.nextRetryAt = time.Time{}
		case reason == blockReasonCooldown:
			entry.state = scheduledStateCooldown
			entry.nextRetryAt = next
		case reason == blockReasonDisabled:
			entry.state = scheduledStateDisabled
			entry.nextRetryAt = time.Time{}
		default:
			entry.state = scheduledStateBlocked
			entry.nextRetryAt = next
		}
		changed = true
	}
	if changed {
		m.rebuildIndexesLocked()
	}
}

// pickReadyLocked selects the next ready auth from the highest available priority bucket.
func (m *modelScheduler) pickReadyLocked(preferWebsocket bool, strategy schedulerStrategy, quotaWindow time.Duration, minimumQuotaPercent float64, predicate func(*scheduledAuth) bool) *Auth {
	if m == nil {
		return nil
	}
	m.promoteExpiredLocked(time.Now())
	priorityReady, okPriority := m.highestReadyPriorityLocked(preferWebsocket, predicate)
	if !okPriority {
		return nil
	}
	return m.pickReadyAtPriorityLocked(preferWebsocket, priorityReady, strategy, quotaWindow, minimumQuotaPercent, predicate)
}

// highestReadyPriorityLocked returns the highest priority bucket that still has a matching ready auth.
// The caller must ensure expired entries are already promoted when needed.
func (m *modelScheduler) highestReadyPriorityLocked(preferWebsocket bool, predicate func(*scheduledAuth) bool) (int, bool) {
	if m == nil {
		return 0, false
	}
	if preferWebsocket {
		// When downstream is websocket and Codex supports websocket transport, prefer websocket-enabled
		// credentials even if they are in a lower priority tier than HTTP-only credentials.
		for _, priority := range m.priorityOrder {
			bucket := m.readyByPriority[priority]
			if bucket == nil {
				continue
			}
			if bucket.ws.pickFirst(predicate) != nil {
				return priority, true
			}
		}
	}
	for _, priority := range m.priorityOrder {
		bucket := m.readyByPriority[priority]
		if bucket == nil {
			continue
		}
		if bucket.all.pickFirst(predicate) != nil {
			return priority, true
		}
	}
	return 0, false
}

// pickReadyAtPriorityLocked selects the next ready auth from a specific priority bucket.
// The caller must ensure expired entries are already promoted when needed.
func (m *modelScheduler) pickReadyAtPriorityLocked(preferWebsocket bool, priority int, strategy schedulerStrategy, quotaWindow time.Duration, minimumQuotaPercent float64, predicate func(*scheduledAuth) bool) *Auth {
	if m == nil {
		return nil
	}
	bucket := m.readyByPriority[priority]
	if bucket == nil {
		return nil
	}
	view := &bucket.all
	if preferWebsocket && bucket.ws.pickFirst(predicate) != nil {
		view = &bucket.ws
	}
	predicate = minimumQuotaScheduledPredicate(view.flat, minimumQuotaPercent, predicate)
	var picked *scheduledAuth
	if strategy == schedulerStrategyFillFirst {
		picked = view.pickFirst(predicate)
	} else if strategy == schedulerStrategyQuota {
		picked = view.pickQuotaPriority(time.Now(), quotaWindow, predicate)
	} else {
		picked = view.pickRoundRobin(predicate)
	}
	if picked == nil || picked.auth == nil {
		return nil
	}
	return picked.auth
}

func (m *modelScheduler) pickQuotaAtPriorityLocked(preferWebsocket bool, priority int, quotaWindow time.Duration, minimumQuotaPercent float64, predicate func(*scheduledAuth) bool) (*Auth, quotaWindowScore, bool) {
	if m == nil {
		return nil, quotaWindowScore{}, false
	}
	bucket := m.readyByPriority[priority]
	if bucket == nil {
		return nil, quotaWindowScore{}, false
	}
	view := &bucket.all
	if preferWebsocket && bucket.ws.pickFirst(predicate) != nil {
		view = &bucket.ws
	}
	predicate = minimumQuotaScheduledPredicate(view.flat, minimumQuotaPercent, predicate)
	picked, windowScore, ok := view.firstQuotaPriorityCandidate(time.Now(), quotaWindow, predicate)
	if picked == nil || picked.auth == nil {
		return nil, quotaWindowScore{}, false
	}
	return picked.auth, windowScore, ok
}

func (m *modelScheduler) pickQuotaWarmupAtPriorityLocked(preferWebsocket bool, priority int, quotaWindow time.Duration, minimumQuotaPercent float64, predicate func(*scheduledAuth) bool) *Auth {
	if m == nil {
		return nil
	}
	bucket := m.readyByPriority[priority]
	if bucket == nil {
		return nil
	}
	view := &bucket.all
	if preferWebsocket && bucket.ws.pickFirst(predicate) != nil {
		view = &bucket.ws
	}
	predicate = minimumQuotaScheduledPredicate(view.flat, minimumQuotaPercent, predicate)
	picked := view.firstQuotaWarmupCandidate(time.Now(), quotaWindow, predicate)
	if picked == nil || picked.auth == nil {
		return nil
	}
	return picked.auth
}

func (m *modelScheduler) entriesAtPriorityLocked(preferWebsocket bool, priority int) []*scheduledAuth {
	if m == nil {
		return nil
	}
	bucket := m.readyByPriority[priority]
	if bucket == nil {
		return nil
	}
	if preferWebsocket && len(bucket.ws.flat) > 0 {
		return bucket.ws.flat
	}
	return bucket.all.flat
}

func (m *modelScheduler) readyCountAtPriorityLocked(preferWebsocket bool, priority int) int {
	if m == nil {
		return 0
	}
	bucket := m.readyByPriority[priority]
	if bucket == nil {
		return 0
	}
	if preferWebsocket && len(bucket.ws.flat) > 0 {
		return len(bucket.ws.flat)
	}
	return len(bucket.all.flat)
}

// unavailableErrorLocked returns the correct unavailable or cooldown error for the shard.
func (m *modelScheduler) unavailableErrorLocked(provider, model string, predicate func(*scheduledAuth) bool) error {
	now := time.Now()
	total, cooldownCount, earliest := m.availabilitySummaryLocked(predicate)
	if total == 0 {
		return &Error{Code: "auth_not_found", Message: "no auth available"}
	}
	if cooldownCount == total && !earliest.IsZero() {
		providerForError := provider
		if providerForError == "mixed" {
			providerForError = ""
		}
		resetIn := earliest.Sub(now)
		if resetIn < 0 {
			resetIn = 0
		}
		return newModelCooldownError(model, providerForError, resetIn)
	}
	return &Error{Code: "auth_unavailable", Message: "no auth available"}
}

// availabilitySummaryLocked summarizes total candidates, cooldown count, and earliest retry time.
func (m *modelScheduler) availabilitySummaryLocked(predicate func(*scheduledAuth) bool) (int, int, time.Time) {
	if m == nil {
		return 0, 0, time.Time{}
	}
	total := 0
	cooldownCount := 0
	earliest := time.Time{}
	for _, entry := range m.entries {
		if predicate != nil && !predicate(entry) {
			continue
		}
		total++
		if entry == nil || entry.auth == nil {
			continue
		}
		if entry.state != scheduledStateCooldown {
			continue
		}
		cooldownCount++
		if !entry.nextRetryAt.IsZero() && (earliest.IsZero() || entry.nextRetryAt.Before(earliest)) {
			earliest = entry.nextRetryAt
		}
	}
	return total, cooldownCount, earliest
}

// rebuildIndexesLocked reconstructs ready and blocked views from the current entry map.
func (m *modelScheduler) rebuildIndexesLocked() {
	cursorStates := make(map[int]readyBucketCursorState, len(m.readyByPriority))
	for priority, bucket := range m.readyByPriority {
		if bucket == nil {
			continue
		}
		cursorStates[priority] = readyBucketCursorState{
			all: snapshotReadyViewCursors(bucket.all),
			ws:  snapshotReadyViewCursors(bucket.ws),
		}
	}

	m.readyByPriority = make(map[int]*readyBucket)
	m.priorityOrder = m.priorityOrder[:0]
	m.blocked = m.blocked[:0]
	priorityBuckets := make(map[int][]*scheduledAuth)
	for _, entry := range m.entries {
		if entry == nil || entry.auth == nil {
			continue
		}
		switch entry.state {
		case scheduledStateReady:
			priority := entry.meta.priority
			priorityBuckets[priority] = append(priorityBuckets[priority], entry)
		case scheduledStateCooldown, scheduledStateBlocked:
			m.blocked = append(m.blocked, entry)
		}
	}
	for priority, entries := range priorityBuckets {
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].auth.ID < entries[j].auth.ID
		})
		bucket := buildReadyBucket(entries)
		if cursorState, ok := cursorStates[priority]; ok && bucket != nil {
			restoreReadyViewCursors(&bucket.all, cursorState.all)
			restoreReadyViewCursors(&bucket.ws, cursorState.ws)
		}
		m.readyByPriority[priority] = bucket
		m.priorityOrder = append(m.priorityOrder, priority)
	}
	sort.Slice(m.priorityOrder, func(i, j int) bool {
		return m.priorityOrder[i] > m.priorityOrder[j]
	})
	sort.Slice(m.blocked, func(i, j int) bool {
		left := m.blocked[i]
		right := m.blocked[j]
		if left == nil || right == nil {
			return left != nil
		}
		if left.nextRetryAt.Equal(right.nextRetryAt) {
			return left.auth.ID < right.auth.ID
		}
		if left.nextRetryAt.IsZero() {
			return false
		}
		if right.nextRetryAt.IsZero() {
			return true
		}
		return left.nextRetryAt.Before(right.nextRetryAt)
	})
}

// buildReadyBucket prepares the general and websocket-only ready views for one priority bucket.
func buildReadyBucket(entries []*scheduledAuth) *readyBucket {
	bucket := &readyBucket{}
	bucket.all = buildReadyView(entries)
	wsEntries := make([]*scheduledAuth, 0, len(entries))
	for _, entry := range entries {
		if entry != nil && entry.meta != nil && entry.meta.websocketEnabled {
			wsEntries = append(wsEntries, entry)
		}
	}
	bucket.ws = buildReadyView(wsEntries)
	return bucket
}

// buildReadyView creates a flat view for rotation.
func buildReadyView(entries []*scheduledAuth) readyView {
	return readyView{flat: append([]*scheduledAuth(nil), entries...)}
}

// pickFirst returns the first ready entry that satisfies predicate without advancing cursors.
func (v *readyView) pickFirst(predicate func(*scheduledAuth) bool) *scheduledAuth {
	for _, entry := range v.flat {
		if predicate == nil || predicate(entry) {
			return entry
		}
	}
	return nil
}

// pickRoundRobin returns the next ready entry using flat round-robin traversal.
func (v *readyView) pickRoundRobin(predicate func(*scheduledAuth) bool) *scheduledAuth {
	if len(v.flat) == 0 {
		return nil
	}
	start := 0
	if len(v.flat) > 0 {
		start = v.cursor % len(v.flat)
	}
	for offset := 0; offset < len(v.flat); offset++ {
		index := (start + offset) % len(v.flat)
		entry := v.flat[index]
		if predicate != nil && !predicate(entry) {
			continue
		}
		v.cursor = index + 1
		return entry
	}
	return nil
}

func (v *readyView) pickQuotaPriority(now time.Time, window time.Duration, predicate func(*scheduledAuth) bool) *scheduledAuth {
	if picked := v.firstQuotaWarmupCandidate(now, window, predicate); picked != nil {
		return picked
	}
	picked, _, ok := v.firstQuotaPriorityCandidate(now, window, predicate)
	if picked != nil {
		return picked
	}
	if ok {
		return nil
	}
	return v.pickRoundRobin(predicate)
}

func (v *readyView) firstQuotaWarmupCandidate(now time.Time, window time.Duration, predicate func(*scheduledAuth) bool) *scheduledAuth {
	for _, entry := range v.flat {
		if predicate != nil && !predicate(entry) {
			continue
		}
		if entry == nil || entry.auth == nil {
			continue
		}
		if !needsQuotaWarmup(entry.auth, now, window) {
			continue
		}
		markQuotaProbeAttempt(entry.auth, now)
		return entry
	}
	return nil
}

func (v *readyView) firstQuotaPriorityCandidate(now time.Time, window time.Duration, predicate func(*scheduledAuth) bool) (*scheduledAuth, quotaWindowScore, bool) {
	var picked *scheduledAuth
	var pickedWindow quotaWindowScore
	for _, entry := range v.flat {
		if predicate != nil && !predicate(entry) {
			continue
		}
		if entry == nil || entry.auth == nil {
			continue
		}
		windowScore, ok := bestQuotaWindowScore(entry.auth, now, window)
		if !ok {
			continue
		}
		if quotaPriorityCandidateBefore(entry.auth, windowScore, pickedAuth(picked), pickedWindow) {
			picked = entry
			pickedWindow = windowScore
		}
	}
	return picked, pickedWindow, picked != nil
}

func pickedAuth(entry *scheduledAuth) *Auth {
	if entry == nil {
		return nil
	}
	return entry.auth
}

func minimumQuotaScheduledPredicate(entries []*scheduledAuth, threshold float64, predicate func(*scheduledAuth) bool) func(*scheduledAuth) bool {
	threshold = normalizeMinimumQuotaPercent(threshold)
	if threshold <= 0 || len(entries) == 0 {
		return predicate
	}
	auths := make([]*Auth, 0, len(entries))
	for _, entry := range entries {
		if entry == nil || entry.auth == nil {
			continue
		}
		if predicate != nil && !predicate(entry) {
			continue
		}
		auths = append(auths, entry.auth)
	}
	allowed := minimumQuotaAllowedAuthIDs(auths, threshold)
	if allowed == nil {
		return predicate
	}
	return func(entry *scheduledAuth) bool {
		if predicate != nil && !predicate(entry) {
			return false
		}
		if entry == nil || entry.auth == nil {
			return false
		}
		_, ok := allowed[entry.auth.ID]
		return ok
	}
}

func quotaPriorityScheduledPredicate(now time.Time, window time.Duration, predicate func(*scheduledAuth) bool) func(*scheduledAuth) bool {
	return func(entry *scheduledAuth) bool {
		if predicate != nil && !predicate(entry) {
			return false
		}
		if entry == nil || entry.auth == nil {
			return false
		}
		_, exhausted := quotaPriorityWindowExhaustedUntil(entry.auth, now, window)
		return !exhausted
	}
}
