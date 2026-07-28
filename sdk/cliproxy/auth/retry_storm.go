package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	networkRetryStormWindow           = 10 * time.Second
	networkRetryStormCooldown         = 20 * time.Second
	networkRetryStormFailureThreshold = 8
	networkRetrySuppressedErrorCode   = "network_retry_suppressed"
)

type networkRetryStormGuard struct {
	mu        sync.Mutex
	buckets   map[string]*networkRetryStormBucket
	threshold int
	window    time.Duration
	cooldown  time.Duration
	now       func() time.Time
}

type networkRetryStormBucket struct {
	failures  []time.Time
	openUntil time.Time
	probing   bool
}

type networkRetryProbeError struct{ err error }

func (e *networkRetryProbeError) Error() string { return e.err.Error() }
func (e *networkRetryProbeError) Unwrap() error { return e.err }

func newNetworkRetryStormGuard(threshold int, window, cooldown time.Duration) *networkRetryStormGuard {
	if threshold <= 0 || window <= 0 || cooldown <= 0 {
		return nil
	}
	return &networkRetryStormGuard{buckets: make(map[string]*networkRetryStormBucket), threshold: threshold, window: window, cooldown: cooldown, now: time.Now}
}

func (m *Manager) SetSameAuthNetworkRetry(retry int) {
	if m == nil {
		return
	}
	if retry < 0 {
		retry = 0
	}
	m.sameAuthNetworkRetry.Store(int32(retry))
}

func (m *Manager) networkRetryStormBefore(ctx context.Context, auth *Auth, provider, model, stage string) (bool, error) {
	if m == nil || m.networkRetryStorm == nil {
		return false, nil
	}
	return m.networkRetryStorm.before(ctx, auth, provider, model, stage)
}

func (m *Manager) releaseNetworkRetryStormProbe(auth *Auth, provider string) {
	if m != nil && m.networkRetryStorm != nil {
		m.networkRetryStorm.releaseProbe(auth, provider)
	}
}

func (m *Manager) recordNetworkRetryStormFailure(ctx context.Context, auth *Auth, provider, model, stage, class string, err error) error {
	if m == nil || m.networkRetryStorm == nil {
		return nil
	}
	return m.networkRetryStorm.recordFailure(ctx, auth, provider, model, stage, class, err)
}

func (m *Manager) recordNetworkRetryStormSuccess(ctx context.Context, auth *Auth, provider, model, stage string) {
	if m != nil && m.networkRetryStorm != nil {
		m.networkRetryStorm.recordSuccess(ctx, auth, provider, model, stage)
	}
}

func (g *networkRetryStormGuard) before(_ context.Context, auth *Auth, provider, _, _ string) (bool, error) {
	if g == nil {
		return false, nil
	}
	key, now := networkRetryStormBucketKey(auth, provider), g.currentTime()
	g.mu.Lock()
	defer g.mu.Unlock()
	bucket := g.bucketLocked(key)
	if bucket.openUntil.After(now) || bucket.probing {
		return false, newNetworkRetrySuppressedError(provider)
	}
	if !bucket.openUntil.IsZero() {
		bucket.probing = true
		return true, nil
	}
	return false, nil
}

func (g *networkRetryStormGuard) releaseProbe(auth *Auth, provider string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if bucket := g.buckets[networkRetryStormBucketKey(auth, provider)]; bucket != nil {
		bucket.probing = false
	}
}

func (g *networkRetryStormGuard) recordFailure(_ context.Context, auth *Auth, provider, _, _, _ string, _ error) error {
	if g == nil {
		return nil
	}
	key, now := networkRetryStormBucketKey(auth, provider), g.currentTime()
	g.mu.Lock()
	defer g.mu.Unlock()
	bucket := g.bucketLocked(key)
	if bucket.probing {
		bucket.probing = false
		bucket.failures = []time.Time{now}
		bucket.openUntil = now.Add(g.cooldown)
		return newNetworkRetrySuppressedError(provider)
	}
	cutoff, kept := now.Add(-g.window), bucket.failures[:0]
	for _, failure := range bucket.failures {
		if !failure.Before(cutoff) {
			kept = append(kept, failure)
		}
	}
	bucket.failures = append(kept, now)
	if len(bucket.failures) >= g.threshold {
		bucket.openUntil = now.Add(g.cooldown)
		return newNetworkRetrySuppressedError(provider)
	}
	return nil
}

func (g *networkRetryStormGuard) recordSuccess(_ context.Context, auth *Auth, provider, _, _ string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	delete(g.buckets, networkRetryStormBucketKey(auth, provider))
	g.mu.Unlock()
}

func (g *networkRetryStormGuard) bucketLocked(key string) *networkRetryStormBucket {
	bucket := g.buckets[key]
	if bucket == nil {
		bucket = &networkRetryStormBucket{}
		g.buckets[key] = bucket
	}
	return bucket
}

func (g *networkRetryStormGuard) currentTime() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}

func networkRetryStormBucketKey(auth *Auth, provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" && auth != nil {
		provider = strings.ToLower(strings.TrimSpace(auth.Provider))
	}
	proxy := ""
	if auth != nil {
		proxy = strings.TrimSpace(auth.ProxyURL)
	}
	return provider + "|" + proxy
}

func newNetworkRetrySuppressedError(provider string) *Error {
	if provider = strings.TrimSpace(provider); provider == "" {
		provider = "upstream"
	}
	return &Error{Code: networkRetrySuppressedErrorCode, Message: fmt.Sprintf("network retry storm active for provider %s", provider), Retryable: true, HTTPStatus: http.StatusServiceUnavailable}
}

func isNetworkRetrySuppressedError(err error) bool {
	authErr, ok := err.(*Error)
	return ok && authErr.Code == networkRetrySuppressedErrorCode
}

func sameAuthNetworkRetryableError(err error) (bool, string) {
	if err == nil || errors.Is(err, context.Canceled) || isRequestInvalidError(err) {
		return false, ""
	}
	switch statusCodeFromError(err) {
	case http.StatusRequestTimeout:
		return true, "http_408"
	case http.StatusBadGateway:
		return true, "http_502"
	case http.StatusServiceUnavailable:
		return true, "http_503"
	case http.StatusGatewayTimeout:
		return true, "http_504"
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusTooManyRequests, http.StatusUnprocessableEntity:
		return false, ""
	}
	var authErr *Error
	if errors.As(err, &authErr) && authErr != nil {
		if strings.EqualFold(strings.TrimSpace(authErr.Code), "empty_stream") {
			return true, "empty_stream"
		}
		if authErr.HTTPStatus > 0 {
			return false, ""
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr != nil {
		if netErr.Timeout() {
			return true, "net_timeout"
		}
		if temporary, ok := netErr.(interface{ Temporary() bool }); ok && temporary.Temporary() {
			return true, "net_temporary"
		}
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return true, "unexpected_eof"
	}
	if errors.Is(err, io.EOF) {
		return true, "eof"
	}
	message := strings.ToLower(err.Error())
	for fragment, class := range map[string]string{
		"connection reset":                 "connection_reset",
		"connection refused":               "connection_refused",
		"broken pipe":                      "broken_pipe",
		"i/o timeout":                      "io_timeout",
		"tls handshake timeout":            "tls_handshake_timeout",
		"dial tcp":                         "dial",
		"no such host":                     "dns",
		"proxyconnect":                     "proxy_connect",
		"use of closed network connection": "closed_network_connection",
		"websocket: close 1006":            "websocket_abnormal_close",
	} {
		if strings.Contains(message, fragment) {
			return true, class
		}
	}
	if strings.Contains(message, "eof") {
		return true, "eof"
	}
	return false, ""
}

// executeWithSameAuthNetworkRetry retries transient network failures without
// consuming another credential from the outer selection loop.
func executeWithSameAuthNetworkRetry[T any](m *Manager, ctx context.Context, auth *Auth, provider, model, stage string, execute func() (T, error)) (T, error) {
	var zero T
	if m == nil {
		return execute()
	}
	limit := int(m.sameAuthNetworkRetry.Load())
	for attempt := 0; ; attempt++ {
		halfOpenProbe, errBefore := m.networkRetryStormBefore(ctx, auth, provider, model, stage)
		if errBefore != nil {
			return zero, errBefore
		}
		result, errExecute := execute()
		if errExecute == nil {
			m.recordNetworkRetryStormSuccess(ctx, auth, provider, model, stage)
			return result, nil
		}
		if errContext := ctx.Err(); errContext != nil {
			if halfOpenProbe {
				m.releaseNetworkRetryStormProbe(auth, provider)
			}
			return zero, errContext
		}
		retryable, class := sameAuthNetworkRetryableError(errExecute)
		if !retryable {
			if halfOpenProbe {
				m.releaseNetworkRetryStormProbe(auth, provider)
				return zero, &networkRetryProbeError{err: errExecute}
			}
			return result, errExecute
		}
		if errStorm := m.recordNetworkRetryStormFailure(ctx, auth, provider, model, stage, class, errExecute); errStorm != nil {
			return zero, errStorm
		}
		if attempt >= limit {
			return result, errExecute
		}
	}
}
