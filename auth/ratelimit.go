package auth

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/patrickkabwe/betterauth-go/internal/apierror"
)

const (
	defaultRateLimitWindow = 60 * time.Second
	defaultRateLimitMax    = 100
)

type resolvedRateLimit struct {
	enabled bool
	window  time.Duration
	max     int
	storage RateLimitStorage
	rules   map[string]RateLimitRule
}

func resolveRateLimit(cfg RateLimitConfig) resolvedRateLimit {
	window := cfg.Window
	if window <= 0 {
		window = defaultRateLimitWindow
	}
	max := cfg.Max
	if max <= 0 {
		max = defaultRateLimitMax
	}
	storage := cfg.Storage
	if storage == nil {
		storage = newMemoryRateLimitStorage()
	}
	return resolvedRateLimit{
		enabled: cfg.Enabled,
		window:  window,
		max:     max,
		storage: storage,
		rules:   cfg.CustomRules,
	}
}

// ruleFor returns the rate-limit window/max and a bucket key suffix for a path.
// CustomRules are matched by exact path or by "prefix/*" wildcard.
func (rl resolvedRateLimit) ruleFor(path string) (time.Duration, int, string) {
	if rule, ok := rl.rules[path]; ok {
		window, max := ruleOrDefault(rule, rl)
		return window, max, path
	}
	for pattern, rule := range rl.rules {
		if strings.HasSuffix(pattern, "*") && strings.HasPrefix(path, strings.TrimSuffix(pattern, "*")) {
			window, max := ruleOrDefault(rule, rl)
			return window, max, pattern
		}
	}
	return rl.window, rl.max, "*"
}

func ruleOrDefault(rule RateLimitRule, rl resolvedRateLimit) (time.Duration, int) {
	window := rule.Window
	if window <= 0 {
		window = rl.window
	}
	max := rule.Max
	if max <= 0 {
		max = rl.max
	}
	return window, max
}

// rateLimitAllow enforces the configured rate limit. It returns true when the
// request is permitted, and writes a 429 response and returns false otherwise.
func (a *Auth) rateLimitAllow(c *Context, path string) bool {
	if !a.cfg.rateLimit.enabled {
		return true
	}
	window, max, ruleKey := a.cfg.rateLimit.ruleFor(path)
	ip := c.ClientIP()
	if ip == "" {
		ip = "unknown"
	}
	key := ip + "|" + ruleKey
	count, err := a.cfg.rateLimit.storage.Incr(c.R.Context(), key, window)
	if err != nil {
		// Fail open: a storage error should not lock users out.
		return true
	}
	if count > max {
		retryAfter := int(window.Seconds())
		c.W.Header().Set("Retry-After", itoa(retryAfter))
		c.WriteError(apierror.New(http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later."))
		return false
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// memoryRateLimitStorage is a fixed-window in-memory counter store. It is the
// default RateLimitStorage when none is supplied.
type memoryRateLimitStorage struct {
	mu      sync.Mutex
	entries map[string]*rateLimitEntry
}

type rateLimitEntry struct {
	count   int
	resetAt time.Time
}

func newMemoryRateLimitStorage() *memoryRateLimitStorage {
	return &memoryRateLimitStorage{entries: make(map[string]*rateLimitEntry)}
}

func (m *memoryRateLimitStorage) Incr(_ context.Context, key string, window time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	e, ok := m.entries[key]
	if !ok || now.After(e.resetAt) {
		m.entries[key] = &rateLimitEntry{count: 1, resetAt: now.Add(window)}
		return 1, nil
	}
	e.count++
	return e.count, nil
}
