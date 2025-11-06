package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

// AppName defaults to "Better Auth" when empty.
const defaultAppName = "Better Auth"

// AdvancedConfig mirrors betterAuth({ advanced }) options supported in Go.
type AdvancedConfig struct {
	UseSecureCookies    bool
	CookiePrefix        string
	IPAddressHeaders    []string
	DisableIPTracking   bool
	DisableCSRFCheck    bool
	SkipTrailingSlashes bool
	GenerateID          func() (string, error)

	// CrossSubDomainCookies sets a shared cookie Domain so sessions work across
	// subdomains (e.g. app.example.com and api.example.com).
	CrossSubDomainCookies CrossSubDomainConfig
	// CookieAttributes overrides default attributes applied to all auth cookies.
	CookieAttributes CookieAttributes
	// Cookies maps a logical cookie key ("session_token", "dont_remember",
	// "session_data") to a custom name, mirroring advanced.cookies in the TS API.
	Cookies map[string]CookieOverride
}

// CrossSubDomainConfig configures cross-subdomain cookie sharing.
type CrossSubDomainConfig struct {
	Enabled bool
	// Domain is the cookie domain to set, e.g. ".example.com". Required when
	// Enabled is true.
	Domain string
}

// CookieAttributes overrides default cookie attributes.
type CookieAttributes struct {
	// SameSite overrides the SameSite mode. Zero value keeps the default (Lax).
	SameSite http.SameSite
	// Partitioned sets the CHIPS Partitioned attribute (independent cookie state).
	Partitioned bool
}

// CookieOverride customizes an individual cookie's name.
type CookieOverride struct {
	Name string
}

// DatabaseConfig mirrors betterAuth({ database }) store-related options.
type DatabaseConfig struct {
	DefaultFindManyLimit int
	GenerateID           func() (string, error)
}

// RateLimitConfig mirrors betterAuth({ rateLimit }) and is enforced by the
// request router when Enabled is true.
type RateLimitConfig struct {
	Enabled bool
	// Window is the sliding window duration (default 60s).
	Window time.Duration
	// Max is the maximum number of requests per window per client (default 100).
	Max int
	// Storage persists counters. Defaults to an in-memory store when nil.
	Storage RateLimitStorage
	// CustomRules overrides the default limit for specific paths (relative to
	// BasePath, e.g. "/sign-in/email"). Use a "*" suffix for prefix matching,
	// e.g. "/sign-in/*".
	CustomRules map[string]RateLimitRule
}

// RateLimitRule is a per-path rate limit override.
type RateLimitRule struct {
	Window time.Duration
	Max    int
}

// RateLimitStorage persists rate-limit counters (optional; in-memory default when nil).
type RateLimitStorage interface {
	Incr(ctx context.Context, key string, window time.Duration) (count int, err error)
}

// SecondaryStorage mirrors betterAuth({ secondaryStorage }) for session/cache offload.
type SecondaryStorage interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// HooksConfig mirrors betterAuth({ hooks }) request middleware.
type HooksConfig struct {
	Before func(*Context) bool
	After  func(*Context)
}

// OnAPIErrorConfig mirrors betterAuth({ onAPIError }).
type OnAPIErrorConfig struct {
	Throw    bool
	ErrorURL string
	OnError  func(err *apierror.Error, ctx *Context)
}

// DatabaseHooksConfig mirrors betterAuth({ databaseHooks }) for core store operations.
type DatabaseHooksConfig struct {
	User    *UserDatabaseHooks
	Session *SessionDatabaseHooks
}

// UserDatabaseHooks runs around user create/update/delete.
type UserDatabaseHooks struct {
	BeforeCreate func(ctx context.Context, user *types.User) (bool, error)
	AfterCreate  func(ctx context.Context, user *types.User) error
	BeforeUpdate func(ctx context.Context, user *types.User, patch store.UserUpdate) (bool, error)
	AfterUpdate  func(ctx context.Context, user *types.User) error
	BeforeDelete func(ctx context.Context, user *types.User) (bool, error)
	AfterDelete  func(ctx context.Context, user *types.User) error
}

// SessionDatabaseHooks runs around session create/update/delete.
type SessionDatabaseHooks struct {
	BeforeCreate func(ctx context.Context, session *types.Session) (bool, error)
	AfterCreate  func(ctx context.Context, session *types.Session) error
	BeforeUpdate func(ctx context.Context, session *types.Session) (bool, error)
	AfterUpdate  func(ctx context.Context, session *types.Session) error
	BeforeDelete func(ctx context.Context, session *types.Session) (bool, error)
	AfterDelete  func(ctx context.Context, session *types.Session) error
}
