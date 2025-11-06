package auth_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/store/memory"
	"github.com/patrickkabwe/betterauth-go/types"
)

// --- CSRF / origin validation ---

func TestCSRFRejectsUntrustedOrigin(t *testing.T) {
	a := newTestAuth()
	resp, _ := doRequestWithHeaders(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "X", "email": "x@example.com", "password": "password123",
	}, nil, map[string]string{"Origin": "https://evil.example.net"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for untrusted origin, got %d", resp.StatusCode)
	}
}

func TestCSRFAllowsTrustedOrigin(t *testing.T) {
	a := newTestAuth()
	resp, data := doRequestWithHeaders(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "X", "email": "trusted@example.com", "password": "password123",
	}, nil, map[string]string{"Origin": "http://localhost:3000"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for trusted origin, got %d body=%s", resp.StatusCode, data)
	}
}

func TestCSRFAllowsNoOrigin(t *testing.T) {
	a := newTestAuth()
	resp, _ := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "X", "email": "noorigin@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 without origin header, got %d", resp.StatusCode)
	}
}

func TestCSRFDisabled(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Advanced.DisableCSRFCheck = true
	})
	resp, _ := doRequestWithHeaders(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "X", "email": "nocsrf@example.com", "password": "password123",
	}, nil, map[string]string{"Origin": "https://evil.example.net"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with CSRF disabled, got %d", resp.StatusCode)
	}
}

// --- CORS wildcard ---

func TestCORSWildcardOrigin(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.TrustedOrigins = []string{"https://*.example.com"}
	})
	resp, _ := doRequestWithHeaders(a, http.MethodGet, "/ok", nil, nil,
		map[string]string{"Origin": "https://app.example.com"})
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("expected wildcard origin echoed, got %q", got)
	}
}

// --- Rate limiting ---

func TestRateLimitGlobal(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.RateLimit = auth.RateLimitConfig{Enabled: true, Max: 2, Window: time.Minute}
	})
	codes := []int{}
	for i := 0; i < 3; i++ {
		resp, _ := doRequest(a, http.MethodGet, "/ok", nil, nil)
		codes = append(codes, resp.StatusCode)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("expected [200 200 429], got %v", codes)
	}
}

func TestRateLimitCustomRule(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.RateLimit = auth.RateLimitConfig{
			Enabled: true, Max: 100, Window: time.Minute,
			CustomRules: map[string]auth.RateLimitRule{
				"/sign-up/email": {Max: 1, Window: time.Minute},
			},
		}
	})
	r1, _ := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{"name": "A", "email": "a@x.com", "password": "password123"}, nil)
	r2, _ := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{"name": "B", "email": "b@x.com", "password": "password123"}, nil)
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("first sign-up should pass, got %d", r1.StatusCode)
	}
	if r2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second sign-up should hit custom limit, got %d", r2.StatusCode)
	}
	// A different path is unaffected by the sign-up rule.
	r3, _ := doRequest(a, http.MethodGet, "/ok", nil, nil)
	if r3.StatusCode != http.StatusOK {
		t.Fatalf("unrelated path should pass, got %d", r3.StatusCode)
	}
}

// --- Secret rotation ---

func TestSecretRotation(t *testing.T) {
	shared := memory.New()
	old, err := auth.New(auth.Config{Secret: "old-secret-aaaaaaaaaaaaaaaaaaaa", BaseURL: "http://localhost:8080", Store: shared})
	if err != nil {
		t.Fatal(err)
	}
	cookies := signUp(t, old, "rotate@example.com")

	// New instance rotates to a fresh primary secret but still trusts the old one.
	rotated, err := auth.New(auth.Config{
		Secret:     "new-secret-bbbbbbbbbbbbbbbbbbbb",
		OldSecrets: []string{"old-secret-aaaaaaaaaaaaaaaaaaaa"},
		BaseURL:    "http://localhost:8080",
		Store:      shared,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, data := doRequest(rotated, http.MethodGet, "/get-session", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotated instance should accept old-secret cookie, got %d body=%s", resp.StatusCode, data)
	}
	if string(data) == "null" {
		t.Fatalf("expected session, got null")
	}
}

// --- Cross-subdomain + custom cookie names ---

func TestCrossSubDomainCookieDomain(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Advanced.CrossSubDomainCookies = auth.CrossSubDomainConfig{Enabled: true, Domain: ".example.com"}
	})
	resp := signUpRaw(t, a, "domain@example.com")
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == "better-auth.session_token" {
			if c.Domain != "example.com" && c.Domain != ".example.com" {
				t.Fatalf("expected shared cookie domain, got %q", c.Domain)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("session_token cookie not set")
	}
}

func TestCustomCookieName(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Advanced.Cookies = map[string]auth.CookieOverride{
			"session_token": {Name: "my_session"},
		}
	})
	resp := signUpRaw(t, a, "customcookie@example.com")
	for _, c := range resp.Cookies() {
		if c.Name == "my_session" {
			return
		}
	}
	t.Fatal("expected custom cookie name 'my_session'")
}

// --- Database hooks ---

func TestDatabaseHooks(t *testing.T) {
	var userCreated, sessionCreated, sessionDeleted atomic.Int32
	a := newTestAuth(func(c *auth.Config) {
		c.DatabaseHooks = auth.DatabaseHooksConfig{
			User: &auth.UserDatabaseHooks{
				BeforeCreate: func(_ context.Context, u *types.User) (bool, error) {
					if u.Additional == nil {
						u.Additional = map[string]any{}
					}
					u.Additional["hooked"] = true
					return true, nil
				},
				AfterCreate: func(_ context.Context, _ *types.User) error {
					userCreated.Add(1)
					return nil
				},
			},
			Session: &auth.SessionDatabaseHooks{
				AfterCreate: func(_ context.Context, _ *types.Session) error {
					sessionCreated.Add(1)
					return nil
				},
				AfterDelete: func(_ context.Context, _ *types.Session) error {
					sessionDeleted.Add(1)
					return nil
				},
			},
		}
	})
	cookies := signUp(t, a, "hooks@example.com")
	if userCreated.Load() != 1 {
		t.Fatalf("expected user AfterCreate to fire once, got %d", userCreated.Load())
	}
	if sessionCreated.Load() < 1 {
		t.Fatalf("expected session AfterCreate to fire, got %d", sessionCreated.Load())
	}
	resp, _ := doRequest(a, http.MethodPost, "/sign-out", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-out failed: %d", resp.StatusCode)
	}
	if sessionDeleted.Load() < 1 {
		t.Fatalf("expected session AfterDelete to fire on sign-out, got %d", sessionDeleted.Load())
	}

	// BeforeCreate mutation persisted.
	u, err := a.Store().FindUserByEmail(context.Background(), "hooks@example.com")
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if u.Additional["hooked"] != true {
		t.Fatalf("expected BeforeCreate mutation persisted, got %+v", u.Additional)
	}
}

func signUpRaw(t *testing.T, a *auth.Auth, email string) *http.Response {
	t.Helper()
	resp, data := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "Test", "email": email, "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-up status = %d body=%s", resp.StatusCode, data)
	}
	return resp
}
