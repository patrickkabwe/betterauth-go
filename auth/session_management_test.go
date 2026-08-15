package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/store/memory"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestCookieCacheGetSession(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Session.CookieCache.Enabled = true
	})
	cookies := signUp(t, a, "cache@example.com")
	for _, c := range cookies {
		if c.Name == "better-auth.session_data" && c.Value != "" {
			goto hasCache
		}
	}
	t.Fatal("expected session_data cookie on sign-up")
hasCache:
	resp, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	if resp.StatusCode != http.StatusOK || string(data) == "null" {
		t.Fatal("get session from cache failed")
	}
}

func TestDeferSessionRefreshNeedsRefresh(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Session.DeferSessionRefresh = true
	})
	cookies := signUp(t, a, "needs@example.com")

	// Force session near expiry so needsRefresh is true
	ctx := context.Background()
	st := a.Store().(*memory.Store)
	_, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	near := time.Now().Add(time.Hour)
	_, _ = st.UpdateSession(ctx, sess.Session.Token, store.SessionUpdate{ExpiresAt: &near})

	resp, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var result types.SessionResponse
	_ = json.Unmarshal(data, &result)
	if resp.StatusCode != http.StatusOK || !result.NeedsRefresh {
		t.Fatalf("expected needsRefresh, got %s", data)
	}
}

func TestDisableRefreshQueryParam(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "disableref@example.com")
	resp, _ := doRequest(a, http.MethodGet, "/get-session?disableRefresh=true", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("get session failed")
	}
}

func TestDeleteUserRequiresFreshSession(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "stale@example.com")
	ctx := context.Background()
	st := a.Store().(*memory.Store)
	_, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	old := time.Now().Add(-48 * time.Hour)
	exp := time.Now().Add(time.Hour)
	_ = st.DeleteSession(ctx, sess.Session.Token)
	_ = st.CreateSession(ctx, &types.Session{
		ID: sess.Session.ID, Token: sess.Session.Token, UserID: sess.Session.UserID,
		CreatedAt: old, UpdatedAt: old, ExpiresAt: exp,
	})
	resp, _ := doRequest(a, http.MethodPost, "/delete-user", map[string]any{}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected stale session rejection, got %d", resp.StatusCode)
	}
}

func TestPostGetSessionRefreshesWhenDeferEnabled(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Session.DeferSessionRefresh = true
	})
	cookies := signUp(t, a, "postref@example.com")
	ctx := context.Background()
	st := a.Store().(*memory.Store)
	_, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	near := time.Now().Add(time.Hour)
	_, _ = st.UpdateSession(ctx, sess.Session.Token, store.SessionUpdate{ExpiresAt: &near})

	resp, data := doRequest(a, http.MethodPost, "/get-session", nil, cookies)
	var result types.SessionResponse
	_ = json.Unmarshal(data, &result)
	if resp.StatusCode != http.StatusOK || result.NeedsRefresh {
		t.Fatalf("POST should refresh session: %s", data)
	}
}

func TestSensitiveSessionIgnoresStaleCache(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Session.CookieCache.Enabled = true
	})
	cookies := signUp(t, a, "stalecache@example.com")
	ctx := context.Background()
	st := a.Store().(*memory.Store)
	_, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	_ = st.DeleteSession(ctx, sess.Session.Token)

	resp, _ := doRequest(a, http.MethodPost, "/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "newpass123",
	}, cookies)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stale cache should not authorize sensitive op, got %d", resp.StatusCode)
	}
}

func TestFreshAgeDisabledAllowsDelete(t *testing.T) {
	disabled := time.Duration(0)
	a := newTestAuth(func(c *auth.Config) {
		c.Session.FreshAge = &disabled
	})
	cookies := signUp(t, a, "freshoff@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/delete-user", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete with freshAge disabled failed: %d", resp.StatusCode)
	}
}

func TestUpdateSessionUserAgent(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "ua@example.com")
	resp, data := doRequest(a, http.MethodPost, "/update-session", map[string]any{
		"userAgent": "BetterAuthTest/1.0",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update failed: %s", data)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["user"]; ok {
		t.Fatalf("unexpected user field: %s", data)
	}
	var result types.UpdateSessionResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Session.UserAgent != "BetterAuthTest/1.0" {
		t.Fatalf("ua=%q", result.Session.UserAgent)
	}
}
