package plugins_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/types"
)

// newLogoutClient builds a client that (optionally) opted into RP-initiated
// logout with a registered post-logout redirect URI.
func newLogoutClient(t *testing.T, clientID, redirect string, enable bool) *types.OAuthClient {
	t.Helper()
	now := time.Now().UTC()
	c := &types.OAuthClient{
		ID: clientID, ClientID: clientID, Name: "Logout",
		RedirectURIs:           []string{"https://app.example/cb"},
		PostLogoutRedirectURIs: []string{redirect},
		CreatedAt:              now, UpdatedAt: now,
	}
	if enable {
		en := true
		c.EnableEndSession = &en
	}
	return c
}

func TestOIDCEndSessionNoRedirect(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	w := get(t, a, "/oauth2/endsession")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "success") {
		t.Fatalf("end-session without redirect should 200 success, got %d %s", w.Code, w.Body.String())
	}
}

func TestOIDCEndSessionValidRedirect(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	redirect := "https://app.example/after-logout"
	if err := extStore(t, a).CreateOAuthClient(context.Background(), newLogoutClient(t, "logout-ok", redirect, true)); err != nil {
		t.Fatal(err)
	}
	path := "/oauth2/endsession?client_id=logout-ok&state=abc&post_logout_redirect_uri=" + url.QueryEscape(redirect)
	w := get(t, a, path)
	if w.Code != http.StatusFound {
		t.Fatalf("valid post-logout redirect should 302, got %d %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, redirect) || !strings.Contains(loc, "state=abc") {
		t.Fatalf("redirect Location wrong: %q", loc)
	}
}

func TestOIDCEndSessionUnregisteredRedirect(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	if err := extStore(t, a).CreateOAuthClient(context.Background(), newLogoutClient(t, "logout-unreg", "https://app.example/registered", true)); err != nil {
		t.Fatal(err)
	}
	path := "/oauth2/endsession?client_id=logout-unreg&post_logout_redirect_uri=" + url.QueryEscape("https://evil.example/steal")
	w := get(t, a, path)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unregistered post-logout redirect should 400, got %d %s", w.Code, w.Body.String())
	}
}

func TestOIDCEndSessionDisabledEndSession(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	redirect := "https://app.example/after-logout"
	// Client has the URI registered but did not enable end-session.
	if err := extStore(t, a).CreateOAuthClient(context.Background(), newLogoutClient(t, "logout-off", redirect, false)); err != nil {
		t.Fatal(err)
	}
	path := "/oauth2/endsession?client_id=logout-off&post_logout_redirect_uri=" + url.QueryEscape(redirect)
	w := get(t, a, path)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("redirect without enable_end_session should 400, got %d %s", w.Code, w.Body.String())
	}
}
