package plugins_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestOIDCAuthorizeRejectsUnregisteredRedirect(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "sec-authz@example.com")
	clientID := registerOAuthClient(t, a) // registers redirect https://app.example/cb

	// A redirect_uri the client never registered must be refused outright — the
	// server must not 302 an authorization code to it.
	path := "/oauth2/authorize?client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape("https://evil.example/cb") +
		"&scope=" + url.QueryEscape("openid") + "&state=xyz"
	w := getWithCookies(t, a, path, cookies)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unregistered redirect_uri should 400 (not redirect), got %d, Location=%q", w.Code, w.Header().Get("Location"))
	}
}

func TestOIDCConsentRejectsUnregisteredRedirect(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "sec-consent@example.com")
	clientID := registerOAuthClient(t, a)

	body := `{"client_id":"` + clientID + `","scope":"openid","accept":true,"redirect_uri":"https://evil.example/cb","state":"xyz"}`
	w := postWithCookies(t, a, "/oauth2/consent", body, cookies)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("consent with unregistered redirect should 400, got %d %s", w.Code, w.Body.String())
	}
}

func TestOIDCConsentRedirectRoundTripsState(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "sec-state@example.com")
	clientID := registerOAuthClient(t, a)

	// A state containing URL metacharacters must survive the redirect intact
	// (the old raw string concat would corrupt it / inject params).
	state := "a b&c=1"
	body, _ := json.Marshal(map[string]any{
		"client_id": clientID, "scope": "openid", "accept": true,
		"redirect_uri": "https://app.example/cb", "state": state,
	})
	w := postWithCookies(t, a, "/oauth2/consent", string(body), cookies)
	if w.Code != http.StatusOK {
		t.Fatalf("consent status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("consent response: %s", w.Body.String())
	}
	u, err := url.Parse(resp.Redirect)
	if err != nil {
		t.Fatalf("redirect is not a valid URL: %q (%v)", resp.Redirect, err)
	}
	if got := u.Query().Get("state"); got != state {
		t.Fatalf("state not round-tripped: got %q want %q (redirect=%q)", got, state, resp.Redirect)
	}
	if u.Query().Get("code") == "" {
		t.Fatalf("redirect missing code: %q", resp.Redirect)
	}
}

func TestOIDCAuthorizeRedirectRoundTripsState(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "sec-authz-state@example.com")

	// A skip-consent client so /oauth2/authorize redirects with the code directly.
	skip := true
	now := time.Now().UTC()
	if err := extStore(t, a).CreateOAuthClient(context.Background(), &types.OAuthClient{
		ID: "sec-skip", ClientID: "sec-skip", Name: "Skip",
		RedirectURIs: []string{"https://app.example/cb"}, SkipConsent: &skip,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	state := "x y&z"
	path := "/oauth2/authorize?client_id=sec-skip&redirect_uri=" + url.QueryEscape("https://app.example/cb") +
		"&scope=" + url.QueryEscape("openid") + "&state=" + url.QueryEscape(state)
	w := getWithCookies(t, a, path, cookies)
	if w.Code != http.StatusFound {
		t.Fatalf("authorize should 302, got %d %s", w.Code, w.Body.String())
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location not a valid URL: %q", w.Header().Get("Location"))
	}
	if got := u.Query().Get("state"); got != state {
		t.Fatalf("state not round-tripped: got %q want %q", got, state)
	}
	if u.Query().Get("code") == "" {
		t.Fatalf("missing code in %q", w.Header().Get("Location"))
	}
}
