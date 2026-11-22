package plugins_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/store"
)

func timePast() time.Time { return time.Now().Add(-time.Hour) }

// registerOAuthClient registers a client and returns its client_id.
func registerOAuthClient(t *testing.T, a *auth.Auth) string {
	t.Helper()
	w := post(t, a, "/oauth2/register", `{"client_name":"Test","redirect_uris":["https://app.example/cb"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", w.Code, w.Body.String())
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil || reg.ClientID == "" {
		t.Fatalf("register response: %s", w.Body.String())
	}
	return reg.ClientID
}

// authorizeCode drives /oauth2/authorize and returns the issued code from the
// redirect Location.
func authorizeCode(t *testing.T, a *auth.Auth, clientID, scope string, cookies []*http.Cookie) string {
	t.Helper()
	path := "/oauth2/authorize?client_id=" + clientID + "&redirect_uri=" + url.QueryEscape("https://app.example/cb") + "&state=xyz&scope=" + url.QueryEscape(scope)
	w := getWithCookies(t, a, path, cookies)
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Fatalf("authorize status=%d body=%s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("bad redirect %q: %v", loc, err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect %q", loc)
	}
	return code
}

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}

func exchangeCode(t *testing.T, a *auth.Auth, code string) tokenResp {
	t.Helper()
	w := post(t, a, "/oauth2/token", `{"grant_type":"authorization_code","code":"`+code+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", w.Code, w.Body.String())
	}
	var tr tokenResp
	if err := json.Unmarshal(w.Body.Bytes(), &tr); err != nil {
		t.Fatalf("token response: %s", w.Body.String())
	}
	return tr
}

func userinfo(t *testing.T, a *auth.Auth, accessToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	return w
}

func extStore(t *testing.T, a *auth.Auth) store.ExtStore {
	t.Helper()
	ext, ok := auth.ExtStore(a.Store())
	if !ok {
		t.Fatal("store is not an ExtStore")
	}
	return ext
}

func TestOIDCAuthorizationCodeFlow(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "oidc-flow@example.com")
	user := currentPluginUser(t, a, cookies)
	clientID := registerOAuthClient(t, a)

	code := authorizeCode(t, a, clientID, "openid email", cookies)
	tr := exchangeCode(t, a, code)
	if tr.AccessToken == "" || tr.TokenType != "Bearer" || tr.ExpiresIn != 3600 {
		t.Fatalf("unexpected token response: %+v", tr)
	}
	if tr.RefreshToken != "" {
		t.Fatalf("no refresh token expected without offline_access, got %q", tr.RefreshToken)
	}

	// The access token must live in oauthAccessToken, linked to the session.
	at, err := extStore(t, a).FindOAuthAccessToken(context.Background(), tr.AccessToken)
	if err != nil {
		t.Fatalf("access token not stored in oauthAccessToken: %v", err)
	}
	if at.UserID != user.ID || at.SessionID == "" || len(at.Scopes) != 2 {
		t.Fatalf("access token not bound correctly: %+v", at)
	}

	w := userinfo(t, a, tr.AccessToken)
	if w.Code != http.StatusOK || !jsonContains(w.Body.Bytes(), "oidc-flow@example.com") {
		t.Fatalf("userinfo status=%d body=%s", w.Code, w.Body.String())
	}

	// A bogus token is rejected.
	if w := userinfo(t, a, "not-a-real-token"); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad token, got %d", w.Code)
	}
}

func TestOIDCRefreshTokenRotation(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "oidc-refresh@example.com")
	clientID := registerOAuthClient(t, a)

	code := authorizeCode(t, a, clientID, "openid offline_access", cookies)
	first := exchangeCode(t, a, code)
	if first.RefreshToken == "" {
		t.Fatal("expected a refresh token with offline_access scope")
	}

	// Rotate: a fresh access + refresh token, different from the first.
	w := post(t, a, "/oauth2/token", `{"grant_type":"refresh_token","client_id":"`+clientID+`","refresh_token":"`+first.RefreshToken+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", w.Code, w.Body.String())
	}
	var rotated tokenResp
	_ = json.Unmarshal(w.Body.Bytes(), &rotated)
	if rotated.RefreshToken == "" || rotated.RefreshToken == first.RefreshToken {
		t.Fatalf("rotation should mint a new refresh token: %+v", rotated)
	}

	// Replay within the window returns the same rotation response.
	w2 := post(t, a, "/oauth2/token", `{"grant_type":"refresh_token","client_id":"`+clientID+`","refresh_token":"`+first.RefreshToken+`"}`)
	if w2.Code != http.StatusOK || strings.TrimSpace(w2.Body.String()) != strings.TrimSpace(w.Body.String()) {
		t.Fatalf("replay should return the stored rotation response; got %d %s", w2.Code, w2.Body.String())
	}

	// Reuse outside the replay window is detected: expire the replay window on
	// the rotated row, then present it again -> invalid_grant + family torn down.
	ext := extStore(t, a)
	if err := ext.RotateOAuthRefreshToken(context.Background(), oauthRefreshID(t, ext, first.RefreshToken), w.Body.String(), timePast()); err != nil {
		t.Fatalf("force-expire replay window: %v", err)
	}
	w3 := post(t, a, "/oauth2/token", `{"grant_type":"refresh_token","client_id":"`+clientID+`","refresh_token":"`+first.RefreshToken+`"}`)
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("reuse outside window should fail, got %d %s", w3.Code, w3.Body.String())
	}
	if _, err := ext.FindOAuthRefreshToken(context.Background(), rotated.RefreshToken); err == nil {
		t.Fatal("family should be invalidated: rotated refresh token must be gone")
	}
}

func oauthRefreshID(t *testing.T, ext store.ExtStore, token string) string {
	t.Helper()
	rt, err := ext.FindOAuthRefreshToken(context.Background(), token)
	if err != nil {
		t.Fatalf("find refresh token: %v", err)
	}
	return rt.ID
}
