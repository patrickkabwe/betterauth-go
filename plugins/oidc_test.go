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
	"github.com/patrickkabwe/betterauth-go/types"
)

func timePast() time.Time { return time.Now().Add(-time.Hour) }

// registerOAuthClient registers a client and returns its client_id.
func registerOAuthClient(t *testing.T, a *auth.Auth) string {
	t.Helper()
	w := post(t, a, "/oauth2/register", `{"client_name":"Test","redirect_uris":["https://app.example/cb"]}`)
	if w.Code != http.StatusCreated {
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

func codeFromURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("bad redirect %q: %v", raw, err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", raw)
	}
	return code
}

// authorizeCode drives /oauth2/authorize, granting consent when the provider
// asks for it, and returns the issued authorization code.
func authorizeCode(t *testing.T, a *auth.Auth, clientID, scope string, cookies []*http.Cookie) string {
	t.Helper()
	path := "/oauth2/authorize?client_id=" + clientID + "&redirect_uri=" + url.QueryEscape("https://app.example/cb") + "&state=xyz&scope=" + url.QueryEscape(scope)
	w := getWithCookies(t, a, path, cookies)
	// Consent already satisfied (skipConsent / prior consent): code in Location.
	if w.Code == http.StatusFound || w.Code == http.StatusSeeOther {
		return codeFromURL(t, w.Header().Get("Location"))
	}
	if w.Code != http.StatusOK {
		t.Fatalf("authorize status=%d body=%s", w.Code, w.Body.String())
	}
	// Consent required: grant it, then read the code from the returned redirect.
	var cr struct {
		ConsentRequired bool `json:"consentRequired"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &cr); err != nil || !cr.ConsentRequired {
		t.Fatalf("expected consentRequired, got %s", w.Body.String())
	}
	body := `{"client_id":"` + clientID + `","scope":"` + scope + `","accept":true,"redirect_uri":"https://app.example/cb","state":"xyz"}`
	cw := postWithCookies(t, a, "/oauth2/consent", body, cookies)
	if cw.Code != http.StatusOK {
		t.Fatalf("consent status=%d body=%s", cw.Code, cw.Body.String())
	}
	var resp struct {
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal(cw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("consent response: %s", cw.Body.String())
	}
	return codeFromURL(t, resp.Redirect)
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
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "oidc-flow@example.com") {
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

func consent(t *testing.T, a *auth.Auth, clientID, scope string, accept bool, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"client_id":"` + clientID + `","scope":"` + scope + `","accept":` + boolJSON(accept) + `,"redirect_uri":"https://app.example/cb","state":"s"}`
	return postWithCookies(t, a, "/oauth2/consent", body, cookies)
}

func boolJSON(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestOIDCConsentPersistenceAndGate(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "consent-gate@example.com")
	clientID := registerOAuthClient(t, a)

	// First authorize needs consent.
	path := "/oauth2/authorize?client_id=" + clientID + "&redirect_uri=" + url.QueryEscape("https://app.example/cb") + "&state=xyz&scope=" + url.QueryEscape("openid email")
	if w := getWithCookies(t, a, path, cookies); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "consentRequired") {
		t.Fatalf("expected consentRequired, got %d %s", w.Code, w.Body.String())
	}

	// Grant consent -> redirect carries a code.
	cw := consent(t, a, clientID, "openid email", true, cookies)
	if cw.Code != http.StatusOK || !strings.Contains(cw.Body.String(), "code=") {
		t.Fatalf("consent accept: %d %s", cw.Code, cw.Body.String())
	}

	// Second authorize for the same scopes is now satisfied -> direct redirect.
	w2 := getWithCookies(t, a, path, cookies)
	if w2.Code != http.StatusFound && w2.Code != http.StatusSeeOther {
		t.Fatalf("expected direct redirect after consent, got %d %s", w2.Code, w2.Body.String())
	}
	if codeFromURL(t, w2.Header().Get("Location")) == "" {
		t.Fatal("expected a code in the post-consent redirect")
	}

	// A broader scope needs consent again.
	path3 := "/oauth2/authorize?client_id=" + clientID + "&redirect_uri=" + url.QueryEscape("https://app.example/cb") + "&state=xyz&scope=" + url.QueryEscape("openid email profile")
	if w3 := getWithCookies(t, a, path3, cookies); w3.Code != http.StatusOK {
		t.Fatalf("broader scope should require consent, got %d", w3.Code)
	}
}

func TestOIDCConsentDenyAndManagement(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "consent-mgmt@example.com")
	clientID := registerOAuthClient(t, a)

	// Deny -> access_denied redirect, no consent stored.
	dw := consent(t, a, clientID, "openid", false, cookies)
	if dw.Code != http.StatusOK || !strings.Contains(dw.Body.String(), "access_denied") {
		t.Fatalf("deny should return access_denied: %d %s", dw.Code, dw.Body.String())
	}

	// Accept -> consent stored and listed.
	_ = consent(t, a, clientID, "openid email", true, cookies)
	lw := getWithCookies(t, a, "/oauth2/get-consents", cookies)
	if lw.Code != http.StatusOK {
		t.Fatalf("get-consents: %d %s", lw.Code, lw.Body.String())
	}
	var consents []types.OAuthConsent
	if err := json.Unmarshal(lw.Body.Bytes(), &consents); err != nil || len(consents) != 1 {
		t.Fatalf("expected 1 consent, got %s", lw.Body.String())
	}
	id := consents[0].ID

	// Update scopes.
	uw := postWithCookies(t, a, "/oauth2/update-consent", `{"id":"`+id+`","update":{"scopes":["openid"]}}`, cookies)
	if uw.Code != http.StatusOK || !strings.Contains(uw.Body.String(), `"openid"`) {
		t.Fatalf("update-consent: %d %s", uw.Code, uw.Body.String())
	}

	// Another user cannot see or delete it.
	other := signUpPluginUser(t, a, "consent-other@example.com")
	if gw := getWithCookies(t, a, "/oauth2/get-consent?id="+id, other); gw.Code != http.StatusNotFound {
		t.Fatalf("cross-user get should 404, got %d", gw.Code)
	}

	// Owner deletes it.
	dwr := postWithCookies(t, a, "/oauth2/delete-consent", `{"id":"`+id+`"}`, cookies)
	if dwr.Code != http.StatusOK {
		t.Fatalf("delete-consent: %d %s", dwr.Code, dwr.Body.String())
	}
	if ext := extStore(t, a); func() bool { _, err := ext.FindOAuthConsentByID(context.Background(), id); return err == nil }() {
		t.Fatal("consent should be gone after delete")
	}
}
