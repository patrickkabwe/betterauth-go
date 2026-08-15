package plugins_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/plugins"
)

func newGenericOAuthCallbackServer(t *testing.T, accountID string, name string, email string) (*httptest.Server, *bool) {
	t.Helper()
	tokenRequestSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenRequestSeen = true
			if r.Method != http.MethodPost {
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			if err := r.ParseForm(); err != nil {
				http.Error(w, "form", http.StatusBadRequest)
				return
			}
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "code" {
				http.Error(w, "form", http.StatusBadRequest)
				return
			}
			if r.Form.Get("redirect_uri") != "http://localhost:8080/api/auth/oauth2/callback/oidc" {
				http.Error(w, "redirect_uri", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access-token","refresh_token":"refresh-token","scope":"openid email","expires_in":3600}`))
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer access-token" {
				http.Error(w, "authorization", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]any{
				"sub":            accountID,
				"name":           name,
				"email":          email,
				"email_verified": true,
				"picture":        "https://idp.example.com/avatar.png",
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	return server, &tokenRequestSeen
}

func TestGenericOAuthSignInAuthorizationURLConfig(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize?prompt=old&tenant=workspace",
				TokenURL:         "https://idp.example.com/oauth/token",
				UserInfoURL:      "https://idp.example.com/oauth/userinfo",
				RedirectURI:      "https://app.example.com/oauth/callback",
				Scopes:           []string{"openid", "email"},
				ResponseType:     "id_token",
				ResponseMode:     "form_post",
				PKCE:             true,
				Prompt:           "select_account",
				AccessType:       "offline",
				AuthorizationURLParams: map[string]string{
					"audience":      "api",
					"response_type": "code",
				},
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"/dashboard","disableRedirect":true,"scopes":["calendar"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL      string `json:"url"`
		Redirect bool   `json:"redirect"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Redirect {
		t.Fatalf("redirect=%v", body.Redirect)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "https" || parsed.Host != "idp.example.com" || parsed.Path != "/oauth/authorize" {
		t.Fatalf("url=%s", body.URL)
	}
	query := parsed.Query()
	if query.Get("client_id") != "client" || query.Get("response_type") != "code" || query.Get("scope") != "calendar openid email" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("prompt") != "select_account" || query.Get("tenant") != "workspace" || query.Get("audience") != "api" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("response_mode") != "form_post" || query.Get("access_type") != "offline" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("redirect_uri") != "https://app.example.com/oauth/callback" {
		t.Fatalf("redirect_uri=%q", query.Get("redirect_uri"))
	}
	if query.Get("state") == "" {
		t.Fatalf("state missing: %s", query.Encode())
	}
	if values := query["prompt"]; len(values) != 1 {
		t.Fatalf("prompt values=%v", values)
	}
}

func TestGenericOAuthLinkReturnsAuthorizationURL(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize?tenant=workspace",
				TokenURL:         "https://idp.example.com/oauth/token",
				Scopes:           []string{"openid", "email"},
				PKCE:             true,
				Prompt:           "consent",
				AccessType:       "offline",
				AuthorizationURLParams: map[string]string{
					"audience": "api",
				},
			},
		},
	}))

	signUp := post(t, a, "/sign-up/email", `{"name":"Link User","email":"generic-oauth-link@example.com","password":"password123"}`)
	if signUp.Code != http.StatusOK {
		t.Fatalf("status %d body %s", signUp.Code, signUp.Body.String())
	}
	w := postWithCookies(t, a, "/oauth2/link", `{"providerId":"oidc","callbackURL":"https://app.example.com/settings","scopes":["repo"]}`, signUp.Result().Cookies())
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL      string `json:"url"`
		Redirect bool   `json:"redirect"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Redirect {
		t.Fatalf("redirect=%v", body.Redirect)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "https" || parsed.Host != "idp.example.com" || parsed.Path != "/oauth/authorize" {
		t.Fatalf("url=%s", body.URL)
	}
	query := parsed.Query()
	if query.Get("client_id") != "client" || query.Get("response_type") != "code" || query.Get("scope") != "repo" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("prompt") != "consent" || query.Get("access_type") != "offline" || query.Get("audience") != "api" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("tenant") != "workspace" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("redirect_uri") != "http://localhost:8080/api/auth/oauth2/callback/oidc" {
		t.Fatalf("redirect_uri=%q", query.Get("redirect_uri"))
	}
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("state") == "" {
		t.Fatalf("state missing: %s", query.Encode())
	}
}

func TestGenericOAuthCallbackRedirectsToStoredCallbackURL(t *testing.T) {
	oauthServer, tokenRequestSeen := newGenericOAuthCallbackServer(t, "oidc-account", "OIDC User", "OIDC@EXAMPLE.COM")
	defer oauthServer.Close()

	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         oauthServer.URL + "/token",
				UserInfoURL:      oauthServer.URL + "/userinfo",
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", body.URL)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	if location := callback.Header().Get("Location"); location != "https://app.example.com/dashboard" {
		t.Fatalf("Location=%q", location)
	}
	if !*tokenRequestSeen {
		t.Fatal("expected token request")
	}
	user, err := a.Store().FindUserByEmail(context.Background(), "oidc@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if user.Name != "OIDC User" || !user.EmailVerified {
		t.Fatalf("user=%+v", user)
	}
	account, err := a.Store().FindAccountByProviderAndAccountID(context.Background(), "oidc", "oidc-account")
	if err != nil {
		t.Fatal(err)
	}
	if account.UserID != user.ID || account.AccessToken != "access-token" || account.RefreshToken != "refresh-token" || account.Scope != "openid,email" {
		t.Fatalf("account=%+v", account)
	}
	if len(callback.Result().Cookies()) == 0 {
		t.Fatal("expected session cookie")
	}
}

func TestGenericOAuthCallbackLinksAccount(t *testing.T) {
	oauthServer, tokenRequestSeen := newGenericOAuthCallbackServer(t, "link-account", "Link User", "generic-oauth-link-callback@example.com")
	defer oauthServer.Close()

	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         oauthServer.URL + "/token",
				UserInfoURL:      oauthServer.URL + "/userinfo",
			},
		},
	}))

	signUp := post(t, a, "/sign-up/email", `{"name":"Link User","email":"generic-oauth-link-callback@example.com","password":"password123"}`)
	if signUp.Code != http.StatusOK {
		t.Fatalf("status %d body %s", signUp.Code, signUp.Body.String())
	}
	user, err := a.Store().FindUserByEmail(context.Background(), "generic-oauth-link-callback@example.com")
	if err != nil {
		t.Fatal(err)
	}
	link := postWithCookies(t, a, "/oauth2/link", `{"providerId":"oidc","callbackURL":"https://app.example.com/settings"}`, signUp.Result().Cookies())
	if link.Code != http.StatusOK {
		t.Fatalf("status %d body %s", link.Code, link.Body.String())
	}
	var linkBody struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(link.Body.Bytes(), &linkBody); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(linkBody.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", linkBody.URL)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	if location := callback.Header().Get("Location"); location != "https://app.example.com/settings" {
		t.Fatalf("Location=%q", location)
	}
	if !*tokenRequestSeen {
		t.Fatal("expected token request")
	}
	account, err := a.Store().FindAccountByProviderAndAccountID(context.Background(), "oidc", "link-account")
	if err != nil {
		t.Fatal(err)
	}
	if account.UserID != user.ID || account.AccessToken != "access-token" {
		t.Fatalf("account=%+v user=%+v", account, user)
	}
}

func TestGenericOAuthCallbackRedirectsProviderErrors(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         "https://idp.example.com/oauth/token",
			},
		},
	}))

	callback := get(t, a, "/oauth2/callback/oidc?error=access_denied&error_description=Denied")
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	location := callback.Header().Get("Location")
	if location != "http://localhost:8080/api/auth/error?error=access_denied&error_description=Denied" {
		t.Fatalf("Location=%q", location)
	}
}

func TestGenericOAuthCallbackRedirectsMissingCode(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         "https://idp.example.com/oauth/token",
			},
		},
	}))

	callback := get(t, a, "/oauth2/callback/oidc?state=state")
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	location := callback.Header().Get("Location")
	if location != "http://localhost:8080/api/auth/error?error=oAuth_code_missing" {
		t.Fatalf("Location=%q", location)
	}
}

func TestGenericOAuthSignInUsesDiscoveryURL(t *testing.T) {
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Discovery") != "secret" {
			t.Fatalf("X-Discovery=%q", r.Header.Get("X-Discovery"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_endpoint":"https://discovery.example.com/oauth/authorize?tenant=workspace","token_endpoint":"https://discovery.example.com/oauth/token"}`))
	}))
	defer discoveryServer.Close()
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID: "oidc", ClientID: "client", ClientSecret: "secret",
				DiscoveryURL: discoveryServer.URL,
				DiscoveryHeaders: map[string]string{
					"X-Discovery": "secret",
				},
				Scopes: []string{"openid"},
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","disableRedirect":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "https" || parsed.Host != "discovery.example.com" || parsed.Path != "/oauth/authorize" {
		t.Fatalf("url=%s", body.URL)
	}
	query := parsed.Query()
	if query.Get("tenant") != "workspace" || query.Get("client_id") != "client" || query.Get("scope") != "openid" {
		t.Fatalf("query=%s", query.Encode())
	}
}

func TestGenericOAuthSignInRejectsIncompleteConfig(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID: "oidc", ClientID: "client", ClientSecret: "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestGenericOAuthCallbackRejectsProviderMismatch(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         "https://idp.example.com/oauth/token",
				UserInfoURL:      "https://idp.example.com/oauth/userinfo",
			},
			{
				ProviderID:       "other",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         "https://idp.example.com/oauth/token",
				UserInfoURL:      "https://idp.example.com/oauth/userinfo",
			},
		},
	}))
	if err := a.CreateVerification(context.Background(), constants.VerificationOAuth2State+"state", "oidc|https://app.example.com/dashboard", time.Minute); err != nil {
		t.Fatal(err)
	}

	callback := get(t, a, "/oauth2/callback/other?code=code&state=state")
	if callback.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
}

func TestGenericOAuthCallbackRejectsIssuerMismatch(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID: "oidc", ClientID: "client", ClientSecret: "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         "https://idp.example.com/oauth/token",
				UserInfoURL:      "https://idp.example.com/oauth/userinfo",
				Issuer:           "https://issuer.example.com",
			},
		},
	}))
	if err := a.CreateVerification(context.Background(), constants.VerificationOAuth2State+"state", "oidc|https://app.example.com/dashboard", time.Minute); err != nil {
		t.Fatal(err)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state=state&iss=https%3A%2F%2Fother.example.com")
	if callback.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
}

func TestGenericOAuthCallbackRequiresIssuerWhenConfigured(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID: "oidc", ClientID: "client", ClientSecret: "secret",
				AuthorizationURL:        "https://idp.example.com/oauth/authorize",
				TokenURL:                "https://idp.example.com/oauth/token",
				UserInfoURL:             "https://idp.example.com/oauth/userinfo",
				Issuer:                  "https://issuer.example.com",
				RequireIssuerValidation: true,
			},
		},
	}))
	if err := a.CreateVerification(context.Background(), constants.VerificationOAuth2State+"state", "oidc|https://app.example.com/dashboard", time.Minute); err != nil {
		t.Fatal(err)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state=state")
	if callback.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
}

func TestGenericOAuthCallbackUsesDiscoveryIssuer(t *testing.T) {
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_endpoint":"https://idp.example.com/oauth/authorize","token_endpoint":"https://idp.example.com/oauth/token","issuer":"https://issuer.example.com"}`))
	}))
	defer discoveryServer.Close()
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID: "oidc", ClientID: "client", ClientSecret: "secret",
				DiscoveryURL: discoveryServer.URL,
			},
		},
	}))
	if err := a.CreateVerification(context.Background(), constants.VerificationOAuth2State+"state", "oidc|https://app.example.com/dashboard", time.Minute); err != nil {
		t.Fatal(err)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state=state&iss=https%3A%2F%2Fother.example.com")
	if callback.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
}
