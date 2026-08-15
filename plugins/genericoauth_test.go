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

func TestGenericOAuthCallbackRedirectsToStoredCallbackURL(t *testing.T) {
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
