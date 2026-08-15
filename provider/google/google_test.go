package google_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/provider/google"
)

func TestGoogleAuthURLRequiresPKCE(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret"})
	_, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb",
	})
	if err == nil {
		t.Fatal("expected pkce error")
	}
}

func TestGoogleAuthURLIncludesHostedDomain(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", HD: "example.com"})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb", CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(authURL, "hd=example.com") {
		t.Fatalf("url=%s", authURL)
	}
}

func TestGoogleAuthURLUsesEndpointAndRedirectOverrides(t *testing.T) {
	p := google.New(google.Config{
		ClientID:              "id",
		ClientSecret:          "secret",
		AuthorizationEndpoint: "https://accounts.example.com/oauth/auth",
		RedirectURI:           "https://app.example.com/google/callback",
	})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb", CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "https" || parsed.Host != "accounts.example.com" || parsed.Path != "/oauth/auth" {
		t.Fatalf("url=%s", authURL)
	}
	if parsed.Query().Get("redirect_uri") != "https://app.example.com/google/callback" {
		t.Fatalf("redirect_uri=%q", parsed.Query().Get("redirect_uri"))
	}
}

func TestGoogleAuthURLIncludesDisplay(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", Display: "popup"})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb", CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatal(err)
	}
	query := googleAuthURLQuery(t, authURL)
	if query.Get("display") != "popup" {
		t.Fatalf("display=%q", query.Get("display"))
	}
}

func TestGoogleAuthURLDisplayOptionOverridesConfig(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", Display: "popup"})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb", CodeVerifier: "verifier", Display: "touch",
	})
	if err != nil {
		t.Fatal(err)
	}
	query := googleAuthURLQuery(t, authURL)
	if query.Get("display") != "touch" {
		t.Fatalf("display=%q", query.Get("display"))
	}
}

func TestGoogleAuthURLCanDisableDefaultScopes(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", DisableDefaultScope: true, Scopes: []string{"calendar.readonly"}})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb", CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatal(err)
	}
	query := googleAuthURLQuery(t, authURL)
	if query.Get("scope") != "calendar.readonly" {
		t.Fatalf("scope=%q", query.Get("scope"))
	}
}

func TestGoogleAuthURLOmitsScopeWhenDefaultScopesDisabled(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", DisableDefaultScope: true})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb", CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatal(err)
	}
	query := googleAuthURLQuery(t, authURL)
	if _, ok := query["scope"]; ok {
		t.Fatalf("query=%s", query.Encode())
	}
}

func TestGoogleGetUserInfoFromIDToken(t *testing.T) {
	claims := map[string]any{
		"sub": "google-sub", "email": "g@example.com", "email_verified": true,
		"name": "G User", "picture": "http://img",
	}
	token := googleTestIDToken(claims)
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret"})
	info, err := p.GetUserInfo(context.Background(), provider.OAuthTokens{IDToken: token})
	if err != nil || info.User.Email != "g@example.com" || info.User.ID != "google-sub" {
		t.Fatalf("info=%+v err=%v", info, err)
	}
}

func TestGoogleGetUserInfoUsesOverride(t *testing.T) {
	p := google.New(google.Config{
		ClientID: "id", ClientSecret: "secret",
		GetUserInfo: func(_ context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error) {
			return &provider.UserInfo{
				User: provider.OAuthUser{ID: "custom-google", Email: tokens.AccessToken + "@example.com", EmailVerified: true},
				Data: map[string]any{"source": "override"},
			}, nil
		},
	})
	info, err := p.GetUserInfo(context.Background(), provider.OAuthTokens{AccessToken: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	if info.User.ID != "custom-google" || info.User.Email != "custom@example.com" || info.Data["source"] != "override" {
		t.Fatalf("info=%+v", info)
	}
}

func TestGoogleGetUserInfoRejectsHostedDomainMismatch(t *testing.T) {
	token := googleTestIDToken(map[string]any{
		"sub": "google-sub", "email": "g@example.com", "email_verified": true,
		"name": "G User", "hd": "other.com",
	})
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", HD: "example.com"})
	info, err := p.GetUserInfo(context.Background(), provider.OAuthTokens{IDToken: token})
	if err != nil {
		t.Fatal(err)
	}
	if info != nil {
		t.Fatalf("info=%+v", info)
	}
}

func TestGoogleGetUserInfoAllowsAnyHostedDomain(t *testing.T) {
	token := googleTestIDToken(map[string]any{
		"sub": "google-sub", "email": "g@example.com", "email_verified": true,
		"name": "G User", "hd": "workspace.com",
	})
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", HD: "*"})
	info, err := p.GetUserInfo(context.Background(), provider.OAuthTokens{IDToken: token})
	if err != nil || info == nil || info.User.Email != "g@example.com" {
		t.Fatalf("info=%+v err=%v", info, err)
	}
}

func TestGoogleGetUserInfoRequiresHostedDomainClaim(t *testing.T) {
	token := googleTestIDToken(map[string]any{
		"sub": "google-sub", "email": "g@example.com", "email_verified": true,
		"name": "G User",
	})
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", HD: "*"})
	info, err := p.GetUserInfo(context.Background(), provider.OAuthTokens{IDToken: token})
	if err != nil {
		t.Fatal(err)
	}
	if info != nil {
		t.Fatalf("info=%+v", info)
	}
}

func TestGoogleSignUpPolicy(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", DisableImplicitSignUp: true, DisableSignUp: true, OverrideUserInfoOnSignIn: true})
	if !p.DisableImplicitSignUp() || !p.DisableSignUp() {
		t.Fatalf("policy implicit=%v signup=%v", p.DisableImplicitSignUp(), p.DisableSignUp())
	}
	if !p.OverrideUserInfoOnSignIn() {
		t.Fatal("expected user info override")
	}
}

func googleTestIDToken(claims map[string]any) string {
	raw, _ := json.Marshal(claims)
	return "hdr." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

func googleAuthURLQuery(t *testing.T, authURL string) url.Values {
	t.Helper()
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Query()
}
