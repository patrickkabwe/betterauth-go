package google_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
