package google_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

func TestGoogleGetUserInfoFromIDToken(t *testing.T) {
	claims := map[string]any{
		"sub": "google-sub", "email": "g@example.com", "email_verified": true,
		"name": "G User", "picture": "http://img",
	}
	raw, _ := json.Marshal(claims)
	token := "hdr." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret"})
	info, err := p.GetUserInfo(context.Background(), provider.OAuthTokens{IDToken: token})
	if err != nil || info.User.Email != "g@example.com" || info.User.ID != "google-sub" {
		t.Fatalf("info=%+v err=%v", info, err)
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
