package github_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/provider/github"
)

func TestGitHubAuthURL(t *testing.T) {
	p := github.New(github.Config{ClientID: "id", ClientSecret: "secret"})
	url, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "state-token", RedirectURI: "http://localhost:8080/api/auth/callback/github",
	})
	if err != nil || url == "" {
		t.Fatalf("url=%s err=%v", url, err)
	}
}

func TestGitHubAuthURLCanDisableDefaultScopes(t *testing.T) {
	p := github.New(github.Config{ClientID: "id", ClientSecret: "secret", DisableDefaultScope: true, Scopes: []string{"repo"}})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "state-token", RedirectURI: "http://localhost:8080/api/auth/callback/github",
	})
	if err != nil {
		t.Fatal(err)
	}
	query := githubAuthURLQuery(t, authURL)
	if query.Get("scope") != "repo" {
		t.Fatalf("scope=%q", query.Get("scope"))
	}
}

func TestGitHubAuthURLOmitsScopeWhenDefaultScopesDisabled(t *testing.T) {
	p := github.New(github.Config{ClientID: "id", ClientSecret: "secret", DisableDefaultScope: true})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "state-token", RedirectURI: "http://localhost:8080/api/auth/callback/github",
	})
	if err != nil {
		t.Fatal(err)
	}
	query := githubAuthURLQuery(t, authURL)
	if _, ok := query["scope"]; ok {
		t.Fatalf("query=%s", query.Encode())
	}
}

func TestGitHubSignUpPolicy(t *testing.T) {
	p := github.New(github.Config{ClientID: "id", ClientSecret: "secret", DisableImplicitSignUp: true, DisableSignUp: true, OverrideUserInfoOnSignIn: true})
	if !p.DisableImplicitSignUp() || !p.DisableSignUp() {
		t.Fatalf("policy implicit=%v signup=%v", p.DisableImplicitSignUp(), p.DisableSignUp())
	}
	if !p.OverrideUserInfoOnSignIn() {
		t.Fatal("expected user info override")
	}
}

func githubAuthURLQuery(t *testing.T, authURL string) url.Values {
	t.Helper()
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Query()
}
