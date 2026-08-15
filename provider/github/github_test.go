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

func TestGitHubAuthURLUsesEndpointAndRedirectOverrides(t *testing.T) {
	p := github.New(github.Config{
		ClientID:              "id",
		ClientSecret:          "secret",
		AuthorizationEndpoint: "https://github.example.com/login/oauth/authorize",
		RedirectURI:           "https://app.example.com/github/callback",
	})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "state-token", RedirectURI: "http://localhost:8080/api/auth/callback/github",
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "https" || parsed.Host != "github.example.com" || parsed.Path != "/login/oauth/authorize" {
		t.Fatalf("url=%s", authURL)
	}
	if parsed.Query().Get("redirect_uri") != "https://app.example.com/github/callback" {
		t.Fatalf("redirect_uri=%q", parsed.Query().Get("redirect_uri"))
	}
}

func TestGitHubAuthURLIncludesPromptAndLoginHint(t *testing.T) {
	p := github.New(github.Config{ClientID: "id", ClientSecret: "secret", Prompt: "select_account"})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "state-token", RedirectURI: "http://localhost:8080/api/auth/callback/github", LoginHint: "octocat",
	})
	if err != nil {
		t.Fatal(err)
	}
	query := githubAuthURLQuery(t, authURL)
	if query.Get("response_type") != "code" || query.Get("prompt") != "select_account" || query.Get("login_hint") != "octocat" {
		t.Fatalf("query=%s", query.Encode())
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

func TestGitHubGetUserInfoUsesOverride(t *testing.T) {
	p := github.New(github.Config{
		ClientID: "id", ClientSecret: "secret",
		GetUserInfo: func(_ context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error) {
			return &provider.UserInfo{
				User: provider.OAuthUser{ID: "custom-github", Email: tokens.AccessToken + "@example.com", EmailVerified: true},
				Data: map[string]any{"source": "override"},
			}, nil
		},
	})
	info, err := p.GetUserInfo(context.Background(), provider.OAuthTokens{AccessToken: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	if info.User.ID != "custom-github" || info.User.Email != "custom@example.com" || info.Data["source"] != "override" {
		t.Fatalf("info=%+v", info)
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
