package github_test

import (
	"context"
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
