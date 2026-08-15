package github

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/provider/oauth2provider"
)

// Config configures the GitHub OAuth provider.
type Config struct {
	ClientID                 string
	ClientSecret             string
	Scopes                   []string
	AuthorizationEndpoint    string
	RedirectURI              string
	Prompt                   string
	DisableDefaultScope      bool
	DisableImplicitSignUp    bool
	DisableSignUp            bool
	OverrideUserInfoOnSignIn bool
	GetUserInfo              func(context.Context, provider.OAuthTokens) (*provider.UserInfo, error)
	MapProfileToUser         func(context.Context, map[string]any) (provider.OAuthUserMapping, error)
}

// Provider implements GitHub OAuth.
type Provider struct {
	*oauth2provider.Provider
}

// New creates a GitHub OAuth provider.
func New(cfg Config) *Provider {
	return &Provider{Provider: oauth2provider.GitHub(oauth2provider.Options{
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Scopes: cfg.Scopes,
		AuthorizationEndpoint: cfg.AuthorizationEndpoint, RedirectURI: cfg.RedirectURI, Prompt: cfg.Prompt,
		DisableDefaultScope: cfg.DisableDefaultScope, DisableImplicitSignUp: cfg.DisableImplicitSignUp,
		DisableSignUp: cfg.DisableSignUp, OverrideUserInfoOnSignIn: cfg.OverrideUserInfoOnSignIn,
		GetUserInfo: cfg.GetUserInfo, MapProfileToUser: cfg.MapProfileToUser,
	})}
}
