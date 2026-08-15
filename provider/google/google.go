package google

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/provider/oauth2provider"
)

// Config configures the Google OAuth provider.
type Config struct {
	ClientID                 string
	ClientSecret             string
	Scopes                   []string
	AuthorizationEndpoint    string
	RedirectURI              string
	AccessType               string
	Display                  string
	Prompt                   string
	HD                       string
	DisableDefaultScope      bool
	DisableImplicitSignUp    bool
	DisableSignUp            bool
	OverrideUserInfoOnSignIn bool
	DisableIDTokenSignIn     bool
	GetUserInfo              func(context.Context, provider.OAuthTokens) (*provider.UserInfo, error)
	MapProfileToUser         func(context.Context, map[string]any) (provider.OAuthUserMapping, error)
}

// Provider implements Google OAuth.
type Provider struct {
	*oauth2provider.IDTokenProvider
}

// New creates a Google OAuth provider.
func New(cfg Config) *Provider {
	return &Provider{IDTokenProvider: oauth2provider.GoogleWithIDToken(oauth2provider.Options{
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Scopes: cfg.Scopes,
		AuthorizationEndpoint: cfg.AuthorizationEndpoint, RedirectURI: cfg.RedirectURI,
		AccessType: cfg.AccessType, Display: cfg.Display, Prompt: cfg.Prompt, HD: cfg.HD,
		DisableDefaultScope: cfg.DisableDefaultScope, DisableImplicitSignUp: cfg.DisableImplicitSignUp,
		DisableSignUp: cfg.DisableSignUp, OverrideUserInfoOnSignIn: cfg.OverrideUserInfoOnSignIn,
		DisableIDTokenSignIn: cfg.DisableIDTokenSignIn,
		GetUserInfo:          cfg.GetUserInfo,
		MapProfileToUser:     cfg.MapProfileToUser,
	})}
}
