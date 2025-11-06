package google

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/jwt"
	oauth2pkg "github.com/patrickkabwe/betterauth-go/internal/oauth2"
	"github.com/patrickkabwe/betterauth-go/provider"
)

const (
	providerID    = constants.ProviderGoogle
	authEndpoint  = "https://accounts.google.com/o/oauth2/v2/auth"
	tokenEndpoint = "https://oauth2.googleapis.com/token"
)

// Config configures the Google OAuth provider.
type Config struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	AccessType   string
	Prompt       string
}

// Provider implements Google OAuth.
type Provider struct {
	cfg Config
}

// New creates a Google OAuth provider.
func New(cfg Config) *Provider {
	return &Provider{cfg: cfg}
}

func (p *Provider) ID() string { return providerID }

func (p *Provider) defaultScopes(extra []string) []string {
	base := []string{"email", "profile", "openid"}
	if len(p.cfg.Scopes) > 0 {
		base = append(base, p.cfg.Scopes...)
	}
	if len(extra) > 0 {
		base = append(base, extra...)
	}
	seen := make(map[string]bool)
	var out []string
	for _, s := range base {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func (p *Provider) CreateAuthorizationURL(_ context.Context, opts provider.AuthorizationURLOpts) (string, error) {
	if p.cfg.ClientID == "" || p.cfg.ClientSecret == "" {
		return "", fmt.Errorf("google client id and secret are required")
	}
	if opts.CodeVerifier == "" {
		return "", fmt.Errorf("code verifier is required for google")
	}
	params := url.Values{}
	params.Set("client_id", p.cfg.ClientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", opts.RedirectURI)
	params.Set("scope", strings.Join(p.defaultScopes(opts.Scopes), " "))
	params.Set("state", opts.State)
	params.Set("code_challenge", oauth2pkg.CodeChallengeS256(opts.CodeVerifier))
	params.Set("code_challenge_method", "S256")
	params.Set("include_granted_scopes", "true")
	accessType := p.cfg.AccessType
	if accessType == "" {
		accessType = "offline"
	}
	params.Set("access_type", accessType)
	if p.cfg.Prompt != "" {
		params.Set("prompt", p.cfg.Prompt)
	}
	return provider.BuildAuthURL(authEndpoint, params), nil
}

func (p *Provider) ValidateAuthorizationCode(ctx context.Context, code, codeVerifier, redirectURI string) (*provider.OAuthTokens, error) {
	data, err := provider.ExchangeAuthorizationCode(ctx, provider.CodeExchangeOpts{
		TokenURL:     tokenEndpoint,
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		Code:         code,
		RedirectURI:  redirectURI,
		CodeVerifier: codeVerifier,
	})
	if err != nil {
		return nil, err
	}
	return provider.TokensFromMap(data), nil
}

func (p *Provider) GetUserInfo(_ context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error) {
	idToken := tokens.IDToken
	if idToken == "" {
		return nil, fmt.Errorf("google id_token missing")
	}
	claims, err := jwt.DecodePayload(idToken)
	if err != nil {
		return nil, err
	}
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	picture, _ := claims["picture"].(string)
	sub, _ := claims["sub"].(string)
	verified, _ := claims["email_verified"].(bool)
	var image *string
	if picture != "" {
		image = &picture
	}
	return &provider.UserInfo{
		User: provider.OAuthUser{
			ID: sub, Name: name, Email: email, Image: image, EmailVerified: verified,
		},
		Data: claims,
	}, nil
}

func (p *Provider) RefreshAccessToken(ctx context.Context, refreshToken string) (*provider.OAuthTokens, error) {
	return provider.RefreshAccessToken(ctx, tokenEndpoint, p.cfg.ClientID, p.cfg.ClientSecret, refreshToken)
}
