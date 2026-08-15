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
	GetUserInfo              func(context.Context, provider.OAuthTokens) (*provider.UserInfo, error)
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

func (p *Provider) DisableImplicitSignUp() bool { return p.cfg.DisableImplicitSignUp }

func (p *Provider) DisableSignUp() bool { return p.cfg.DisableSignUp }

func (p *Provider) OverrideUserInfoOnSignIn() bool { return p.cfg.OverrideUserInfoOnSignIn }

func (p *Provider) defaultScopes(extra []string) []string {
	base := []string{}
	if !p.cfg.DisableDefaultScope {
		base = append(base, "email", "profile", "openid")
	}
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
	params.Set("redirect_uri", p.redirectURI(opts.RedirectURI))
	scopes := p.defaultScopes(opts.Scopes)
	if len(scopes) > 0 {
		params.Set("scope", strings.Join(scopes, " "))
	}
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
	display := p.cfg.Display
	if opts.Display != "" {
		display = opts.Display
	}
	if display != "" {
		params.Set("display", display)
	}
	if p.cfg.HD != "" {
		params.Set("hd", p.cfg.HD)
	}
	if opts.LoginHint != "" {
		params.Set("login_hint", opts.LoginHint)
	}
	return provider.BuildAuthURL(p.authorizationEndpoint(), params), nil
}

func (p *Provider) ValidateAuthorizationCode(ctx context.Context, code, codeVerifier, redirectURI string) (*provider.OAuthTokens, error) {
	data, err := provider.ExchangeAuthorizationCode(ctx, provider.CodeExchangeOpts{
		TokenURL:     tokenEndpoint,
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		Code:         code,
		RedirectURI:  p.redirectURI(redirectURI),
		CodeVerifier: codeVerifier,
	})
	if err != nil {
		return nil, err
	}
	return provider.TokensFromMap(data), nil
}

func (p *Provider) authorizationEndpoint() string {
	if p.cfg.AuthorizationEndpoint != "" {
		return p.cfg.AuthorizationEndpoint
	}
	return authEndpoint
}

func (p *Provider) redirectURI(defaultRedirectURI string) string {
	if p.cfg.RedirectURI != "" {
		return p.cfg.RedirectURI
	}
	return defaultRedirectURI
}

func (p *Provider) GetUserInfo(ctx context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error) {
	if p.cfg.GetUserInfo != nil {
		return p.cfg.GetUserInfo(ctx, tokens)
	}
	idToken := tokens.IDToken
	if idToken == "" {
		return nil, fmt.Errorf("google id_token missing")
	}
	claims, err := jwt.DecodePayload(idToken)
	if err != nil {
		return nil, err
	}
	if !hostedDomainAllowed(p.cfg.HD, claims["hd"]) {
		return nil, nil
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

func hostedDomainAllowed(configuredHostedDomain string, tokenHostedDomain any) bool {
	if configuredHostedDomain == "" {
		return true
	}
	hostedDomain, ok := tokenHostedDomain.(string)
	if !ok || hostedDomain == "" {
		return false
	}
	if configuredHostedDomain == "*" {
		return true
	}
	return hostedDomain == configuredHostedDomain
}

func (p *Provider) RefreshAccessToken(ctx context.Context, refreshToken string) (*provider.OAuthTokens, error) {
	return provider.RefreshAccessToken(ctx, tokenEndpoint, p.cfg.ClientID, p.cfg.ClientSecret, refreshToken)
}
