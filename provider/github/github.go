package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/provider"
)

const (
	providerID    = constants.ProviderGitHub
	authEndpoint  = "https://github.com/login/oauth/authorize"
	tokenEndpoint = "https://github.com/login/oauth/access_token"
	userEndpoint  = "https://api.github.com/user"
	emailEndpoint = "https://api.github.com/user/emails"
)

// Config configures the GitHub OAuth provider.
type Config struct {
	ClientID                 string
	ClientSecret             string
	Scopes                   []string
	Prompt                   string
	DisableDefaultScope      bool
	DisableImplicitSignUp    bool
	DisableSignUp            bool
	OverrideUserInfoOnSignIn bool
}

// Provider implements GitHub OAuth.
type Provider struct {
	cfg Config
}

// New creates a GitHub OAuth provider.
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
		base = append(base, "read:user", "user:email")
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
		return "", fmt.Errorf("github client id and secret are required")
	}
	params := url.Values{}
	params.Set("client_id", p.cfg.ClientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", opts.RedirectURI)
	scopes := p.defaultScopes(opts.Scopes)
	if len(scopes) > 0 {
		params.Set("scope", strings.Join(scopes, " "))
	}
	params.Set("state", opts.State)
	if p.cfg.Prompt != "" {
		params.Set("prompt", p.cfg.Prompt)
	}
	if opts.LoginHint != "" {
		params.Set("login_hint", opts.LoginHint)
	}
	return provider.BuildAuthURL(authEndpoint, params), nil
}

func (p *Provider) ValidateAuthorizationCode(ctx context.Context, code, _, redirectURI string) (*provider.OAuthTokens, error) {
	data, err := provider.ExchangeAuthorizationCode(ctx, provider.CodeExchangeOpts{
		TokenURL:     tokenEndpoint,
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		Code:         code,
		RedirectURI:  redirectURI,
	})
	if err != nil {
		return nil, err
	}
	return provider.TokensFromMap(data), nil
}

type githubProfile struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (p *Provider) GetUserInfo(ctx context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error) {
	if tokens.AccessToken == "" {
		return nil, fmt.Errorf("github access token missing")
	}
	profile, err := p.fetchProfile(ctx, tokens.AccessToken)
	if err != nil {
		return nil, err
	}
	emails, _ := p.fetchEmails(ctx, tokens.AccessToken)
	email := profile.Email
	verified := false
	for _, e := range emails {
		if e.Primary || email == "" {
			email = e.Email
			verified = e.Verified
		}
		if e.Email == profile.Email {
			verified = e.Verified
		}
	}
	name := profile.Name
	if name == "" {
		name = profile.Login
	}
	var image *string
	if profile.AvatarURL != "" {
		image = &profile.AvatarURL
	}
	raw := map[string]any{"profile": profile, "emails": emails}
	return &provider.UserInfo{
		User: provider.OAuthUser{
			ID:            fmt.Sprintf("%d", profile.ID),
			Name:          name,
			Email:         email,
			Image:         image,
			EmailVerified: verified,
		},
		Data: raw,
	}, nil
}

func (p *Provider) fetchProfile(ctx context.Context, accessToken string) (*githubProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "betterauth-go")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github profile: %s", string(body))
	}
	var profile githubProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

func (p *Provider) fetchEmails(ctx context.Context, accessToken string) ([]githubEmail, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, emailEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "betterauth-go")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github emails: %s", string(body))
	}
	var emails []githubEmail
	if err := json.Unmarshal(body, &emails); err != nil {
		return nil, err
	}
	return emails, nil
}

func (p *Provider) RefreshAccessToken(ctx context.Context, refreshToken string) (*provider.OAuthTokens, error) {
	return provider.RefreshAccessToken(ctx, tokenEndpoint, p.cfg.ClientID, p.cfg.ClientSecret, refreshToken)
}
