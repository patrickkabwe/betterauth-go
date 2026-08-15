package oauth2provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	oauth2pkg "github.com/patrickkabwe/betterauth-go/internal/oauth2"
	"github.com/patrickkabwe/betterauth-go/provider"
)

const defaultUserAgent = "better-auth"

// ProfileMapper converts provider profile JSON into a Better Auth OAuth user.
type ProfileMapper func(context.Context, map[string]any) (provider.OAuthUser, error)

// ProfileExtractor selects the profile object from a provider user-info response.
type ProfileExtractor func(map[string]any) (map[string]any, error)

// Config describes a standard OAuth2 provider.
type Config struct {
	ID                        string
	Name                      string
	ClientID                  string
	ClientSecret              string
	Scopes                    []string
	AdditionalScopes          []string
	DisableDefaultScope       bool
	AuthorizationEndpoint     string
	TokenEndpoint             string
	UserInfoEndpoint          string
	AlwaysSendScope           bool
	UserInfoMethod            string
	UserInfoBody              string
	UserInfoHeaders           map[string]string
	RedirectURI               string
	Prompt                    string
	AuthorizationParams       map[string]string
	AuthorizationParamsFunc   func(provider.AuthorizationURLOpts) map[string]string
	AuthorizationParamsAppend func(*url.Values, provider.AuthorizationURLOpts)
	UsePKCE                   bool
	TokenAuthentication       provider.OAuthClientAuthentication
	DisableImplicitSignUp     bool
	DisableSignUp             bool
	OverrideUserInfoOnSignIn  bool
	GetUserInfo               func(context.Context, provider.OAuthTokens) (*provider.UserInfo, error)
	MapProfileToUser          func(context.Context, map[string]any) (provider.OAuthUserMapping, error)
	ProfileMapper             ProfileMapper
	ProfileExtractor          ProfileExtractor
}

// Provider implements a conventional OAuth2 social provider.
type Provider struct {
	cfg                 Config
	baseScopes          []string
	baseScopeSet        map[string]struct{}
	baseScopeString     string
	authorizationParams []authorizationParam
}

type authorizationParam struct {
	key   string
	value string
}

// New creates a conventional OAuth2 provider.
func New(cfg Config) *Provider {
	baseScopes := staticScopes(cfg.Scopes, cfg.AdditionalScopes, cfg.DisableDefaultScope)
	return &Provider{
		cfg:                 cfg,
		baseScopes:          baseScopes,
		baseScopeSet:        scopeSet(baseScopes),
		baseScopeString:     strings.Join(baseScopes, " "),
		authorizationParams: authorizationParams(cfg.AuthorizationParams),
	}
}

func (p *Provider) ID() string { return p.cfg.ID }

func (p *Provider) DisableImplicitSignUp() bool { return p.cfg.DisableImplicitSignUp }

func (p *Provider) DisableSignUp() bool { return p.cfg.DisableSignUp }

func (p *Provider) OverrideUserInfoOnSignIn() bool {
	return p.cfg.OverrideUserInfoOnSignIn
}

func (p *Provider) CreateAuthorizationURL(_ context.Context, opts provider.AuthorizationURLOpts) (string, error) {
	if p.cfg.ClientID == "" || p.cfg.ClientSecret == "" {
		return "", fmt.Errorf("%s client id and secret are required", p.cfg.ID)
	}
	if p.cfg.AuthorizationEndpoint == "" {
		return "", fmt.Errorf("%s authorization endpoint is required", p.cfg.ID)
	}
	if p.cfg.UsePKCE && opts.CodeVerifier == "" {
		return "", fmt.Errorf("code verifier is required for %s", p.cfg.ID)
	}

	params := url.Values{}
	params.Set("client_id", p.cfg.ClientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", p.redirectURI(opts.RedirectURI))
	params.Set("state", opts.State)
	scope := p.scopeString(opts.Scopes)
	if scope != "" || p.cfg.AlwaysSendScope {
		params.Set("scope", scope)
	}
	if p.cfg.UsePKCE {
		params.Set("code_challenge", oauth2pkg.CodeChallengeS256(opts.CodeVerifier))
		params.Set("code_challenge_method", "S256")
	}
	if p.cfg.Prompt != "" {
		params.Set("prompt", p.cfg.Prompt)
	}
	if opts.LoginHint != "" {
		params.Set("login_hint", opts.LoginHint)
	}
	for _, param := range p.authorizationParams {
		params.Set(param.key, param.value)
	}
	if p.cfg.AuthorizationParamsFunc != nil {
		for key, value := range p.cfg.AuthorizationParamsFunc(opts) {
			params.Set(key, value)
		}
	}
	if p.cfg.AuthorizationParamsAppend != nil {
		p.cfg.AuthorizationParamsAppend(&params, opts)
	}
	return provider.BuildAuthURL(p.cfg.AuthorizationEndpoint, params), nil
}

func (p *Provider) ValidateAuthorizationCode(ctx context.Context, code, codeVerifier, redirectURI string) (*provider.OAuthTokens, error) {
	if p.cfg.TokenEndpoint == "" {
		return nil, fmt.Errorf("%s token endpoint is required", p.cfg.ID)
	}
	opts := provider.CodeExchangeOpts{
		TokenURL:       p.cfg.TokenEndpoint,
		ClientID:       p.cfg.ClientID,
		ClientSecret:   p.cfg.ClientSecret,
		Code:           code,
		RedirectURI:    p.redirectURI(redirectURI),
		Authentication: p.tokenAuthentication(),
	}
	if p.cfg.UsePKCE {
		opts.CodeVerifier = codeVerifier
	}
	data, err := provider.ExchangeAuthorizationCode(ctx, opts)
	if err != nil {
		return nil, err
	}
	return provider.TokensFromMap(data), nil
}

func (p *Provider) RefreshAccessToken(ctx context.Context, refreshToken string) (*provider.OAuthTokens, error) {
	if p.cfg.TokenEndpoint == "" {
		return nil, fmt.Errorf("%s token endpoint is required", p.cfg.ID)
	}
	return provider.RefreshAccessTokenWithOptions(ctx, provider.RefreshAccessTokenOpts{
		TokenURL:       p.cfg.TokenEndpoint,
		ClientID:       p.cfg.ClientID,
		ClientSecret:   p.cfg.ClientSecret,
		RefreshToken:   refreshToken,
		Authentication: p.tokenAuthentication(),
	})
}

func (p *Provider) GetUserInfo(ctx context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error) {
	if p.cfg.GetUserInfo != nil {
		return p.cfg.GetUserInfo(ctx, tokens)
	}
	if tokens.AccessToken == "" {
		return nil, fmt.Errorf("%s access token missing", p.cfg.ID)
	}
	if p.cfg.UserInfoEndpoint == "" {
		return nil, fmt.Errorf("%s user info endpoint is required", p.cfg.ID)
	}
	if p.cfg.ProfileMapper == nil {
		return nil, fmt.Errorf("%s profile mapper is required", p.cfg.ID)
	}

	raw, err := p.fetchUserInfo(ctx, tokens.AccessToken)
	if err != nil {
		return nil, err
	}
	profile := raw
	if p.cfg.ProfileExtractor != nil {
		profile, err = p.cfg.ProfileExtractor(raw)
		if err != nil {
			return nil, err
		}
	}
	user, err := p.cfg.ProfileMapper(ctx, profile)
	if err != nil {
		return nil, err
	}
	if p.cfg.MapProfileToUser != nil {
		mapping, err := p.cfg.MapProfileToUser(ctx, profile)
		if err != nil {
			return nil, err
		}
		user = provider.ApplyOAuthUserMapping(user, mapping)
	}
	return &provider.UserInfo{User: user, Data: profile}, nil
}

func (p *Provider) scopeString(extra []string) string {
	if len(extra) == 0 {
		return p.baseScopeString
	}
	out := make([]string, 0, len(p.baseScopes)+len(extra))
	out = append(out, p.baseScopes...)
	extraSeen := make(map[string]struct{}, len(extra))
	for _, scope := range extra {
		if scope == "" {
			continue
		}
		if _, ok := p.baseScopeSet[scope]; ok {
			continue
		}
		if _, ok := extraSeen[scope]; ok {
			continue
		}
		extraSeen[scope] = struct{}{}
		out = append(out, scope)
	}
	return strings.Join(out, " ")
}

func (p *Provider) redirectURI(defaultRedirectURI string) string {
	if p.cfg.RedirectURI != "" {
		return p.cfg.RedirectURI
	}
	return defaultRedirectURI
}

func (p *Provider) tokenAuthentication() provider.OAuthClientAuthentication {
	if p.cfg.TokenAuthentication != "" {
		return p.cfg.TokenAuthentication
	}
	return provider.OAuthClientAuthenticationPost
}

func staticScopes(defaultScopes []string, additionalScopes []string, disableDefaultScopes bool) []string {
	total := len(additionalScopes)
	if !disableDefaultScopes {
		total += len(defaultScopes)
	}
	if total == 0 {
		return nil
	}
	seen := make(map[string]struct{}, total)
	out := make([]string, 0, total)
	if !disableDefaultScopes {
		out = appendUniqueScopes(out, seen, defaultScopes)
	}
	return appendUniqueScopes(out, seen, additionalScopes)
}

func appendUniqueScopes(out []string, seen map[string]struct{}, scopes []string) []string {
	for _, scope := range scopes {
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	return out
}

func scopeSet(scopes []string) map[string]struct{} {
	if len(scopes) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		out[scope] = struct{}{}
	}
	return out
}

func authorizationParams(params map[string]string) []authorizationParam {
	if len(params) == 0 {
		return nil
	}
	out := make([]authorizationParam, 0, len(params))
	for key, value := range params {
		out = append(out, authorizationParam{key: key, value: value})
	}
	return out
}

func (p *Provider) fetchUserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	method := p.cfg.UserInfoMethod
	if method == "" {
		method = http.MethodGet
	}
	body := io.Reader(nil)
	if p.cfg.UserInfoBody != "" {
		body = bytes.NewBufferString(p.cfg.UserInfoBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.cfg.UserInfoEndpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", defaultUserAgent)
	for key, value := range p.cfg.UserInfoHeaders {
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s user info failed: status=%d body=%s", p.cfg.ID, resp.StatusCode, string(responseBody))
	}
	var raw map[string]any
	if err := json.Unmarshal(responseBody, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func stringField(profile map[string]any, key string) string {
	value, ok := profile[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case json.Number:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func boolField(profile map[string]any, key string) bool {
	value, ok := profile[key]
	if !ok || value == nil {
		return false
	}
	typed, ok := value.(bool)
	return ok && typed
}

func mapField(profile map[string]any, key string) map[string]any {
	value, ok := profile[key]
	if !ok || value == nil {
		return nil
	}
	typed, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return typed
}

func optionalImage(value string) *string {
	if value == "" {
		return nil
	}
	image := value
	return &image
}

func requiredProfile(profile map[string]any, key string) (map[string]any, error) {
	next := mapField(profile, key)
	if next == nil {
		return nil, fmt.Errorf("profile field %q is required", key)
	}
	return next, nil
}

func errInactiveProfile(providerID string) error {
	return errors.New(providerID + " profile is inactive")
}
