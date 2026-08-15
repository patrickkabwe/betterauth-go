package google

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/jwt"
	oauth2pkg "github.com/patrickkabwe/betterauth-go/internal/oauth2"
	"github.com/patrickkabwe/betterauth-go/provider"
)

const (
	providerID    = constants.ProviderGoogle
	authEndpoint  = "https://accounts.google.com/o/oauth2/v2/auth"
	tokenEndpoint = "https://oauth2.googleapis.com/token"
	jwksEndpoint  = "https://www.googleapis.com/oauth2/v3/certs"
	maxTokenAge   = time.Hour
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
	params.Set("scope", strings.Join(scopes, " "))
	params.Set("state", opts.State)
	params.Set("code_challenge", oauth2pkg.CodeChallengeS256(opts.CodeVerifier))
	params.Set("code_challenge_method", "S256")
	params.Set("include_granted_scopes", "true")
	if p.cfg.AccessType != "" {
		params.Set("access_type", p.cfg.AccessType)
	}
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
		TokenURL:       tokenEndpoint,
		ClientID:       p.cfg.ClientID,
		ClientSecret:   p.cfg.ClientSecret,
		Code:           code,
		RedirectURI:    p.redirectURI(redirectURI),
		CodeVerifier:   codeVerifier,
		Authentication: provider.OAuthClientAuthenticationPost,
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
	user := provider.OAuthUser{
		ID: sub, Name: name, Email: email, Image: image, EmailVerified: verified,
	}
	if p.cfg.MapProfileToUser != nil {
		mapping, err := p.cfg.MapProfileToUser(ctx, claims)
		if err != nil {
			return nil, err
		}
		user = provider.ApplyOAuthUserMapping(user, mapping)
	}
	return &provider.UserInfo{
		User: user,
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

func (p *Provider) VerifyIDToken(ctx context.Context, token, nonce string) (bool, error) {
	if p.cfg.DisableIDTokenSignIn {
		return false, nil
	}
	header, claims, signingInput, signature, err := googleIDTokenParts(token)
	if err != nil {
		return false, nil
	}
	kid, _ := header["kid"].(string)
	alg, _ := header["alg"].(string)
	if kid == "" || alg != "RS256" {
		return false, nil
	}
	key, err := googlePublicKey(ctx, kid)
	if err != nil {
		return false, nil
	}
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return false, nil
	}
	if !validGoogleIDTokenClaims(claims, p.cfg.ClientID, nonce, p.cfg.HD, time.Now()) {
		return false, nil
	}
	return true, nil
}

func googleIDTokenParts(token string) (map[string]any, map[string]any, string, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, "", nil, fmt.Errorf("invalid google id token")
	}
	header, err := decodeGoogleJWTPart(parts[0])
	if err != nil {
		return nil, nil, "", nil, err
	}
	claims, err := decodeGoogleJWTPart(parts[1])
	if err != nil {
		return nil, nil, "", nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, "", nil, err
	}
	return header, claims, parts[0] + "." + parts[1], signature, nil
}

func decodeGoogleJWTPart(part string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

type googleJWKSet struct {
	Keys []googleJWK `json:"keys"`
}

type googleJWK struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func googlePublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksEndpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("google jwks request failed with status %d: %s", resp.StatusCode, string(body))
	}
	var keys googleJWKSet
	if err := json.Unmarshal(body, &keys); err != nil {
		return nil, err
	}
	for _, key := range keys.Keys {
		if key.Kid == kid {
			return googleJWKPublicKey(key)
		}
	}
	return nil, fmt.Errorf("google jwk %q not found", kid)
}

func googleJWKPublicKey(key googleJWK) (*rsa.PublicKey, error) {
	if key.Kty != "RSA" || key.N == "" || key.E == "" {
		return nil, fmt.Errorf("invalid google jwk")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	if e == 0 {
		return nil, fmt.Errorf("invalid google jwk exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func validGoogleIDTokenClaims(claims map[string]any, audience string, nonce string, hostedDomain string, now time.Time) bool {
	if !validGoogleIssuer(claims["iss"]) || !validGoogleAudience(claims["aud"], audience) {
		return false
	}
	if !validGoogleTimeClaims(claims, now) {
		return false
	}
	if nonce != "" && claims["nonce"] != nonce {
		return false
	}
	return hostedDomainAllowed(hostedDomain, claims["hd"])
}

func validGoogleIssuer(value any) bool {
	issuer, ok := value.(string)
	return ok && (issuer == "https://accounts.google.com" || issuer == "accounts.google.com")
}

func validGoogleAudience(value any, audience string) bool {
	switch aud := value.(type) {
	case string:
		return aud == audience
	case []any:
		for _, item := range aud {
			if item == audience {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func validGoogleTimeClaims(claims map[string]any, now time.Time) bool {
	exp, ok := googleNumericClaim(claims["exp"])
	if !ok || now.Unix() >= exp {
		return false
	}
	if nbf, ok := googleNumericClaim(claims["nbf"]); ok && now.Unix() < nbf {
		return false
	}
	iat, ok := googleNumericClaim(claims["iat"])
	if !ok {
		return false
	}
	issuedAt := time.Unix(iat, 0)
	if issuedAt.After(now.Add(time.Minute)) {
		return false
	}
	if now.Sub(issuedAt) > maxTokenAge {
		return false
	}
	return true
}

func googleNumericClaim(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), true
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	default:
		return 0, false
	}
}
