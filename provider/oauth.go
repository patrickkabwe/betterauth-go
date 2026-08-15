package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ClientConfig holds OAuth client credentials.
type ClientConfig struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
}

// OAuthProvider supports the authorization-code OAuth flow.
type OAuthProvider interface {
	SocialProvider
	ValidateAuthorizationCode(ctx context.Context, code, codeVerifier, redirectURI string) (*OAuthTokens, error)
}

// CodeExchangeOpts configures an authorization-code token exchange.
type CodeExchangeOpts struct {
	TokenURL       string
	ClientID       string
	ClientSecret   string
	ClientKey      string
	Code           string
	RedirectURI    string
	CodeVerifier   string
	DeviceID       string
	Authentication OAuthClientAuthentication
	Headers        map[string]string
	Resources      []string
	ExtraParams    map[string]string
	ExtraOverwrite bool
}

// OAuthClientAuthentication controls how client credentials are sent.
type OAuthClientAuthentication string

const (
	OAuthClientAuthenticationPost  OAuthClientAuthentication = "post"
	OAuthClientAuthenticationBasic OAuthClientAuthentication = "basic"
)

// RefreshAccessTokenOpts configures a refresh_token grant request.
type RefreshAccessTokenOpts struct {
	TokenURL       string
	ClientID       string
	ClientSecret   string
	RefreshToken   string
	Authentication OAuthClientAuthentication
	Resources      []string
	ExtraParams    map[string]string
}

// ExchangeAuthorizationCode performs a standard OAuth2 code exchange.
func ExchangeAuthorizationCode(ctx context.Context, opts CodeExchangeOpts) (map[string]any, error) {
	form := url.Values{}
	headers := http.Header{}
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	headers.Set("Accept", "application/json")
	for key, value := range opts.Headers {
		headers.Set(key, value)
	}
	if opts.Code != "" {
		form.Set("grant_type", "authorization_code")
		form.Set("code", opts.Code)
		form.Set("redirect_uri", opts.RedirectURI)
		if opts.CodeVerifier != "" {
			form.Set("code_verifier", opts.CodeVerifier)
		}
		if opts.ClientKey != "" {
			form.Set("client_key", opts.ClientKey)
		}
		if opts.DeviceID != "" {
			form.Set("device_id", opts.DeviceID)
		}
		for _, resource := range opts.Resources {
			form.Add("resource", resource)
		}
		if err := applyOAuthClientAuthentication(headers, form, opts.ClientID, opts.ClientSecret, opts.Authentication, opts.TokenURL); err != nil {
			return nil, err
		}
	}
	for k, v := range opts.ExtraParams {
		if opts.ExtraOverwrite {
			form.Set(k, v)
			continue
		}
		if _, exists := form[k]; !exists {
			form.Set(k, v)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = headers

	resp, err := noRedirectHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if isRedirectStatus(resp.StatusCode) {
		return nil, fmt.Errorf("oauth endpoint %q returned an HTTP redirect; configure the final endpoint URL", opts.TokenURL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	if errCode, ok := data["error"].(string); ok && errCode != "" {
		return nil, fmt.Errorf("oauth error: %s", errCode)
	}
	return data, nil
}

func noRedirectHTTPClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func isRedirectStatus(status int) bool {
	return status == http.StatusMovedPermanently ||
		status == http.StatusFound ||
		status == http.StatusSeeOther ||
		status == http.StatusTemporaryRedirect ||
		status == http.StatusPermanentRedirect
}

// TokensFromMap converts a token endpoint JSON body into OAuthTokens.
func TokensFromMap(data map[string]any) *OAuthTokens {
	tokens := &OAuthTokens{Raw: cloneTokenData(data)}
	if v, ok := data["token_type"].(string); ok {
		tokens.TokenType = v
	}
	if v, ok := data["access_token"].(string); ok {
		tokens.AccessToken = v
	}
	if v, ok := data["refresh_token"].(string); ok {
		tokens.RefreshToken = v
	}
	if v, ok := data["id_token"].(string); ok {
		tokens.IDToken = v
	}
	tokens.Scopes = tokenScopes(data["scope"])
	if exp, ok := tokenSeconds(data["expires_in"]); ok {
		t := time.Now().Add(time.Duration(exp) * time.Second)
		tokens.AccessTokenExpiresAt = &t
	}
	if exp, ok := tokenSeconds(data["refresh_token_expires_in"]); ok {
		t := time.Now().Add(time.Duration(exp) * time.Second)
		tokens.RefreshTokenExpiresAt = &t
	}
	return tokens
}

func tokenSeconds(value any) (float64, bool) {
	switch seconds := value.(type) {
	case float64:
		return seconds, true
	case float32:
		return float64(seconds), true
	case int:
		return float64(seconds), true
	case int64:
		return float64(seconds), true
	case json.Number:
		value, err := seconds.Float64()
		if err != nil {
			return 0, false
		}
		return value, true
	default:
		return 0, false
	}
}

func tokenScopes(value any) []string {
	switch scopes := value.(type) {
	case string:
		if scopes == "" {
			return nil
		}
		return strings.Split(scopes, " ")
	case []string:
		return append([]string(nil), scopes...)
	case []any:
		out := make([]string, 0, len(scopes))
		for _, scope := range scopes {
			value, ok := scope.(string)
			if ok {
				out = append(out, value)
			}
		}
		return out
	default:
		return nil
	}
}

func cloneTokenData(data map[string]any) map[string]any {
	if len(data) == 0 {
		return nil
	}
	out := make(map[string]any, len(data))
	for key, value := range data {
		out[key] = value
	}
	return out
}

// BuildAuthURL constructs an OAuth2 authorization URL.
func BuildAuthURL(endpoint string, params url.Values) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	query := parsed.Query()
	for key, values := range params {
		query.Del(key)
		for _, value := range values {
			query.Add(key, value)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// RefreshAccessToken performs a refresh_token grant.
func RefreshAccessToken(ctx context.Context, tokenURL, clientID, clientSecret, refreshToken string) (*OAuthTokens, error) {
	return RefreshAccessTokenWithOptions(ctx, RefreshAccessTokenOpts{
		TokenURL:       tokenURL,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		RefreshToken:   refreshToken,
		Authentication: OAuthClientAuthenticationPost,
	})
}

// RefreshAccessTokenWithOptions performs a refresh_token grant with explicit request options.
func RefreshAccessTokenWithOptions(ctx context.Context, opts RefreshAccessTokenOpts) (*OAuthTokens, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", opts.RefreshToken)
	headers := http.Header{}
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	headers.Set("Accept", "application/json")
	if err := applyOAuthClientAuthentication(headers, form, opts.ClientID, opts.ClientSecret, opts.Authentication, opts.TokenURL); err != nil {
		return nil, err
	}
	for _, resource := range opts.Resources {
		form.Add("resource", resource)
	}
	for key, value := range opts.ExtraParams {
		form.Set(key, value)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = headers
	resp, err := noRedirectHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if isRedirectStatus(resp.StatusCode) {
		return nil, fmt.Errorf("oauth endpoint %q returned an HTTP redirect; configure the final endpoint URL", opts.TokenURL)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("refresh token failed for endpoint %q with status %d: %s", opts.TokenURL, resp.StatusCode, string(body))
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	if errCode, ok := data["error"].(string); ok && errCode != "" {
		return nil, fmt.Errorf("oauth refresh error for endpoint %q: %s", opts.TokenURL, errCode)
	}
	return TokensFromMap(data), nil
}

func applyOAuthClientAuthentication(headers http.Header, form url.Values, clientID, clientSecret string, authentication OAuthClientAuthentication, tokenURL string) error {
	switch authentication {
	case "", OAuthClientAuthenticationPost:
		form.Set("client_id", clientID)
		if clientSecret != "" {
			form.Set("client_secret", clientSecret)
		}
	case OAuthClientAuthenticationBasic:
		credentials := clientID + ":" + clientSecret
		headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
	default:
		return fmt.Errorf("unsupported oauth client authentication %q for token endpoint %q", authentication, tokenURL)
	}
	return nil
}
