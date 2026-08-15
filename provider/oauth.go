package provider

import (
	"context"
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
	TokenURL     string
	ClientID     string
	ClientSecret string
	Code         string
	RedirectURI  string
	CodeVerifier string
	ExtraParams  map[string]string
}

// ExchangeAuthorizationCode performs a standard OAuth2 code exchange.
func ExchangeAuthorizationCode(ctx context.Context, opts CodeExchangeOpts) (map[string]any, error) {
	form := url.Values{}
	if len(opts.ExtraParams) > 0 {
		for k, v := range opts.ExtraParams {
			form.Set(k, v)
		}
	} else {
		form.Set("grant_type", "authorization_code")
		form.Set("code", opts.Code)
		form.Set("redirect_uri", opts.RedirectURI)
		form.Set("client_id", opts.ClientID)
		if opts.ClientSecret != "" {
			form.Set("client_secret", opts.ClientSecret)
		}
		if opts.CodeVerifier != "" {
			form.Set("code_verifier", opts.CodeVerifier)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

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
	if strings.Contains(endpoint, "?") {
		return endpoint + "&" + params.Encode()
	}
	return endpoint + "?" + params.Encode()
}

// RefreshAccessToken performs a refresh_token grant.
func RefreshAccessToken(ctx context.Context, tokenURL, clientID, clientSecret, refreshToken string) (*OAuthTokens, error) {
	params := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     clientID,
	}
	if clientSecret != "" {
		params["client_secret"] = clientSecret
	}
	data, err := ExchangeAuthorizationCode(ctx, CodeExchangeOpts{
		TokenURL:    tokenURL,
		ExtraParams: params,
	})
	if err != nil {
		return nil, err
	}
	return TokensFromMap(data), nil
}
