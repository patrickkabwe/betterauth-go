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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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
	if v, ok := data["scope"].(string); ok && v != "" {
		tokens.Scopes = strings.Split(v, " ")
	}
	if exp, ok := data["expires_in"].(float64); ok {
		t := time.Now().Add(time.Duration(exp) * time.Second)
		tokens.AccessTokenExpiresAt = &t
	}
	if exp, ok := data["refresh_token_expires_in"].(float64); ok {
		t := time.Now().Add(time.Duration(exp) * time.Second)
		tokens.RefreshTokenExpiresAt = &t
	}
	return tokens
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
	data, err := ExchangeAuthorizationCode(ctx, CodeExchangeOpts{
		TokenURL: tokenURL,
		ExtraParams: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": refreshToken,
			"client_id":     clientID,
			"client_secret": clientSecret,
		},
	})
	if err != nil {
		return nil, err
	}
	return TokensFromMap(data), nil
}
