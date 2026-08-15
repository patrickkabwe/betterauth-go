package oauth2provider

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

	"github.com/patrickkabwe/betterauth-go/internal/jwt"
	"github.com/patrickkabwe/betterauth-go/provider"
)

const (
	googleJWKSEndpoint = "https://www.googleapis.com/oauth2/v3/certs"
	googleMaxTokenAge  = time.Hour
)

// IDTokenProvider is an OAuth provider that can verify native sign-in ID tokens.
type IDTokenProvider struct {
	*Provider
	verifyIDToken func(context.Context, string, string) (bool, error)
}

func (p *IDTokenProvider) VerifyIDToken(ctx context.Context, token string, nonce string) (bool, error) {
	if p.verifyIDToken == nil {
		return false, nil
	}
	return p.verifyIDToken(ctx, token, nonce)
}

// Google creates a Google OAuth provider.
func Google(opts Options) *Provider {
	return googleProvider(opts)
}

// GoogleWithIDToken creates a Google OAuth provider that supports native ID-token sign-in.
func GoogleWithIDToken(opts Options) *IDTokenProvider {
	return &IDTokenProvider{Provider: googleProvider(opts), verifyIDToken: googleIDTokenVerifier(opts)}
}

func googleProvider(opts Options) *Provider {
	params := cloneStringMap(opts.AuthorizationParams)
	params["include_granted_scopes"] = "true"
	if opts.AccessType != "" {
		params["access_type"] = opts.AccessType
	}
	if opts.HD != "" {
		params["hd"] = opts.HD
	}
	return New(Config{
		ID: ProviderGoogle, Name: "Google",
		ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
		Scopes: []string{"email", "profile", "openid"}, AdditionalScopes: opts.Scopes, DisableDefaultScope: opts.DisableDefaultScope,
		AuthorizationEndpoint: endpoint(opts.AuthorizationEndpoint, "https://accounts.google.com/o/oauth2/v2/auth"),
		TokenEndpoint:         endpoint(opts.TokenEndpoint, "https://oauth2.googleapis.com/token"),
		RedirectURI:           opts.RedirectURI,
		Prompt:                opts.Prompt,
		AuthorizationParams:   params,
		AuthorizationParamsAppend: func(values *url.Values, urlOpts provider.AuthorizationURLOpts) {
			display := opts.Display
			if urlOpts.Display != "" {
				display = urlOpts.Display
			}
			if display != "" {
				values.Set("display", display)
			}
		},
		UsePKCE:               true,
		AlwaysSendScope:       true,
		DisableImplicitSignUp: opts.DisableImplicitSignUp, DisableSignUp: opts.DisableSignUp,
		OverrideUserInfoOnSignIn: opts.OverrideUserInfoOnSignIn,
		GetUserInfo:              googleUserInfo(opts),
		MapProfileToUser:         opts.MapProfileToUser,
	})
}

func googleUserInfo(opts Options) func(context.Context, provider.OAuthTokens) (*provider.UserInfo, error) {
	if opts.GetUserInfo != nil {
		return opts.GetUserInfo
	}
	return func(ctx context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error) {
		if tokens.IDToken == "" {
			return nil, fmt.Errorf("google id_token missing")
		}
		claims, err := jwt.DecodePayload(tokens.IDToken)
		if err != nil {
			return nil, err
		}
		if !hostedDomainAllowed(opts.HD, claims["hd"]) {
			return nil, nil
		}
		user := provider.OAuthUser{
			ID: stringField(claims, "sub"), Name: stringField(claims, "name"),
			Email: stringField(claims, "email"), Image: optionalImage(stringField(claims, "picture")),
			EmailVerified: boolField(claims, "email_verified"),
		}
		if opts.MapProfileToUser != nil {
			mapping, err := opts.MapProfileToUser(ctx, claims)
			if err != nil {
				return nil, err
			}
			user = provider.ApplyOAuthUserMapping(user, mapping)
		}
		return &provider.UserInfo{User: user, Data: claims}, nil
	}
}

func googleIDTokenVerifier(opts Options) func(context.Context, string, string) (bool, error) {
	if opts.DisableIDTokenSignIn {
		return func(context.Context, string, string) (bool, error) {
			return false, nil
		}
	}
	return func(ctx context.Context, token string, nonce string) (bool, error) {
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
		if !validGoogleIDTokenClaims(claims, opts.ClientID, nonce, opts.HD, time.Now()) {
			return false, nil
		}
		return true, nil
	}
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleJWKSEndpoint, nil)
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
	if now.Sub(issuedAt) > googleMaxTokenAge {
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
