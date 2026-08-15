package google_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/provider/google"
)

func TestGoogleAuthURLRequiresPKCE(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret"})
	_, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb",
	})
	if err == nil {
		t.Fatal("expected pkce error")
	}
}

func TestGoogleAuthURLIncludesHostedDomain(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", HD: "example.com"})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb", CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(authURL, "hd=example.com") {
		t.Fatalf("url=%s", authURL)
	}
}

func TestGoogleAuthURLUsesEndpointAndRedirectOverrides(t *testing.T) {
	p := google.New(google.Config{
		ClientID:              "id",
		ClientSecret:          "secret",
		AuthorizationEndpoint: "https://accounts.example.com/oauth/auth",
		RedirectURI:           "https://app.example.com/google/callback",
	})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb", CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "https" || parsed.Host != "accounts.example.com" || parsed.Path != "/oauth/auth" {
		t.Fatalf("url=%s", authURL)
	}
	if parsed.Query().Get("redirect_uri") != "https://app.example.com/google/callback" {
		t.Fatalf("redirect_uri=%q", parsed.Query().Get("redirect_uri"))
	}
}

func TestGoogleAuthURLIncludesDisplay(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", Display: "popup"})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb", CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatal(err)
	}
	query := googleAuthURLQuery(t, authURL)
	if query.Get("display") != "popup" {
		t.Fatalf("display=%q", query.Get("display"))
	}
}

func TestGoogleAuthURLOmitsAccessTypeByDefault(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret"})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb", CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatal(err)
	}
	query := googleAuthURLQuery(t, authURL)
	if _, ok := query["access_type"]; ok {
		t.Fatalf("query=%s", query.Encode())
	}
}

func TestGoogleAuthURLIncludesConfiguredAccessType(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", AccessType: "offline"})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb", CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatal(err)
	}
	query := googleAuthURLQuery(t, authURL)
	if query.Get("access_type") != "offline" {
		t.Fatalf("access_type=%q", query.Get("access_type"))
	}
}

func TestGoogleAuthURLDisplayOptionOverridesConfig(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", Display: "popup"})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb", CodeVerifier: "verifier", Display: "touch",
	})
	if err != nil {
		t.Fatal(err)
	}
	query := googleAuthURLQuery(t, authURL)
	if query.Get("display") != "touch" {
		t.Fatalf("display=%q", query.Get("display"))
	}
}

func TestGoogleAuthURLCanDisableDefaultScopes(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", DisableDefaultScope: true, Scopes: []string{"calendar.readonly"}})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb", CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatal(err)
	}
	query := googleAuthURLQuery(t, authURL)
	if query.Get("scope") != "calendar.readonly" {
		t.Fatalf("scope=%q", query.Get("scope"))
	}
}

func TestGoogleAuthURLUsesEmptyScopeWhenDefaultScopesDisabled(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", DisableDefaultScope: true})
	authURL, err := p.CreateAuthorizationURL(context.Background(), provider.AuthorizationURLOpts{
		State: "s", RedirectURI: "http://localhost/cb", CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatal(err)
	}
	query := googleAuthURLQuery(t, authURL)
	scopes, ok := query["scope"]
	if !ok || len(scopes) != 1 || scopes[0] != "" {
		t.Fatalf("scope=%v query=%s", scopes, query.Encode())
	}
}

func TestGoogleGetUserInfoFromIDToken(t *testing.T) {
	claims := map[string]any{
		"sub": "google-sub", "email": "g@example.com", "email_verified": true,
		"name": "G User", "picture": "http://img",
	}
	token := googleTestIDToken(claims)
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret"})
	info, err := p.GetUserInfo(context.Background(), provider.OAuthTokens{IDToken: token})
	if err != nil || info.User.Email != "g@example.com" || info.User.ID != "google-sub" {
		t.Fatalf("info=%+v err=%v", info, err)
	}
}

func TestGoogleGetUserInfoUsesOverride(t *testing.T) {
	p := google.New(google.Config{
		ClientID: "id", ClientSecret: "secret",
		GetUserInfo: func(_ context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error) {
			return &provider.UserInfo{
				User: provider.OAuthUser{ID: "custom-google", Email: tokens.AccessToken + "@example.com", EmailVerified: true},
				Data: map[string]any{"source": "override"},
			}, nil
		},
	})
	info, err := p.GetUserInfo(context.Background(), provider.OAuthTokens{AccessToken: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	if info.User.ID != "custom-google" || info.User.Email != "custom@example.com" || info.Data["source"] != "override" {
		t.Fatalf("info=%+v", info)
	}
}

func TestGoogleGetUserInfoMapsProfileToUser(t *testing.T) {
	claims := map[string]any{
		"sub": "google-sub", "email": "g@example.com", "email_verified": false,
		"name": "G User", "picture": "http://img",
	}
	mappedName := "Mapped Google"
	mappedVerified := true
	p := google.New(google.Config{
		ClientID: "id", ClientSecret: "secret",
		MapProfileToUser: func(_ context.Context, profile map[string]any) (provider.OAuthUserMapping, error) {
			if profile["sub"] != "google-sub" {
				t.Fatalf("profile=%+v", profile)
			}
			return provider.OAuthUserMapping{Name: &mappedName, EmailVerified: &mappedVerified}, nil
		},
	})
	info, err := p.GetUserInfo(context.Background(), provider.OAuthTokens{IDToken: googleTestIDToken(claims)})
	if err != nil {
		t.Fatal(err)
	}
	if info.User.ID != "google-sub" || info.User.Name != "Mapped Google" || !info.User.EmailVerified {
		t.Fatalf("user=%+v", info.User)
	}
}

func TestGoogleGetUserInfoRejectsHostedDomainMismatch(t *testing.T) {
	token := googleTestIDToken(map[string]any{
		"sub": "google-sub", "email": "g@example.com", "email_verified": true,
		"name": "G User", "hd": "other.com",
	})
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", HD: "example.com"})
	info, err := p.GetUserInfo(context.Background(), provider.OAuthTokens{IDToken: token})
	if err != nil {
		t.Fatal(err)
	}
	if info != nil {
		t.Fatalf("info=%+v", info)
	}
}

func TestGoogleGetUserInfoAllowsAnyHostedDomain(t *testing.T) {
	token := googleTestIDToken(map[string]any{
		"sub": "google-sub", "email": "g@example.com", "email_verified": true,
		"name": "G User", "hd": "workspace.com",
	})
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", HD: "*"})
	info, err := p.GetUserInfo(context.Background(), provider.OAuthTokens{IDToken: token})
	if err != nil || info == nil || info.User.Email != "g@example.com" {
		t.Fatalf("info=%+v err=%v", info, err)
	}
}

func TestGoogleGetUserInfoRequiresHostedDomainClaim(t *testing.T) {
	token := googleTestIDToken(map[string]any{
		"sub": "google-sub", "email": "g@example.com", "email_verified": true,
		"name": "G User",
	})
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", HD: "*"})
	info, err := p.GetUserInfo(context.Background(), provider.OAuthTokens{IDToken: token})
	if err != nil {
		t.Fatal(err)
	}
	if info != nil {
		t.Fatalf("info=%+v", info)
	}
}

func TestGoogleVerifyIDTokenAcceptsValidToken(t *testing.T) {
	token, jwks := signedGoogleIDToken(t, map[string]any{
		"aud":   "id",
		"nonce": "nonce-value",
		"hd":    "example.com",
	})
	restore := mockGoogleJWKS(t, jwks)
	defer restore()

	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", HD: "example.com"})
	valid, err := p.VerifyIDToken(context.Background(), token, "nonce-value")
	if err != nil || !valid {
		t.Fatalf("valid=%v err=%v", valid, err)
	}
}

func TestGoogleVerifyIDTokenRejectsNonceMismatch(t *testing.T) {
	token, jwks := signedGoogleIDToken(t, map[string]any{
		"aud":   "id",
		"nonce": "nonce-value",
	})
	restore := mockGoogleJWKS(t, jwks)
	defer restore()

	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret"})
	valid, err := p.VerifyIDToken(context.Background(), token, "other-nonce")
	if err != nil || valid {
		t.Fatalf("valid=%v err=%v", valid, err)
	}
}

func TestGoogleVerifyIDTokenRejectsAudienceMismatch(t *testing.T) {
	token, jwks := signedGoogleIDToken(t, map[string]any{
		"aud": "other-client",
	})
	restore := mockGoogleJWKS(t, jwks)
	defer restore()

	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret"})
	valid, err := p.VerifyIDToken(context.Background(), token, "")
	if err != nil || valid {
		t.Fatalf("valid=%v err=%v", valid, err)
	}
}

func TestGoogleVerifyIDTokenRejectsHostedDomainMismatch(t *testing.T) {
	token, jwks := signedGoogleIDToken(t, map[string]any{
		"aud": "id",
		"hd":  "other.com",
	})
	restore := mockGoogleJWKS(t, jwks)
	defer restore()

	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", HD: "example.com"})
	valid, err := p.VerifyIDToken(context.Background(), token, "")
	if err != nil || valid {
		t.Fatalf("valid=%v err=%v", valid, err)
	}
}

func TestGoogleVerifyIDTokenCanBeDisabled(t *testing.T) {
	token, _ := signedGoogleIDToken(t, map[string]any{"aud": "id"})
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", DisableIDTokenSignIn: true})
	valid, err := p.VerifyIDToken(context.Background(), token, "")
	if err != nil || valid {
		t.Fatalf("valid=%v err=%v", valid, err)
	}
}

func TestGoogleSignUpPolicy(t *testing.T) {
	p := google.New(google.Config{ClientID: "id", ClientSecret: "secret", DisableImplicitSignUp: true, DisableSignUp: true, OverrideUserInfoOnSignIn: true})
	if !p.DisableImplicitSignUp() || !p.DisableSignUp() {
		t.Fatalf("policy implicit=%v signup=%v", p.DisableImplicitSignUp(), p.DisableSignUp())
	}
	if !p.OverrideUserInfoOnSignIn() {
		t.Fatal("expected user info override")
	}
}

func googleTestIDToken(claims map[string]any) string {
	raw, _ := json.Marshal(claims)
	return "hdr." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

func signedGoogleIDToken(t *testing.T, claims map[string]any) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	payload := map[string]any{
		"iss":            "https://accounts.google.com",
		"aud":            "id",
		"sub":            "google-sub",
		"email":          "g@example.com",
		"email_verified": true,
		"name":           "G User",
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
	}
	for name, value := range claims {
		payload[name] = value
	}
	header := map[string]any{"alg": "RS256", "kid": "test-google-key", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
	exponent := big.NewInt(int64(key.PublicKey.E)).Bytes()
	jwksBody, err := json.Marshal(map[string]any{
		"keys": []map[string]any{
			{
				"kid": "test-google-key",
				"alg": "RS256",
				"kty": "RSA",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(exponent),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return token, string(jwksBody)
}

func mockGoogleJWKS(t *testing.T, jwks string) func() {
	t.Helper()
	transport := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://www.googleapis.com/oauth2/v3/certs" {
			t.Fatalf("unexpected request URL: %s", req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(jwks)),
			Request:    req,
		}, nil
	})
	return func() {
		http.DefaultTransport = transport
	}
}

func googleAuthURLQuery(t *testing.T, authURL string) url.Values {
	t.Helper()
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Query()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
