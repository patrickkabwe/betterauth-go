package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestExchangeAuthorizationCodeRefusesRedirect(t *testing.T) {
	internalHit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			http.Redirect(w, r, "/internal-token", http.StatusFound)
		case "/internal-token":
			internalHit = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"leaked-internal-token"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	_, err := ExchangeAuthorizationCode(context.Background(), CodeExchangeOpts{
		TokenURL:     server.URL + "/token",
		ClientID:     "client",
		ClientSecret: "secret",
		Code:         "code",
		RedirectURI:  server.URL + "/callback",
	})
	if err == nil {
		t.Fatal("expected redirect error")
	}
	if internalHit {
		t.Fatal("redirect target was reached")
	}
}

func TestExchangeAuthorizationCodeMergesExtraParams(t *testing.T) {
	var formValues url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		formValues = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-token"}`))
	}))
	defer server.Close()

	_, err := ExchangeAuthorizationCode(context.Background(), CodeExchangeOpts{
		TokenURL:     server.URL,
		ClientID:     "client",
		ClientSecret: "secret",
		Code:         "code",
		RedirectURI:  "https://app.example.com/callback",
		CodeVerifier: "verifier",
		ExtraParams: map[string]string{
			"audience":   "api",
			"grant_type": "custom",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if formValues.Get("grant_type") != "authorization_code" || formValues.Get("code") != "code" || formValues.Get("redirect_uri") != "https://app.example.com/callback" {
		t.Fatalf("form=%v", formValues)
	}
	if formValues.Get("client_id") != "client" || formValues.Get("client_secret") != "secret" || formValues.Get("code_verifier") != "verifier" {
		t.Fatalf("form=%v", formValues)
	}
	if formValues.Get("audience") != "api" {
		t.Fatalf("form=%v", formValues)
	}
}

func TestExchangeAuthorizationCodeSupportsRequestOptions(t *testing.T) {
	var formValues url.Values
	var authorization string
	var customHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		customHeader = r.Header.Get("X-Provider")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		formValues = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-token"}`))
	}))
	defer server.Close()

	_, err := ExchangeAuthorizationCode(context.Background(), CodeExchangeOpts{
		TokenURL:       server.URL,
		ClientID:       "client",
		ClientSecret:   "secret",
		ClientKey:      "client-key",
		Code:           "code",
		RedirectURI:    "https://app.example.com/callback",
		CodeVerifier:   "verifier",
		DeviceID:       "device-id",
		Authentication: OAuthClientAuthenticationBasic,
		Headers: map[string]string{
			"X-Provider": "custom",
		},
		Resources: []string{
			"https://api-one.example.com",
			"https://api-two.example.com",
		},
		ExtraParams: map[string]string{
			"audience":   "api",
			"grant_type": "custom",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("client:secret"))
	if authorization != expectedAuthorization || customHeader != "custom" {
		t.Fatalf("authorization=%q customHeader=%q", authorization, customHeader)
	}
	if formValues.Get("grant_type") != "authorization_code" || formValues.Get("code") != "code" || formValues.Get("redirect_uri") != "https://app.example.com/callback" {
		t.Fatalf("form=%v", formValues)
	}
	if formValues.Get("code_verifier") != "verifier" || formValues.Get("client_key") != "client-key" || formValues.Get("device_id") != "device-id" {
		t.Fatalf("form=%v", formValues)
	}
	if formValues.Get("audience") != "api" {
		t.Fatalf("form=%v", formValues)
	}
	resources := formValues["resource"]
	if len(resources) != 2 || resources[0] != "https://api-one.example.com" || resources[1] != "https://api-two.example.com" {
		t.Fatalf("resources=%v", resources)
	}
	if _, ok := formValues["client_id"]; ok {
		t.Fatalf("form=%v", formValues)
	}
	if _, ok := formValues["client_secret"]; ok {
		t.Fatalf("form=%v", formValues)
	}
}

func TestRefreshAccessTokenOmitsEmptyClientSecret(t *testing.T) {
	var formValues url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		formValues = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access"}`))
	}))
	defer server.Close()

	tokens, err := RefreshAccessToken(context.Background(), server.URL, "client", "", "refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "new-access" {
		t.Fatalf("tokens=%+v", tokens)
	}
	if formValues.Get("grant_type") != "refresh_token" || formValues.Get("refresh_token") != "refresh-token" || formValues.Get("client_id") != "client" {
		t.Fatalf("form=%v", formValues)
	}
	if _, ok := formValues["client_secret"]; ok {
		t.Fatalf("form=%v", formValues)
	}
}

func TestRefreshAccessTokenWithOptionsAddsExtraParams(t *testing.T) {
	var formValues url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		formValues = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access"}`))
	}))
	defer server.Close()

	tokens, err := RefreshAccessTokenWithOptions(context.Background(), RefreshAccessTokenOpts{
		TokenURL:       server.URL,
		ClientID:       "client",
		ClientSecret:   "secret",
		RefreshToken:   "refresh-token",
		Authentication: OAuthClientAuthenticationPost,
		ExtraParams: map[string]string{
			"audience": "api",
			"scope":    "email profile",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "new-access" {
		t.Fatalf("tokens=%+v", tokens)
	}
	if formValues.Get("grant_type") != "refresh_token" || formValues.Get("refresh_token") != "refresh-token" || formValues.Get("client_id") != "client" || formValues.Get("client_secret") != "secret" {
		t.Fatalf("form=%v", formValues)
	}
	if formValues.Get("audience") != "api" || formValues.Get("scope") != "email profile" {
		t.Fatalf("form=%v", formValues)
	}
}

func TestRefreshAccessTokenWithOptionsUsesBasicAuth(t *testing.T) {
	var formValues url.Values
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		formValues = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access"}`))
	}))
	defer server.Close()

	_, err := RefreshAccessTokenWithOptions(context.Background(), RefreshAccessTokenOpts{
		TokenURL:       server.URL,
		ClientID:       "client",
		ClientSecret:   "secret",
		RefreshToken:   "refresh-token",
		Authentication: OAuthClientAuthenticationBasic,
		ExtraParams: map[string]string{
			"resource": "https://api.example.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	expectedAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("client:secret"))
	if authorization != expectedAuthorization {
		t.Fatalf("authorization=%q", authorization)
	}
	if formValues.Get("grant_type") != "refresh_token" || formValues.Get("refresh_token") != "refresh-token" || formValues.Get("resource") != "https://api.example.com" {
		t.Fatalf("form=%v", formValues)
	}
	if _, ok := formValues["client_id"]; ok {
		t.Fatalf("form=%v", formValues)
	}
	if _, ok := formValues["client_secret"]; ok {
		t.Fatalf("form=%v", formValues)
	}
}

func TestRefreshAccessTokenWithOptionsRejectsUnknownAuthentication(t *testing.T) {
	_, err := RefreshAccessTokenWithOptions(context.Background(), RefreshAccessTokenOpts{
		TokenURL:       "https://auth.example.com/token",
		ClientID:       "client",
		ClientSecret:   "secret",
		RefreshToken:   "refresh-token",
		Authentication: OAuthClientAuthentication("custom"),
	})
	if err == nil {
		t.Fatal("expected authentication error")
	}
}

func TestTokensFromMapMapsOAuthTokenFields(t *testing.T) {
	data := map[string]any{
		"token_type":               "Bearer",
		"access_token":             "access-token",
		"refresh_token":            "refresh-token",
		"id_token":                 "id-token",
		"scope":                    "email profile",
		"expires_in":               float64(60),
		"refresh_token_expires_in": float64(120),
		"provider_id":              "provider-specific",
	}

	tokens := TokensFromMap(data)
	if tokens.TokenType != "Bearer" || tokens.AccessToken != "access-token" || tokens.RefreshToken != "refresh-token" || tokens.IDToken != "id-token" {
		t.Fatalf("tokens=%+v", tokens)
	}
	if len(tokens.Scopes) != 2 || tokens.Scopes[0] != "email" || tokens.Scopes[1] != "profile" {
		t.Fatalf("scopes=%v", tokens.Scopes)
	}
	assertExpiryWithin(t, tokens.AccessTokenExpiresAt, time.Minute)
	assertExpiryWithin(t, tokens.RefreshTokenExpiresAt, 2*time.Minute)
	if tokens.Raw["provider_id"] != "provider-specific" {
		t.Fatalf("raw=%v", tokens.Raw)
	}
	data["provider_id"] = "changed"
	if tokens.Raw["provider_id"] != "provider-specific" {
		t.Fatalf("raw mutated with input map: %v", tokens.Raw)
	}
}

func TestTokensFromMapMapsNonFloatExpiryFields(t *testing.T) {
	tokens := TokensFromMap(map[string]any{
		"expires_in":               60,
		"refresh_token_expires_in": json.Number("120"),
	})

	assertExpiryWithin(t, tokens.AccessTokenExpiresAt, time.Minute)
	assertExpiryWithin(t, tokens.RefreshTokenExpiresAt, 2*time.Minute)
}

func TestTokensFromMapMapsArrayScopes(t *testing.T) {
	tokens := TokensFromMap(map[string]any{
		"scope": []any{"email", "profile"},
	})

	if len(tokens.Scopes) != 2 || tokens.Scopes[0] != "email" || tokens.Scopes[1] != "profile" {
		t.Fatalf("scopes=%v", tokens.Scopes)
	}
}

func TestBuildAuthURLReplacesDuplicateQueryParams(t *testing.T) {
	params := url.Values{}
	params.Set("client_id", "new-client")
	params.Set("state", "state-token")

	authURL := BuildAuthURL("https://auth.example.com/oauth?client_id=old-client&tenant=workspace", params)
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if query.Get("client_id") != "new-client" || query.Get("state") != "state-token" || query.Get("tenant") != "workspace" {
		t.Fatalf("query=%s", query.Encode())
	}
	if values := query["client_id"]; len(values) != 1 {
		t.Fatalf("client_id values=%v", values)
	}
}

func assertExpiryWithin(t *testing.T, expiry *time.Time, expected time.Duration) {
	t.Helper()
	if expiry == nil {
		t.Fatal("expiry is nil")
	}
	remaining := time.Until(*expiry)
	if remaining < expected-time.Second || remaining > expected+time.Second {
		t.Fatalf("remaining=%s expected=%s", remaining, expected)
	}
}
