package provider

import (
	"context"
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
