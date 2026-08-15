package provider

import (
	"testing"
	"time"
)

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
