package provider

import "testing"

func TestTokensFromMapPreservesRawTokenResponse(t *testing.T) {
	data := map[string]any{
		"access_token": "access-token",
		"scope":        "email profile",
		"provider_id":  "provider-specific",
	}

	tokens := TokensFromMap(data)
	if tokens.Raw["provider_id"] != "provider-specific" {
		t.Fatalf("raw=%v", tokens.Raw)
	}
	data["provider_id"] = "changed"
	if tokens.Raw["provider_id"] != "provider-specific" {
		t.Fatalf("raw mutated with input map: %v", tokens.Raw)
	}
}
