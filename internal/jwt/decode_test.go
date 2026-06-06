package jwt

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestDecodePayload(t *testing.T) {
	claims := map[string]any{"sub": "u1", "email": "a@b.com"}
	raw, _ := json.Marshal(claims)
	token := "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
	got, err := DecodePayload(token)
	if err != nil || got["sub"] != "u1" {
		t.Fatalf("got=%v err=%v", got, err)
	}
}
