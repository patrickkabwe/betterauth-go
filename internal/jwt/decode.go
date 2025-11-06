package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// DecodePayload parses a JWT payload without verifying the signature.
// Use only for tokens obtained from a trusted token endpoint.
func DecodePayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, ErrInvalid
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalid
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, ErrInvalid
	}
	return payload, nil
}
