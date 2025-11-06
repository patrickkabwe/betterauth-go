package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	berrors "github.com/patrickkabwe/betterauth-go/errors"
)

// ErrExpired indicates an expired JWT.
var ErrExpired = berrors.ErrTokenExpired

// ErrInvalid indicates an invalid JWT.
var ErrInvalid = berrors.ErrTokenInvalid

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// SignHS256 creates a JWT with HS256 matching Better Auth's signJWT.
func SignHS256(secret string, claims map[string]any, expiresIn time.Duration) (string, error) {
	now := time.Now()
	payload := make(map[string]any, len(claims)+2)
	for k, v := range claims {
		payload[k] = v
	}
	payload["iat"] = now.Unix()
	payload["exp"] = now.Add(expiresIn).Unix()

	h, err := json.Marshal(header{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	segments := []string{
		base64.RawURLEncoding.EncodeToString(h),
		base64.RawURLEncoding.EncodeToString(p),
	}
	signingInput := strings.Join(segments[:2], ".")
	sig := signHS256(signingInput, secret)
	segments = append(segments, base64.RawURLEncoding.EncodeToString(sig))
	return strings.Join(segments, "."), nil
}

// VerifyHS256 verifies a JWT and returns its payload.
// VerifyHS256Any verifies an HS256 token against any of the provided secrets
// (primary first, then rotated/old secrets).
func VerifyHS256Any(token string, secrets []string) (map[string]any, error) {
	var lastErr error
	for _, secret := range secrets {
		claims, err := VerifyHS256(token, secret)
		if err == nil {
			return claims, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func VerifyHS256(token, secret string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalid
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalid
	}
	expected := signHS256(signingInput, secret)
	if !hmac.Equal(sig, expected) {
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
	if exp, ok := payload["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, ErrExpired
		}
	}
	return payload, nil
}

func signHS256(input, secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(input))
	return mac.Sum(nil)
}

// EmailClaim extracts the email claim from a JWT payload.
func EmailClaim(payload map[string]any) (string, error) {
	email, ok := payload["email"].(string)
	if !ok || email == "" {
		return "", berrors.ErrMissingEmailClaim
	}
	return strings.ToLower(email), nil
}
