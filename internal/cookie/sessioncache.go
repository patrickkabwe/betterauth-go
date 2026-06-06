package cookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/types"
)

// CachedSessionData is the inner payload stored in the session_data cookie.
type CachedSessionData struct {
	Session   types.Session `json:"session"`
	User      types.User    `json:"user"`
	UpdatedAt int64         `json:"updatedAt"`
	Version   string        `json:"version"`
}

type compactPayload struct {
	Session   CachedSessionData `json:"session"`
	ExpiresAt int64             `json:"expiresAt"`
	Signature string            `json:"signature"`
}

// SessionDataName returns the session_data cookie name.
func (c Config) SessionDataName() string {
	prefix := c.Prefix
	if prefix == "" {
		prefix = "better-auth"
	}
	name := prefix + ".session_data"
	if c.Secure {
		name = "__Secure-" + name
	}
	return c.resolveName("session_data", name)
}

// EncodeSessionCache serializes session data using the compact strategy (base64url + HMAC).
func EncodeSessionCache(secret string, data CachedSessionData, maxAgeSec int) (string, error) {
	expiresAt := time.Now().Add(time.Duration(maxAgeSec) * time.Second).UnixMilli()
	signBody, err := json.Marshal(struct {
		Session   types.Session `json:"session"`
		User      types.User    `json:"user"`
		UpdatedAt int64         `json:"updatedAt"`
		Version   string        `json:"version"`
		ExpiresAt int64         `json:"expiresAt"`
	}{
		Session:   data.Session,
		User:      data.User,
		UpdatedAt: data.UpdatedAt,
		Version:   data.Version,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return "", err
	}

	payload := compactPayload{
		Session:   data,
		ExpiresAt: expiresAt,
		Signature: signHMACBase64URL(string(signBody), secret),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeSessionCacheAny verifies a session_data cookie against any of the
// provided secrets (primary first, then rotated/old secrets).
func DecodeSessionCacheAny(encoded string, secrets []string, expectedVersion string) (*CachedSessionData, int64, error) {
	var lastErr error
	for _, secret := range secrets {
		data, exp, err := DecodeSessionCache(encoded, secret, expectedVersion)
		if err == nil {
			return data, exp, nil
		}
		lastErr = err
	}
	return nil, 0, lastErr
}

// DecodeSessionCache verifies and decodes a compact session_data cookie value.
func DecodeSessionCache(encoded, secret, expectedVersion string) (*CachedSessionData, int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, 0, berrors.ErrInvalidSessionCacheEncoding
	}

	var payload compactPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, 0, berrors.ErrInvalidSessionCachePayload
	}

	signBody, err := json.Marshal(struct {
		Session   types.Session `json:"session"`
		User      types.User    `json:"user"`
		UpdatedAt int64         `json:"updatedAt"`
		Version   string        `json:"version"`
		ExpiresAt int64         `json:"expiresAt"`
	}{
		Session:   payload.Session.Session,
		User:      payload.Session.User,
		UpdatedAt: payload.Session.UpdatedAt,
		Version:   payload.Session.Version,
		ExpiresAt: payload.ExpiresAt,
	})
	if err != nil {
		return nil, 0, err
	}

	expectedSig := signHMACBase64URL(string(signBody), secret)
	if !hmac.Equal([]byte(payload.Signature), []byte(expectedSig)) {
		return nil, 0, berrors.ErrInvalidSessionCacheSig
	}

	if expectedVersion != "" && payload.Session.Version != expectedVersion {
		return nil, 0, berrors.ErrSessionCacheVersionMismatch
	}

	return &payload.Session, payload.ExpiresAt, nil
}

func signHMACBase64URL(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
