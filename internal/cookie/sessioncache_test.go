package cookie_test

import (
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/internal/cookie"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestSessionCacheRoundTrip(t *testing.T) {
	secret := "test-secret"
	now := time.Now()
	data := cookie.CachedSessionData{
		Session: types.Session{
			ID: "s1", Token: "tok", UserID: "u1",
			ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
		},
		User: types.User{
			ID: "u1", Name: "Test", Email: "t@example.com",
			CreatedAt: now, UpdatedAt: now,
		},
		UpdatedAt: now.UnixMilli(),
		Version:   "1",
	}

	encoded, err := cookie.EncodeSessionCache(secret, data, 300)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := cookie.DecodeSessionCache(encoded, secret, "1")
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Session.Token != "tok" || decoded.User.Email != "t@example.com" {
		t.Fatal("round trip mismatch")
	}
}

func TestSessionCacheRejectsBadSignature(t *testing.T) {
	secret := "test-secret"
	now := time.Now()
	data := cookie.CachedSessionData{
		Session:   types.Session{ID: "s1", Token: "tok", UserID: "u1", ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now},
		User:      types.User{ID: "u1", Email: "a@b.com", CreatedAt: now, UpdatedAt: now},
		UpdatedAt: now.UnixMilli(),
		Version:   "1",
	}
	encoded, _ := cookie.EncodeSessionCache(secret, data, 300)
	if _, _, err := cookie.DecodeSessionCache(encoded, "wrong-secret", "1"); err == nil {
		t.Fatal("expected signature failure")
	}
}

func TestSessionDataCookieName(t *testing.T) {
	cfg := cookie.DefaultConfig()
	if cfg.SessionDataName() != "better-auth.session_data" {
		t.Fatal(cfg.SessionDataName())
	}
}
