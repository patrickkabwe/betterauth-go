package cookie_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/patrickkabwe/betterauth-go/internal/cookie"
)

func TestSignAndVerify(t *testing.T) {
	secret := "my-secret-key"
	token := "abc123XYZ"

	signed := cookie.SignCookie(token, secret)
	value, ok := cookie.VerifySignedCookie(signed, secret)
	if !ok {
		t.Fatal("verification failed")
	}
	if value != token {
		t.Fatalf("value = %q, want %q", value, token)
	}
}

func TestVerifyRejectsTampered(t *testing.T) {
	secret := "my-secret-key"
	signed := cookie.SignCookie("token", secret)

	tampered := signed[:len(signed)-2] + "XX"
	if _, ok := cookie.VerifySignedCookie(tampered, secret); ok {
		t.Fatal("expected verification to fail")
	}
}

func TestCookieNames(t *testing.T) {
	cfg := cookie.DefaultConfig()
	if cfg.SessionTokenName() != "better-auth.session_token" {
		t.Fatalf("name = %q", cfg.SessionTokenName())
	}

	secure := cookie.Config{Prefix: "better-auth", Secure: true}
	if secure.SessionTokenName() != "__Secure-better-auth.session_token" {
		t.Fatalf("secure name = %q", secure.SessionTokenName())
	}
}

func TestSetAndGetSessionCookie(t *testing.T) {
	cfg := cookie.DefaultConfig()
	secret := "secret"
	rr := httptest.NewRecorder()
	cookie.SetSessionCookie(rr, cfg, secret, "session-token", 3600, false)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}

	token, ok := cookie.GetSessionToken(req, cfg, secret)
	if !ok || token != "session-token" {
		t.Fatalf("token=%q ok=%v", token, ok)
	}
}

func TestDeleteSessionCookies(t *testing.T) {
	cfg := cookie.DefaultConfig()
	rr := httptest.NewRecorder()
	cookie.SetSessionCookie(rr, cfg, "secret", "tok", 3600, true)
	cookie.DeleteSessionCookies(rr, cfg)
	if len(rr.Result().Cookies()) == 0 {
		t.Fatal("expected expired cookies")
	}
}

func TestVerifyURIEncodedCookie(t *testing.T) {
	secret := "secret"
	signed := cookie.SignCookie("tok", secret)
	encoded := "%" + signed[:3] // partial encoding triggers PathUnescape branch
	_, ok := cookie.VerifySignedCookie(encoded, secret)
	_ = ok // may fail; exercises decode path
	_, ok2 := cookie.VerifySignedCookie(signed, secret)
	if !ok2 {
		t.Fatal("plain signed cookie should verify")
	}
}

func TestSecureDontRememberName(t *testing.T) {
	cfg := cookie.Config{Prefix: "better-auth", Secure: true}
	if cfg.DontRememberName() != "__Secure-better-auth.dont_remember" {
		t.Fatal("secure dont remember name")
	}
}

func TestIsDontRemember(t *testing.T) {
	cfg := cookie.DefaultConfig()
	secret := "secret"
	rr := httptest.NewRecorder()
	cookie.SetSessionCookie(rr, cfg, secret, "tok", 3600, true)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	if !cookie.IsDontRemember(req, cfg, secret) {
		t.Fatal("expected dont remember")
	}
}

func TestSetSessionDataCookie(t *testing.T) {
	cfg := cookie.DefaultConfig()
	rr := httptest.NewRecorder()
	cookie.SetSessionDataCookie(rr, cfg, "cached-value", 300)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	c, err := req.Cookie(cfg.SessionDataName())
	if err != nil || c.Value != "cached-value" {
		t.Fatal("session data cookie not set")
	}
}

func TestDontRememberCookieName(t *testing.T) {
	cfg := cookie.DefaultConfig()
	if cfg.DontRememberName() != "better-auth.dont_remember" {
		t.Fatal("dont remember name")
	}
}
