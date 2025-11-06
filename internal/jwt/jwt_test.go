package jwt_test

import (
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/internal/jwt"
)

func TestSignAndVerify(t *testing.T) {
	token, err := jwt.SignHS256("secret", map[string]any{"email": "a@b.com"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := jwt.VerifyHS256(token, "secret")
	if err != nil {
		t.Fatal(err)
	}
	email, err := jwt.EmailClaim(payload)
	if err != nil || email != "a@b.com" {
		t.Fatalf("email = %q err=%v", email, err)
	}
}

func TestExpired(t *testing.T) {
	token, _ := jwt.SignHS256("secret", map[string]any{"email": "a@b.com"}, -time.Hour)
	if _, err := jwt.VerifyHS256(token, "secret"); err != jwt.ErrExpired {
		t.Fatalf("err = %v", err)
	}
}

func TestMalformedToken(t *testing.T) {
	if _, err := jwt.VerifyHS256("not.three.parts", "secret"); err != jwt.ErrInvalid {
		t.Fatalf("err = %v", err)
	}
}

func TestEmailClaimMissing(t *testing.T) {
	token, _ := jwt.SignHS256("secret", map[string]any{"sub": "x"}, time.Hour)
	payload, _ := jwt.VerifyHS256(token, "secret")
	if _, err := jwt.EmailClaim(payload); err == nil {
		t.Fatal("expected missing email error")
	}
}

func TestInvalidSignature(t *testing.T) {
	token, _ := jwt.SignHS256("secret", map[string]any{"email": "a@b.com"}, time.Hour)
	if _, err := jwt.VerifyHS256(token, "wrong"); err != jwt.ErrInvalid {
		t.Fatalf("err = %v", err)
	}
}
