package crypto_test

import (
	"testing"

	"github.com/patrickkabwe/betterauth-go/internal/crypto"
)

func TestHashAndVerify(t *testing.T) {
	password := "mySecurePassword123!"
	hash, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := crypto.VerifyPassword(hash, password)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected valid password")
	}
}

func TestRejectWrongPassword(t *testing.T) {
	hash, err := crypto.HashPassword("correct")
	if err != nil {
		t.Fatal(err)
	}

	valid, err := crypto.VerifyPassword(hash, "wrong")
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected invalid password")
	}
}

func TestValidateEmail(t *testing.T) {
	if !crypto.ValidateEmail("user@example.com") {
		t.Fatal("valid email rejected")
	}
	if crypto.ValidateEmail("bad") || crypto.ValidateEmail("@example.com") || crypto.ValidateEmail("a@b") {
		t.Fatal("invalid email accepted")
	}
}

func TestInvalidHashFormat(t *testing.T) {
	valid, err := crypto.VerifyPassword("not-a-hash", "password")
	if err == nil || valid {
		t.Fatal("expected invalid hash error")
	}
	valid, err = crypto.VerifyPassword("zz:yy", "password")
	if err == nil || valid {
		t.Fatal("expected hex decode error")
	}
}

func TestHmacEqualDifferentLengths(t *testing.T) {
	hash, _ := crypto.HashPassword("test")
	valid, _ := crypto.VerifyPassword(hash[:len(hash)-2]+"00", "test")
	if valid {
		t.Fatal("tampered hash should not verify")
	}
}

func TestDifferentHashesForSamePassword(t *testing.T) {
	h1, _ := crypto.HashPassword("same")
	h2, _ := crypto.HashPassword("same")
	if h1 == h2 {
		t.Fatal("expected different hashes")
	}
}
