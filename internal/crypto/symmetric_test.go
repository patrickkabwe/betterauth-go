package crypto_test

import (
	"testing"

	"github.com/patrickkabwe/betterauth-go/internal/crypto"
)

func TestSymmetricEncryptDecrypt(t *testing.T) {
	secret := "secret-key-for-symmetric-encryption"
	first, err := crypto.SymmetricEncrypt(secret, "123456")
	if err != nil {
		t.Fatal(err)
	}
	second, err := crypto.SymmetricEncrypt(secret, "123456")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("ciphertext should use a random nonce")
	}
	plain, err := crypto.SymmetricDecrypt(secret, first)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "123456" {
		t.Fatalf("plain=%q", plain)
	}
}

func TestSymmetricDecryptAnyUsesRotatedSecrets(t *testing.T) {
	encrypted, err := crypto.SymmetricEncrypt("old-secret", "otp")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := crypto.SymmetricDecryptAny([]string{"new-secret", "old-secret"}, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "otp" {
		t.Fatalf("plain=%q", plain)
	}
	if _, err := crypto.SymmetricDecryptAny([]string{"wrong-secret"}, encrypted); err == nil {
		t.Fatal("expected wrong secret to fail")
	}
}
