package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

var ErrInvalidCiphertext = errors.New("invalid ciphertext")

// SymmetricEncrypt encrypts data with a key derived from secret.
func SymmetricEncrypt(secret string, data string) (string, error) {
	key := sha256.Sum256([]byte(secret))
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return "", err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, nonce, []byte(data), nil)
	payload := make([]byte, 0, len(nonce)+len(sealed))
	payload = append(payload, nonce...)
	payload = append(payload, sealed...)
	return hex.EncodeToString(payload), nil
}

// SymmetricDecrypt decrypts data encrypted by SymmetricEncrypt.
func SymmetricDecrypt(secret string, data string) (string, error) {
	payload, err := hex.DecodeString(data)
	if err != nil {
		return "", err
	}
	if len(payload) <= chacha20poly1305.NonceSizeX {
		return "", ErrInvalidCiphertext
	}
	key := sha256.Sum256([]byte(secret))
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return "", err
	}
	nonce := payload[:chacha20poly1305.NonceSizeX]
	ciphertext := payload[chacha20poly1305.NonceSizeX:]
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// SymmetricDecryptAny decrypts data using the first secret that succeeds.
func SymmetricDecryptAny(secrets []string, data string) (string, error) {
	var lastErr error
	for _, secret := range secrets {
		plain, err := SymmetricDecrypt(secret, data)
		if err == nil {
			return plain, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("%w: no secrets configured", ErrInvalidCiphertext)
}
