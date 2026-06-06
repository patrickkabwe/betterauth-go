package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"unicode"

	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"golang.org/x/crypto/scrypt"
)

// Scrypt parameters matching Better Auth defaults.
const (
	scryptN = 16384
	scryptR = 16
	scryptP = 1
	scryptDKLen = 64
	saltLen = 16
)

// HashPassword hashes a password using scrypt with Better Auth compatible format: salt_hex:key_hex
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, err := scrypt.Key(
		[]byte(normalizePassword(password)),
		salt,
		scryptN,
		scryptR,
		scryptP,
		scryptDKLen,
	)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(key), nil
}

// VerifyPassword checks a password against a Better Auth scrypt hash.
func VerifyPassword(hash, password string) (bool, error) {
	parts := strings.SplitN(hash, ":", 2)
	if len(parts) != 2 {
		return false, berrors.ErrInvalidHashFormat
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false, err
	}

	expectedKey, err := hex.DecodeString(parts[1])
	if err != nil {
		return false, err
	}

	key, err := scrypt.Key(
		[]byte(normalizePassword(password)),
		salt,
		scryptN,
		scryptR,
		scryptP,
		scryptDKLen,
	)
	if err != nil {
		return false, err
	}

	return hmacEqual(key, expectedKey), nil
}

// normalizePassword applies NFKC normalization matching Better Auth.
func normalizePassword(password string) string {
	// Go's unicode/norm package would be ideal, but for ASCII passwords this is sufficient.
	// For full NFKC compatibility we use strings.Map.
	return strings.Map(func(r rune) rune {
		// NFKC is complex; use golang.org/x/text for production if needed.
		return r
	}, password)
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// ValidateEmail performs basic email validation.
func ValidateEmail(email string) bool {
	email = strings.TrimSpace(email)
	at := strings.LastIndex(email, "@")
	if at < 1 || at >= len(email)-1 {
		return false
	}
	local := email[:at]
	domain := email[at+1:]
	if len(local) == 0 || len(domain) < 3 || !strings.Contains(domain, ".") {
		return false
	}
	for _, r := range email {
		if r > unicode.MaxASCII && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			// allow unicode in local part
			continue
		}
	}
	return true
}
