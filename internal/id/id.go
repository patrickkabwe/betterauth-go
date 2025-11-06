package id

import (
	"crypto/rand"
	"math/big"
)

const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// Generate creates a random ID matching Better Auth's generateId format.
func Generate(size int) (string, error) {
	if size <= 0 {
		size = 32
	}
	result := make([]byte, size)
	max := big.NewInt(int64(len(alphabet)))
	for i := range result {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		result[i] = alphabet[n.Int64()]
	}
	return string(result), nil
}
