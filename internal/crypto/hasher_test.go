package crypto_test

import (
	"testing"

	"github.com/patrickkabwe/betterauth-go/internal/crypto"
)

func TestScryptHasher(t *testing.T) {
	h := crypto.ScryptHasher{}
	hash, err := h.Hash("password123")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := h.Verify(hash, "password123")
	if err != nil || !ok {
		t.Fatal("verify failed")
	}
}

func TestFuncHasher(t *testing.T) {
	h := crypto.FuncHasher{
		HashFn:   func(p string) (string, error) { return "x:" + p, nil },
		VerifyFn: func(hash, p string) (bool, error) { return hash == "x:"+p, nil },
	}
	hash, _ := h.Hash("abc")
	ok, _ := h.Verify(hash, "abc")
	if !ok {
		t.Fatal("func hasher failed")
	}
}
