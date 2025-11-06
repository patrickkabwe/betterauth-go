package auth_test

import (
	"testing"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/store/memory"
)

func TestNewValidation(t *testing.T) {
	_, err := auth.New(auth.Config{})
	if err == nil {
		t.Fatal("expected secret error")
	}
	_, err = auth.New(auth.Config{Secret: "x"})
	if err == nil {
		t.Fatal("expected store error")
	}
}

func TestNewSuccess(t *testing.T) {
	a, err := auth.New(auth.Config{Secret: "secret-key-long-enough", Store: memory.New()})
	if err != nil || a == nil {
		t.Fatal(err)
	}
}
