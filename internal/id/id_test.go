package id_test

import (
	"testing"

	"github.com/patrickkabwe/betterauth-go/internal/id"
)

func TestGenerate(t *testing.T) {
	s, err := id.Generate(32)
	if err != nil || len(s) != 32 {
		t.Fatalf("id=%q err=%v", s, err)
	}
	s2, _ := id.Generate(32)
	if s == s2 {
		t.Fatal("ids should differ")
	}
}

func TestGenerateDefaultSize(t *testing.T) {
	s, err := id.Generate(0)
	if err != nil || len(s) != 32 {
		t.Fatal("default size")
	}
}
