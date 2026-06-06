package auth

import "testing"

func TestMatchPath(t *testing.T) {
	vars, ok := matchPath("/reset-password/{token}", "/reset-password/abc123")
	if !ok || vars["token"] != "abc123" {
		t.Fatalf("vars=%v ok=%v", vars, ok)
	}
	if _, ok := matchPath("/ok", "/missing"); ok {
		t.Fatal("should not match")
	}
}

func TestNormalizePath(t *testing.T) {
	if normalizePath("/foo/") != "/foo" {
		t.Fatal("trim failed")
	}
	if normalizePath("") != "/" {
		t.Fatal("empty path")
	}
}
