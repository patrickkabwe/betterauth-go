package oauthcrypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSigningKeyRoundTrip(t *testing.T) {
	key, seed, err := NewSigningKey("kid-1")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := key.SignAccessToken(jwt.MapClaims{
		"iss": "https://issuer", "sub": "u1", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !LooksLikeJWT(tok) {
		t.Fatalf("signed token should look like a JWT: %q", tok)
	}
	claims, err := ParseAccessToken(tok, key.Public())
	if err != nil || claims["sub"] != "u1" {
		t.Fatalf("parse failed: %+v err=%v", claims, err)
	}

	// Reload from the seed -> same public key, still verifies.
	reloaded, err := SigningKeyFromSeed("kid-1", seed)
	if err != nil || reloaded.PublicX != key.PublicX {
		t.Fatalf("reload mismatch: %q vs %q err=%v", reloaded.PublicX, key.PublicX, err)
	}
	if _, err := ParseAccessToken(tok, reloaded.Public()); err != nil {
		t.Fatalf("reloaded key cannot verify: %v", err)
	}

	// Tampered token fails.
	if _, err := ParseAccessToken(tok+"x", key.Public()); err == nil {
		t.Fatal("tampered token should not verify")
	}
}

func TestJWKThumbprintKnownAnswer(t *testing.T) {
	// RFC 8037 Appendix A.3.
	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
	got, err := JWKThumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	if want := "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"; got != want {
		t.Fatalf("thumbprint = %q, want %q", got, want)
	}
}

// makeDPoPProof builds an Ed25519 DPoP proof and returns it with its jkt.
func makeDPoPProof(t *testing.T, htm, htu, ath string, iat time.Time) (string, string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
	claims := jwt.MapClaims{"htm": htm, "htu": htu, "iat": iat.Unix(), "jti": "jti-" + ath + htm}
	if ath != "" {
		claims["ath"] = ath
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = jwk
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	jkt, _ := JWKThumbprint(jwk)
	return signed, jkt, pub
}

func TestVerifyDPoPProof(t *testing.T) {
	now := time.Now()
	htu := "https://issuer/oauth2/token"

	proof, jkt, _ := makeDPoPProof(t, "POST", htu, "", now)
	res, err := VerifyDPoPProof(proof, "POST", htu, now, time.Minute)
	if err != nil || res.JKT != jkt || res.JTI == "" {
		t.Fatalf("valid proof should verify: %+v err=%v", res, err)
	}

	// Wrong method.
	if _, err := VerifyDPoPProof(proof, "GET", htu, now, time.Minute); err == nil {
		t.Fatal("htm mismatch should fail")
	}
	// Wrong URL.
	if _, err := VerifyDPoPProof(proof, "POST", htu+"/x", now, time.Minute); err == nil {
		t.Fatal("htu mismatch should fail")
	}
	// Stale iat.
	old, _, _ := makeDPoPProof(t, "POST", htu, "", now.Add(-10*time.Minute))
	if _, err := VerifyDPoPProof(old, "POST", htu, now, time.Minute); err == nil {
		t.Fatal("stale iat should fail")
	}
	// Tampered proof.
	if _, err := VerifyDPoPProof(proof+"x", "POST", htu, now, time.Minute); err == nil {
		t.Fatal("tampered proof should fail")
	}

	// ath is surfaced for the caller to match against the access token.
	ath := AccessTokenHash("the-access-token")
	withAth, _, _ := makeDPoPProof(t, "GET", "https://issuer/oauth2/userinfo", ath, now)
	r2, err := VerifyDPoPProof(withAth, "GET", "https://issuer/oauth2/userinfo", now, time.Minute)
	if err != nil || r2.ATH != ath {
		t.Fatalf("ath should round-trip: %+v err=%v", r2, err)
	}
}
