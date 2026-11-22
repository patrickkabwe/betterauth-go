// Package oauthcrypto provides the signing and proof-of-possession primitives
// for the OAuth provider: EdDSA-signed RFC 9068 JWT access tokens and RFC 9449
// DPoP proof verification with RFC 7638 JWK thumbprints. It deliberately uses
// only the standard library plus golang-jwt (no JWK dependency); JWK parsing
// and thumbprints are computed by hand for the OKP (Ed25519) and EC (P-256)
// key types DPoP clients commonly use.
package oauthcrypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// b64 is base64url without padding, as used throughout JOSE.
var b64 = base64.RawURLEncoding

// SigningKey is the EdDSA key the provider uses to sign JWT access tokens.
type SigningKey struct {
	Kid     string
	Private ed25519.PrivateKey
	PublicX string // base64url of the 32-byte public key (the JWK `x`)
}

// NewSigningKey generates a fresh Ed25519 signing key and returns it together
// with the base64-encoded 32-byte seed to persist (reload with SigningKeyFromSeed).
func NewSigningKey(kid string) (SigningKey, string, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return SigningKey{}, "", err
	}
	seed := b64.EncodeToString(priv.Seed())
	return SigningKey{Kid: kid, Private: priv, PublicX: b64.EncodeToString(pub)}, seed, nil
}

// SigningKeyFromSeed reconstructs a signing key from a persisted base64 seed.
func SigningKeyFromSeed(kid, seedB64 string) (SigningKey, error) {
	seed, err := b64.DecodeString(seedB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		return SigningKey{}, errors.New("oauthcrypto: invalid signing-key seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return SigningKey{Kid: kid, Private: priv, PublicX: b64.EncodeToString(pub)}, nil
}

// Public returns the Ed25519 public key.
func (k SigningKey) Public() ed25519.PublicKey {
	return k.Private.Public().(ed25519.PublicKey)
}

// SignAccessToken signs the claims as an EdDSA JWT with the RFC 9068 `at+jwt`
// type header and the key id.
func (k SigningKey) SignAccessToken(claims jwt.MapClaims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["typ"] = "at+jwt"
	tok.Header["kid"] = k.Kid
	return tok.SignedString(k.Private)
}

// ParseAccessToken verifies an EdDSA access token against the public key and
// returns its claims. It enforces the signature and standard time claims.
func ParseAccessToken(token string, pub ed25519.PublicKey) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != "EdDSA" {
			return nil, fmt.Errorf("oauthcrypto: unexpected alg %q", t.Method.Alg())
		}
		return pub, nil
	}, jwt.WithValidMethods([]string{"EdDSA"}))
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// LooksLikeJWT reports whether a token is a compact JWS (three dot-separated,
// non-empty segments) — used to branch opaque vs JWT access tokens.
func LooksLikeJWT(token string) bool {
	dots := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			dots++
		}
	}
	if dots != 2 {
		return false
	}
	for _, seg := range splitDots(token) {
		if seg == "" {
			return false
		}
	}
	return true
}

func splitDots(s string) [3]string {
	var out [3]string
	idx := 0
	start := 0
	for i := 0; i < len(s) && idx < 3; i++ {
		if s[i] == '.' {
			out[idx] = s[start:i]
			idx++
			start = i + 1
		}
	}
	if idx < 3 {
		out[idx] = s[start:]
	}
	return out
}

// AccessTokenHash returns the DPoP `ath` claim value for a token:
// base64url(SHA-256(token)).
func AccessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return b64.EncodeToString(sum[:])
}

// DPoPResult is the outcome of verifying a DPoP proof.
type DPoPResult struct {
	JKT      string // RFC 7638 thumbprint of the proof's key — the cnf value
	JTI      string
	IssuedAt time.Time
	ATH      string // the proof's `ath` claim, if present
}

// VerifyDPoPProof parses and verifies a DPoP proof JWS (RFC 9449 §4.3): it
// confirms the `dpop+jwt` type, reconstructs the embedded JWK public key,
// verifies the signature, and checks `htm`/`htu` and `iat` freshness. It
// returns the key thumbprint (jkt), the jti (for replay checks by the caller)
// and the `ath` claim. The caller enforces jti replay and the ath match.
func VerifyDPoPProof(proof, htm, htu string, now time.Time, maxAge time.Duration) (DPoPResult, error) {
	var jwkRaw map[string]any
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(proof, claims, func(t *jwt.Token) (any, error) {
		if typ, _ := t.Header["typ"].(string); typ != "dpop+jwt" {
			return nil, errors.New("oauthcrypto: dpop proof missing dpop+jwt typ")
		}
		raw, ok := t.Header["jwk"].(map[string]any)
		if !ok {
			return nil, errors.New("oauthcrypto: dpop proof missing jwk header")
		}
		jwkRaw = raw
		return publicKeyFromJWK(raw)
	}, jwt.WithValidMethods([]string{"EdDSA", "ES256"}), jwt.WithoutClaimsValidation())
	if err != nil {
		return DPoPResult{}, err
	}
	if m, _ := claims["htm"].(string); m != htm {
		return DPoPResult{}, fmt.Errorf("oauthcrypto: dpop htm mismatch (got %q want %q)", m, htm)
	}
	if u, _ := claims["htu"].(string); u != htu {
		return DPoPResult{}, fmt.Errorf("oauthcrypto: dpop htu mismatch (got %q want %q)", u, htu)
	}
	iatF, ok := claims["iat"].(float64)
	if !ok {
		return DPoPResult{}, errors.New("oauthcrypto: dpop proof missing iat")
	}
	iat := time.Unix(int64(iatF), 0)
	if iat.Before(now.Add(-maxAge)) || iat.After(now.Add(30*time.Second)) {
		return DPoPResult{}, errors.New("oauthcrypto: dpop proof iat outside the acceptance window")
	}
	jkt, err := JWKThumbprint(jwkRaw)
	if err != nil {
		return DPoPResult{}, err
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return DPoPResult{}, errors.New("oauthcrypto: dpop proof missing jti")
	}
	ath, _ := claims["ath"].(string)
	return DPoPResult{JKT: jkt, JTI: jti, IssuedAt: iat, ATH: ath}, nil
}

// publicKeyFromJWK reconstructs a public key from a DPoP proof's embedded JWK.
func publicKeyFromJWK(jwk map[string]any) (any, error) {
	kty, _ := jwk["kty"].(string)
	switch kty {
	case "OKP":
		if crv, _ := jwk["crv"].(string); crv != "Ed25519" {
			return nil, fmt.Errorf("oauthcrypto: unsupported OKP curve %v", jwk["crv"])
		}
		x, err := b64.DecodeString(stringField(jwk, "x"))
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("oauthcrypto: invalid OKP x")
		}
		return ed25519.PublicKey(x), nil
	case "EC":
		if crv, _ := jwk["crv"].(string); crv != "P-256" {
			return nil, fmt.Errorf("oauthcrypto: unsupported EC curve %v", jwk["crv"])
		}
		x, errX := b64.DecodeString(stringField(jwk, "x"))
		y, errY := b64.DecodeString(stringField(jwk, "y"))
		if errX != nil || errY != nil {
			return nil, errors.New("oauthcrypto: invalid EC coordinates")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("oauthcrypto: EC point not on P-256")
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("oauthcrypto: unsupported jwk kty %q", kty)
	}
}

// JWKThumbprint computes the RFC 7638 thumbprint of a public JWK: SHA-256 over
// the required members in lexicographic order with no whitespace, base64url.
func JWKThumbprint(jwk map[string]any) (string, error) {
	var canonical string
	switch jwk["kty"] {
	case "OKP":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, stringField(jwk, "crv"), stringField(jwk, "x"))
	case "EC":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, stringField(jwk, "crv"), stringField(jwk, "x"), stringField(jwk, "y"))
	default:
		return "", fmt.Errorf("oauthcrypto: cannot thumbprint kty %v", jwk["kty"])
	}
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:]), nil
}

func stringField(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}
