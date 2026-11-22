package plugins_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/types"
)

const caTokenURL = "http://localhost:8080/api/auth/oauth2/token"

// caClient holds a confidential client's private_key_jwt signing key and builds
// RFC 7523 client assertions against it.
type caClient struct {
	clientID string
	kid      string
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
}

func newCAClient(t *testing.T, clientID string) caClient {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return caClient{clientID: clientID, kid: "ca-key-1", priv: priv, pub: pub}
}

// jwks renders the client's public key as an inline RFC 7517 JWK Set (OKP).
func (c caClient) jwks() string {
	set := map[string]any{"keys": []map[string]any{{
		"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
		"kid": c.kid, "x": base64.RawURLEncoding.EncodeToString(c.pub),
	}}}
	b, _ := json.Marshal(set)
	return string(b)
}

// assertion signs a client_assertion JWT with the client's key.
func (c caClient) assertion(t *testing.T, aud, jti string, iat, exp time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": c.clientID, "sub": c.clientID, "aud": aud,
		"jti": jti, "iat": iat.Unix(), "exp": exp.Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = c.kid
	s, err := tok.SignedString(c.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// registerPrivateKeyJWTClient inserts a confidential client configured for
// private_key_jwt with an inline JWKS, and returns its id.
func registerPrivateKeyJWTClient(t *testing.T, a *auth.Auth, cc caClient, authMethod string) {
	t.Helper()
	now := time.Now()
	skip := true
	err := extStore(t, a).CreateOAuthClient(context.Background(), &types.OAuthClient{
		ID: cc.clientID, ClientID: cc.clientID, Name: "ca-client",
		RedirectURIs:            []string{"https://app.example/cb"},
		TokenEndpointAuthMethod: authMethod,
		JWKS:                    cc.jwks(),
		SkipConsent:             &skip,
		CreatedAt:               now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
}

// tokenWithAssertion posts an authorization_code token request authenticated by
// a client_assertion.
func tokenWithAssertion(t *testing.T, a *auth.Auth, code, clientID, assertion string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]string{
		"grant_type":            "authorization_code",
		"code":                  code,
		"client_id":             clientID,
		"client_assertion":      assertion,
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
	}
	b, _ := json.Marshal(body)
	return post(t, a, "/oauth2/token", string(b))
}

func TestOIDCClientAssertionAuthCode(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "ca@example.com")
	cc := newCAClient(t, "ca-client-ok")
	registerPrivateKeyJWTClient(t, a, cc, "private_key_jwt")

	code := authorizeCode(t, a, cc.clientID, "openid email", cookies)
	now := time.Now()
	assertion := cc.assertion(t, caTokenURL, "jti-ok-1", now, now.Add(time.Minute))

	w := tokenWithAssertion(t, a, code, cc.clientID, assertion)
	if w.Code != http.StatusOK {
		t.Fatalf("token: %d %s", w.Code, w.Body.String())
	}
	var tr tokenResp
	if err := json.Unmarshal(w.Body.Bytes(), &tr); err != nil || tr.AccessToken == "" {
		t.Fatalf("token response: %s", w.Body.String())
	}
}

func TestOIDCClientAssertionReplayJTI(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "ca-replay@example.com")
	cc := newCAClient(t, "ca-client-replay")
	registerPrivateKeyJWTClient(t, a, cc, "private_key_jwt")

	now := time.Now()
	// First exchange consumes jti "dup".
	code1 := authorizeCode(t, a, cc.clientID, "openid", cookies)
	if w := tokenWithAssertion(t, a, code1, cc.clientID, cc.assertion(t, caTokenURL, "dup", now, now.Add(time.Minute))); w.Code != http.StatusOK {
		t.Fatalf("first token: %d %s", w.Code, w.Body.String())
	}
	// Second exchange with a fresh code but the same jti must be rejected.
	code2 := authorizeCode(t, a, cc.clientID, "openid", cookies)
	w := tokenWithAssertion(t, a, code2, cc.clientID, cc.assertion(t, caTokenURL, "dup", now, now.Add(time.Minute)))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "jti") {
		t.Fatalf("replayed jti should 401 with jti error, got %d %s", w.Code, w.Body.String())
	}
}

func TestOIDCClientAssertionWrongKey(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "ca-wrongkey@example.com")
	cc := newCAClient(t, "ca-client-wrongkey")
	registerPrivateKeyJWTClient(t, a, cc, "private_key_jwt")

	code := authorizeCode(t, a, cc.clientID, "openid", cookies)
	// Sign with a different key not in the client's JWKS.
	other := newCAClient(t, cc.clientID)
	other.kid = cc.kid
	now := time.Now()
	w := tokenWithAssertion(t, a, code, cc.clientID, other.assertion(t, caTokenURL, "jti-wrongkey", now, now.Add(time.Minute)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-key assertion should 401, got %d %s", w.Code, w.Body.String())
	}
}

func TestOIDCClientAssertionBadAudience(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "ca-aud@example.com")
	cc := newCAClient(t, "ca-client-aud")
	registerPrivateKeyJWTClient(t, a, cc, "private_key_jwt")

	code := authorizeCode(t, a, cc.clientID, "openid", cookies)
	now := time.Now()
	w := tokenWithAssertion(t, a, code, cc.clientID, cc.assertion(t, "https://evil.example/token", "jti-aud", now, now.Add(time.Minute)))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "aud") {
		t.Fatalf("bad aud should 401 with aud error, got %d %s", w.Code, w.Body.String())
	}
}

func TestOIDCClientAssertionExpired(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "ca-exp@example.com")
	cc := newCAClient(t, "ca-client-exp")
	registerPrivateKeyJWTClient(t, a, cc, "private_key_jwt")

	code := authorizeCode(t, a, cc.clientID, "openid", cookies)
	past := time.Now().Add(-10 * time.Minute)
	w := tokenWithAssertion(t, a, code, cc.clientID, cc.assertion(t, caTokenURL, "jti-exp", past, past.Add(time.Minute)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expired assertion should 401, got %d %s", w.Code, w.Body.String())
	}
}

func TestOIDCClientAssertionWrongAuthMethod(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "ca-method@example.com")
	cc := newCAClient(t, "ca-client-method")
	// Registered with a secret method, not private_key_jwt.
	registerPrivateKeyJWTClient(t, a, cc, "client_secret_post")

	code := authorizeCode(t, a, cc.clientID, "openid", cookies)
	now := time.Now()
	w := tokenWithAssertion(t, a, code, cc.clientID, cc.assertion(t, caTokenURL, "jti-method", now, now.Add(time.Minute)))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "private_key_jwt") {
		t.Fatalf("wrong auth method should 401, got %d %s", w.Code, w.Body.String())
	}
}

func TestOIDCClientAssertionClientIDMismatch(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "ca-mismatch@example.com")
	cc := newCAClient(t, "ca-client-mismatch")
	registerPrivateKeyJWTClient(t, a, cc, "private_key_jwt")

	code := authorizeCode(t, a, cc.clientID, "openid", cookies)
	now := time.Now()
	assertion := cc.assertion(t, caTokenURL, "jti-mismatch", now, now.Add(time.Minute))
	// Body client_id disagrees with the assertion's sub/iss.
	w := tokenWithAssertion(t, a, code, "some-other-client", assertion)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "does not match") {
		t.Fatalf("client_id mismatch should 401, got %d %s", w.Code, w.Body.String())
	}
}
