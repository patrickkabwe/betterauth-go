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
	"github.com/patrickkabwe/betterauth-go/internal/oauthcrypto"
	"github.com/patrickkabwe/betterauth-go/plugins"
)

func TestOIDCJWTAccessTokens(t *testing.T) {
	a := newTestAuth(t,
		plugins.OIDCProvider(plugins.OIDCProviderOptions{JWTAccessTokens: true}),
		plugins.JWT(plugins.JWTOptions{}),
	)
	cookies := signUpPluginUser(t, a, "jwt-at@example.com")
	clientID := registerOAuthClient(t, a)

	code := authorizeCode(t, a, clientID, "openid email", cookies)
	tr := exchangeCode(t, a, code)
	if !oauthcrypto.LooksLikeJWT(tr.AccessToken) {
		t.Fatalf("expected a JWT access token, got %q", tr.AccessToken)
	}
	// Stateless: not stored in oauthAccessToken.
	if _, err := extStore(t, a).FindOAuthAccessToken(context.Background(), tr.AccessToken); err == nil {
		t.Fatal("JWT access tokens must not be stored")
	}
	// userinfo verifies the JWT.
	if w := userinfo(t, a, tr.AccessToken); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "jwt-at@example.com") {
		t.Fatalf("userinfo: %d %s", w.Code, w.Body.String())
	}
	// JWKS endpoint exposes the OKP signing key (created at token issuance).
	if w := get(t, a, "/jwks"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "OKP") || !strings.Contains(w.Body.String(), "EdDSA") {
		t.Fatalf("jwks should expose the EdDSA key: %d %s", w.Code, w.Body.String())
	}
}

// dpopClient holds a client's DPoP key and builds proofs.
type dpopClient struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newDPoPClient(t *testing.T) dpopClient {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return dpopClient{pub: pub, priv: priv}
}

func (d dpopClient) proof(t *testing.T, htm, htu, ath, jti string) string {
	t.Helper()
	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(d.pub)}
	claims := jwt.MapClaims{"htm": htm, "htu": htu, "iat": time.Now().Unix(), "jti": jti}
	if ath != "" {
		claims["ath"] = ath
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = jwk
	s, err := tok.SignedString(d.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func doReq(t *testing.T, a *auth.Auth, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}

func TestOIDCDPoPBinding(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{JWTAccessTokens: true}))
	cookies := signUpPluginUser(t, a, "dpop@example.com")
	clientID := registerOAuthClient(t, a)
	dc := newDPoPClient(t)
	const tokenURL = "http://localhost:8080/api/auth/oauth2/token"
	const userinfoURL = "http://localhost:8080/api/auth/oauth2/userinfo"

	code := authorizeCode(t, a, clientID, "openid email", cookies)

	// Token request with a DPoP proof -> DPoP-bound token.
	tw := doReq(t, a, http.MethodPost, "/oauth2/token",
		`{"grant_type":"authorization_code","code":"`+code+`"}`,
		map[string]string{"DPoP": dc.proof(t, "POST", tokenURL, "", "jti-token")})
	if tw.Code != http.StatusOK {
		t.Fatalf("token: %d %s", tw.Code, tw.Body.String())
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	_ = json.Unmarshal(tw.Body.Bytes(), &tr)
	if tr.TokenType != "DPoP" || tr.AccessToken == "" {
		t.Fatalf("expected DPoP token_type: %+v", tr)
	}

	ath := oauthcrypto.AccessTokenHash(tr.AccessToken)

	// userinfo WITHOUT a proof -> 401.
	if w := doReq(t, a, http.MethodGet, "/oauth2/userinfo", "", map[string]string{"Authorization": "DPoP " + tr.AccessToken}); w.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo without proof should 401, got %d", w.Code)
	}

	// userinfo WITH a valid matching proof -> 200.
	ok := doReq(t, a, http.MethodGet, "/oauth2/userinfo", "", map[string]string{
		"Authorization": "DPoP " + tr.AccessToken,
		"DPoP":          dc.proof(t, "GET", userinfoURL, ath, "jti-ui-1"),
	})
	if ok.Code != http.StatusOK || !strings.Contains(ok.Body.String(), "dpop@example.com") {
		t.Fatalf("userinfo with proof: %d %s", ok.Code, ok.Body.String())
	}

	// A proof from a DIFFERENT key (wrong jkt) -> 401.
	other := newDPoPClient(t)
	if w := doReq(t, a, http.MethodGet, "/oauth2/userinfo", "", map[string]string{
		"Authorization": "DPoP " + tr.AccessToken,
		"DPoP":          other.proof(t, "GET", userinfoURL, ath, "jti-ui-2"),
	}); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-key proof should 401, got %d", w.Code)
	}

	// Replaying a jti already used -> 401.
	if w := doReq(t, a, http.MethodGet, "/oauth2/userinfo", "", map[string]string{
		"Authorization": "DPoP " + tr.AccessToken,
		"DPoP":          dc.proof(t, "GET", userinfoURL, ath, "jti-ui-1"),
	}); w.Code != http.StatusUnauthorized {
		t.Fatalf("replayed jti should 401, got %d", w.Code)
	}
}
