package plugins_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/plugins"
)

func registerClientWithSecret(t *testing.T, a *auth.Auth) (string, string) {
	t.Helper()
	w := post(t, a, "/oauth2/register", `{"client_name":"Test","redirect_uris":["https://app.example/cb"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", w.Code, w.Body.String())
	}
	var reg struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil || reg.ClientID == "" || reg.ClientSecret == "" {
		t.Fatalf("register response: %s", w.Body.String())
	}
	return reg.ClientID, reg.ClientSecret
}

func introspect(t *testing.T, a *auth.Auth, token, clientID, secret string) map[string]any {
	t.Helper()
	body := `{"token":"` + token + `","client_id":"` + clientID + `","client_secret":"` + secret + `"}`
	w := post(t, a, "/oauth2/introspect", body)
	if w.Code != http.StatusOK {
		t.Fatalf("introspect status=%d body=%s", w.Code, w.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func TestOIDCIntrospectAndRevoke(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "introspect@example.com")
	user := currentPluginUser(t, a, cookies)
	clientID, secret := registerClientWithSecret(t, a)

	code := authorizeCode(t, a, clientID, "openid offline_access", cookies)
	tr := exchangeCode(t, a, code)
	if tr.AccessToken == "" || tr.RefreshToken == "" {
		t.Fatalf("expected access+refresh tokens: %+v", tr)
	}

	// Introspect the access token -> active with metadata.
	active := introspect(t, a, tr.AccessToken, clientID, secret)
	if active["active"] != true || active["client_id"] != clientID || active["sub"] != user.ID || active["token_type"] != "Bearer" {
		t.Fatalf("access introspection wrong: %+v", active)
	}

	// Unknown token -> inactive.
	if r := introspect(t, a, "bogus", clientID, secret); r["active"] != false {
		t.Fatalf("bogus token should be inactive: %+v", r)
	}

	// Wrong client auth -> 401.
	if w := post(t, a, "/oauth2/introspect", `{"token":"`+tr.AccessToken+`","client_id":"`+clientID+`","client_secret":"nope"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad client secret should 401, got %d", w.Code)
	}

	// A different (non-issuer, unlinked) client cannot see the token.
	otherID, otherSecret := registerClientWithSecret(t, a)
	if r := introspect(t, a, tr.AccessToken, otherID, otherSecret); r["active"] != false {
		t.Fatalf("non-issuer client should see inactive: %+v", r)
	}

	// Revoke the access token -> subsequently inactive.
	if w := post(t, a, "/oauth2/revoke", `{"token":"`+tr.AccessToken+`","client_id":"`+clientID+`","client_secret":"`+secret+`"}`); w.Code != http.StatusOK {
		t.Fatalf("revoke access status=%d body=%s", w.Code, w.Body.String())
	}
	if r := introspect(t, a, tr.AccessToken, clientID, secret); r["active"] != false {
		t.Fatalf("revoked access token should be inactive: %+v", r)
	}

	// Revoke the refresh token -> family gone, refresh grant fails.
	if w := post(t, a, "/oauth2/revoke", `{"token":"`+tr.RefreshToken+`","token_type_hint":"refresh_token","client_id":"`+clientID+`","client_secret":"`+secret+`"}`); w.Code != http.StatusOK {
		t.Fatalf("revoke refresh status=%d body=%s", w.Code, w.Body.String())
	}
	rw := post(t, a, "/oauth2/token", `{"grant_type":"refresh_token","client_id":"`+clientID+`","refresh_token":"`+tr.RefreshToken+`"}`)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("refresh after revoke should fail, got %d %s", rw.Code, rw.Body.String())
	}
}
