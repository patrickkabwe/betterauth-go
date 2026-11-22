package plugins_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/plugins"
)

// authorizeRaw issues the authorize GET with arbitrary extra query and returns
// the recorder (no consent handling).
func authorizeRaw(t *testing.T, a *auth.Auth, clientID, scope, extra string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	path := "/oauth2/authorize?client_id=" + clientID + "&redirect_uri=" + url.QueryEscape("https://app.example/cb") + "&state=xyz&scope=" + url.QueryEscape(scope) + extra
	return getWithCookies(t, a, path, cookies)
}

func TestOIDCResourceManagement(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "res-mgmt@example.com")
	clientID := registerOAuthClient(t, a)

	// Create.
	cw := postWithCookies(t, a, "/oauth2/resource", `{"identifier":"https://api.example","name":"API","allowedScopes":["read"],"accessTokenTtl":600}`, cookies)
	if cw.Code != http.StatusOK {
		t.Fatalf("create resource: %d %s", cw.Code, cw.Body.String())
	}
	// List + get.
	if lw := getWithCookies(t, a, "/oauth2/resources", cookies); lw.Code != http.StatusOK || !strings.Contains(lw.Body.String(), "https://api.example") {
		t.Fatalf("list resources: %d %s", lw.Code, lw.Body.String())
	}
	if gw := getWithCookies(t, a, "/oauth2/resource?identifier="+url.QueryEscape("https://api.example"), cookies); gw.Code != http.StatusOK {
		t.Fatalf("get resource: %d %s", gw.Code, gw.Body.String())
	}
	// Update (disable).
	uw := postWithCookies(t, a, "/oauth2/resource/update", `{"identifier":"https://api.example","name":"API v2","disabled":true}`, cookies)
	if uw.Code != http.StatusOK || !strings.Contains(uw.Body.String(), "API v2") {
		t.Fatalf("update resource: %d %s", uw.Code, uw.Body.String())
	}

	// Link + list + unlink.
	res := extStore(t, a)
	resource, _ := res.FindOAuthResource(context.Background(), "https://api.example")
	lk := postWithCookies(t, a, "/oauth2/client-resource/link", `{"client_id":"`+clientID+`","resource_id":"`+resource.Identifier+`"}`, cookies)
	if lk.Code != http.StatusOK {
		t.Fatalf("link: %d %s", lk.Code, lk.Body.String())
	}
	if clw := getWithCookies(t, a, "/oauth2/client-resource?client_id="+clientID, cookies); clw.Code != http.StatusOK || !strings.Contains(clw.Body.String(), resource.Identifier) {
		t.Fatalf("list client-resources: %d %s", clw.Code, clw.Body.String())
	}
	if uk := postWithCookies(t, a, "/oauth2/client-resource/unlink", `{"client_id":"`+clientID+`","resource_id":"`+resource.Identifier+`"}`, cookies); uk.Code != http.StatusOK {
		t.Fatalf("unlink: %d %s", uk.Code, uk.Body.String())
	}

	// Delete.
	if dw := postWithCookies(t, a, "/oauth2/resource/delete", `{"identifier":"https://api.example"}`, cookies); dw.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", dw.Code, dw.Body.String())
	}
	if gw := getWithCookies(t, a, "/oauth2/resource?identifier="+url.QueryEscape("https://api.example"), cookies); gw.Code != http.StatusNotFound {
		t.Fatalf("resource should be gone, got %d", gw.Code)
	}
}

func TestOIDCResourceValidation(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	cookies := signUpPluginUser(t, a, "res-val@example.com")
	clientID := registerOAuthClient(t, a)
	resParam := "&resource=" + url.QueryEscape("https://api.example")

	// Unknown resource -> invalid_target (redirect carries the error).
	w := authorizeRaw(t, a, clientID, "openid read", resParam, cookies)
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "error=invalid_target") {
		t.Fatalf("unknown resource should be invalid_target: %d %s", w.Code, w.Header().Get("Location"))
	}

	// Register the resource (allowedScopes read).
	if cw := postWithCookies(t, a, "/oauth2/resource", `{"identifier":"https://api.example","name":"API","allowedScopes":["read"]}`, cookies); cw.Code != http.StatusOK {
		t.Fatalf("create resource: %s", cw.Body.String())
	}

	// Scope not allowed by the resource -> invalid_scope.
	w2 := authorizeRaw(t, a, clientID, "openid write", resParam, cookies)
	if w2.Code != http.StatusFound || !strings.Contains(w2.Header().Get("Location"), "error=invalid_scope") {
		t.Fatalf("scope mismatch should be invalid_scope: %d %s", w2.Code, w2.Header().Get("Location"))
	}

	// Valid resource + scope -> consent, grant, token carries the resource.
	w3 := authorizeRaw(t, a, clientID, "openid read", resParam, cookies)
	if w3.Code != http.StatusOK || !strings.Contains(w3.Body.String(), "consentRequired") {
		t.Fatalf("expected consentRequired: %d %s", w3.Code, w3.Body.String())
	}
	consentBody := `{"client_id":"` + clientID + `","scope":"openid read","resource":["https://api.example"],"accept":true,"redirect_uri":"https://app.example/cb","state":"xyz"}`
	cw := postWithCookies(t, a, "/oauth2/consent", consentBody, cookies)
	var cr struct {
		Redirect string `json:"redirect"`
	}
	_ = json.Unmarshal(cw.Body.Bytes(), &cr)
	tr := exchangeCode(t, a, codeFromURL(t, cr.Redirect))
	at, err := extStore(t, a).FindOAuthAccessToken(context.Background(), tr.AccessToken)
	if err != nil || len(at.Resources) != 1 || at.Resources[0] != "https://api.example" {
		t.Fatalf("access token should carry the resource: %+v err=%v", at, err)
	}
}

func TestOIDCResourceEnforcePerClient(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{EnforcePerClientResources: true}))
	cookies := signUpPluginUser(t, a, "res-enforce@example.com")
	clientID := registerOAuthClient(t, a)
	resParam := "&resource=" + url.QueryEscape("https://api.example")

	if cw := postWithCookies(t, a, "/oauth2/resource", `{"identifier":"https://api.example","name":"API"}`, cookies); cw.Code != http.StatusOK {
		t.Fatalf("create resource: %s", cw.Body.String())
	}
	// Not linked -> invalid_target.
	if w := authorizeRaw(t, a, clientID, "openid", resParam, cookies); !strings.Contains(w.Header().Get("Location"), "error=invalid_target") {
		t.Fatalf("unlinked client should be invalid_target: %s", w.Header().Get("Location"))
	}
	// Link, then it passes the resource gate (consent required next).
	if lk := postWithCookies(t, a, "/oauth2/client-resource/link", `{"client_id":"`+clientID+`","resource_id":"https://api.example"}`, cookies); lk.Code != http.StatusOK {
		t.Fatalf("link: %s", lk.Body.String())
	}
	if w := authorizeRaw(t, a, clientID, "openid", resParam, cookies); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "consentRequired") {
		t.Fatalf("linked client should pass resource gate: %d %s", w.Code, w.Body.String())
	}
}
