package plugins_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/patrickkabwe/betterauth-go/plugins"
)

func TestOIDCRegisterFullMetadata(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	body := `{
		"client_name":"Full App",
		"redirect_uris":["https://app.example/cb"],
		"grant_types":["authorization_code","refresh_token"],
		"token_endpoint_auth_method":"client_secret_post",
		"application_type":"native",
		"scope":"openid email",
		"client_uri":"https://app.example",
		"logo_uri":"https://app.example/logo.png",
		"contacts":["dev@app.example"],
		"tos_uri":"https://app.example/tos",
		"policy_uri":"https://app.example/privacy",
		"post_logout_redirect_uris":["https://app.example/after-logout"]
	}`
	w := post(t, a, "/oauth2/register", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", w.Code, w.Body.String())
	}
	var r map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatalf("register response: %s", w.Body.String())
	}
	if r["client_id"] == "" || r["client_id"] == nil {
		t.Fatalf("missing client_id: %v", r)
	}
	if r["client_secret"] == nil || r["client_secret"] == "" {
		t.Fatalf("expected client_secret for client_secret_post: %v", r)
	}
	if r["client_secret_expires_at"] != float64(0) {
		t.Fatalf("client_secret_expires_at should be 0, got %v", r["client_secret_expires_at"])
	}
	if r["client_id_issued_at"] == nil {
		t.Fatalf("missing client_id_issued_at: %v", r)
	}
	if r["token_endpoint_auth_method"] != "client_secret_post" {
		t.Fatalf("token_endpoint_auth_method=%v", r["token_endpoint_auth_method"])
	}
	if r["application_type"] != "native" {
		t.Fatalf("application_type=%v", r["application_type"])
	}
	if r["client_name"] != "Full App" || r["scope"] != "openid email" {
		t.Fatalf("echoed metadata wrong: %v", r)
	}
	rt, _ := r["response_types"].([]any)
	if len(rt) != 1 || rt[0] != "code" {
		t.Fatalf("response_types=%v", r["response_types"])
	}
}

func TestOIDCRegisterDefaults(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	w := post(t, a, "/oauth2/register", `{"client_name":"Defaults","redirect_uris":["https://app.example/cb"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var r map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &r)
	if r["token_endpoint_auth_method"] != "client_secret_basic" {
		t.Fatalf("default auth method=%v", r["token_endpoint_auth_method"])
	}
	if r["application_type"] != "web" {
		t.Fatalf("default application_type=%v", r["application_type"])
	}
	gt, _ := r["grant_types"].([]any)
	if len(gt) != 1 || gt[0] != "authorization_code" {
		t.Fatalf("default grant_types=%v", r["grant_types"])
	}
}

func TestOIDCRegisterPublicClientNoSecret(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	w := post(t, a, "/oauth2/register", `{"client_name":"Public","redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"none"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var r map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &r)
	if _, ok := r["client_secret"]; ok {
		t.Fatalf("public client must not receive a client_secret: %v", r)
	}
}

func TestOIDCRegisterUnsupportedAuthMethod(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	w := post(t, a, "/oauth2/register", `{"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"tls_client_auth"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unsupported auth method should 400, got %d %s", w.Code, w.Body.String())
	}
}

func TestOIDCRegisterInvalidApplicationType(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	w := post(t, a, "/oauth2/register", `{"redirect_uris":["https://app.example/cb"],"application_type":"desktop"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid application_type should 400, got %d %s", w.Code, w.Body.String())
	}
}

func TestOIDCRegisterAuthCodeRequiresRedirect(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	w := post(t, a, "/oauth2/register", `{"client_name":"NoRedirect"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("authorization_code without redirect_uris should 400, got %d %s", w.Code, w.Body.String())
	}
}

func TestOIDCRegisterPrivateKeyJWTRequiresJWKS(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	w := post(t, a, "/oauth2/register", `{"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"private_key_jwt"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("private_key_jwt without jwks should 400, got %d %s", w.Code, w.Body.String())
	}
}

func TestOIDCRegisterUnsupportedGrant(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	w := post(t, a, "/oauth2/register", `{"redirect_uris":["https://app.example/cb"],"grant_types":["password"]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("no mutually supported grant should 400, got %d %s", w.Code, w.Body.String())
	}
}
