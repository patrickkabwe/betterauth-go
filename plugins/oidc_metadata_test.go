package plugins_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/patrickkabwe/betterauth-go/plugins"
)

func TestOIDCMetadataCompleteness(t *testing.T) {
	a := newTestAuth(t, plugins.OIDCProvider(plugins.OIDCProviderOptions{}))
	w := get(t, a, "/.well-known/openid-configuration")
	if w.Code != http.StatusOK {
		t.Fatalf("metadata status=%d", w.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("metadata json: %s", w.Body.String())
	}

	// Endpoints advertised in Phase 8.
	for _, k := range []string{
		"registration_endpoint", "end_session_endpoint", "device_authorization_endpoint",
		"introspection_endpoint", "revocation_endpoint", "userinfo_endpoint", "jwks_uri",
	} {
		if _, ok := m[k]; !ok {
			t.Fatalf("metadata missing %q: %v", k, m)
		}
	}

	// grant_types_supported must include authorization_code, refresh_token and
	// the RFC 8628 device_code grant.
	gts, _ := m["grant_types_supported"].([]any)
	want := map[string]bool{
		"authorization_code": false, "refresh_token": false,
		"urn:ietf:params:oauth:grant-type:device_code": false,
	}
	for _, g := range gts {
		if s, ok := g.(string); ok {
			if _, tracked := want[s]; tracked {
				want[s] = true
			}
		}
	}
	for g, seen := range want {
		if !seen {
			t.Fatalf("grant_types_supported missing %q: %v", g, m["grant_types_supported"])
		}
	}

	// PKCE and iss advertisement.
	cm, _ := m["code_challenge_methods_supported"].([]any)
	if len(cm) != 1 || cm[0] != "S256" {
		t.Fatalf("code_challenge_methods_supported=%v", m["code_challenge_methods_supported"])
	}
	if m["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("authorization_response_iss_parameter_supported=%v", m["authorization_response_iss_parameter_supported"])
	}
	if _, ok := m["claims_supported"]; !ok {
		t.Fatalf("claims_supported missing: %v", m)
	}
}
