package plugins_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestSSORegisterListAndMetadata(t *testing.T) {
	a := newTestAuth(t, plugins.SSO(plugins.SSOOptions{}))
	cookies := signUpPluginUser(t, a, "sso-admin@example.com")
	body := `{"providerId":"acme","issuer":"https://sp.example.test","domain":"example.com","samlConfig":{"entryPoint":"https://idp.example.test/sso","entityId":"https://sp.example.test/entity"}}`
	create := postWithCookies(t, a, "/sso/register", body, cookies)
	if create.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", create.Code, create.Body.String())
	}
	if !strings.Contains(create.Body.String(), `"type":"saml"`) {
		t.Fatalf("register body=%s", create.Body.String())
	}

	list := getWithCookies(t, a, "/sso/providers", cookies)
	if list.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
	if !strings.Contains(list.Body.String(), `"providerId":"acme"`) {
		t.Fatalf("list body=%s", list.Body.String())
	}

	metadata := get(t, a, "/sso/saml2/sp/metadata?providerId=acme")
	if metadata.Code != http.StatusOK {
		t.Fatalf("metadata status=%d body=%s", metadata.Code, metadata.Body.String())
	}
	if !strings.Contains(metadata.Body.String(), "EntityDescriptor") ||
		!strings.Contains(metadata.Body.String(), "/sso/saml2/sp/acs/acme") {
		t.Fatalf("metadata body=%s", metadata.Body.String())
	}
}

func TestSSOSAMLSignInRedirect(t *testing.T) {
	a := newTestAuth(t, plugins.SSO(plugins.SSOOptions{
		Providers: []plugins.SSOProviderConfig{{
			ProviderID: "acme",
			Issuer:     "https://sp.example.test",
			Domain:     "example.com",
			SAMLConfig: plugins.SSOSAMLConfig{
				EntryPoint: "https://idp.example.test/sso",
				EntityID:   "https://sp.example.test/entity",
			},
		}},
	}))
	resp := post(t, a, "/sign-in/sso", `{"domain":"example.com","callbackURL":"https://app.example.test/dashboard"}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("sign-in status=%d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		URL      string `json:"url"`
		Redirect bool   `json:"redirect"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host != "idp.example.test" || parsed.Query().Get("SAMLRequest") == "" || parsed.Query().Get("RelayState") == "" || !body.Redirect {
		t.Fatalf("redirect=%+v", body)
	}
}

func TestSSOSAMLACSCreateSession(t *testing.T) {
	a := newTestAuth(t, plugins.SSO(plugins.SSOOptions{
		Providers: []plugins.SSOProviderConfig{{
			ProviderID: "acme",
			Issuer:     "https://sp.example.test",
			Domain:     "example.com",
			SAMLConfig: plugins.SSOSAMLConfig{
				EntryPoint: "https://idp.example.test/sso",
				EntityID:   "https://sp.example.test/entity",
			},
		}},
	}))
	form := url.Values{}
	form.Set("SAMLResponse", samlResponse("sso-user@example.com", "SSO User"))
	req := httptest.NewRequest(http.MethodPost, "/sso/saml2/sp/acs/acme", strings.NewReader(form.Encode()))
	req.Header.Set(constants.HeaderContentType, "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("acs status=%d body=%s", w.Code, w.Body.String())
	}

	session := getWithCookies(t, a, "/get-session", w.Result().Cookies())
	if session.Code != http.StatusOK {
		t.Fatalf("session status=%d body=%s", session.Code, session.Body.String())
	}
	var sessionBody struct {
		User types.User `json:"user"`
	}
	if err := json.Unmarshal(session.Body.Bytes(), &sessionBody); err != nil {
		t.Fatal(err)
	}
	if sessionBody.User.Email != "sso-user@example.com" || !sessionBody.User.EmailVerified {
		t.Fatalf("user=%+v", sessionBody.User)
	}
}

func TestSSOOIDCSignInRedirect(t *testing.T) {
	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request %s", r.URL.Path)
	}))
	defer oidc.Close()
	a := newTestAuth(t, plugins.SSO(plugins.SSOOptions{
		Providers: []plugins.SSOProviderConfig{{
			ProviderID: "oidc-acme",
			Issuer:     oidc.URL,
			Domain:     "oidc.example.com",
			OIDCConfig: plugins.SSOOIDCConfig{
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
				AuthorizationEndpoint: oidc.URL + "/authorize",
				TokenEndpoint:         oidc.URL + "/token",
				UserInfoEndpoint:      oidc.URL + "/userinfo",
				Scopes:                []string{"email", "profile"},
			},
		}},
	}))
	resp := post(t, a, "/sign-in/sso", `{"domain":"oidc.example.com","callbackURL":"https://app.example.test/dashboard"}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("sign-in status=%d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		URL      string `json:"url"`
		Redirect bool   `json:"redirect"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if parsed.Path != "/authorize" || !body.Redirect {
		t.Fatalf("redirect=%+v", body)
	}
	if query.Get("client_id") != "client-id" || query.Get("response_type") != "code" || query.Get("state") == "" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("scope") != "openid email profile" || query.Get("code_challenge") == "" || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("redirect_uri") != "http://localhost:8080/api/auth/sso/oidc/callback/oidc-acme" {
		t.Fatalf("redirect_uri=%q", query.Get("redirect_uri"))
	}
}

func TestSSOOIDCCallbackCreateSession(t *testing.T) {
	var state string
	var oidc *httptest.Server
	oidc = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "code-1" || r.Form.Get("code_verifier") == "" {
				t.Fatalf("token form=%s", r.Form.Encode())
			}
			if r.Form.Get("redirect_uri") != "http://localhost:8080/api/auth/sso/oidc/callback/oidc-acme" {
				t.Fatalf("redirect_uri=%q", r.Form.Get("redirect_uri"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-1",
				"id_token": oidcIDToken(map[string]any{
					"iss": oidc.URL, "aud": "client-id", "sub": "subject-1",
					"email": "oidc-user@example.com", "email_verified": true, "name": "OIDC User",
				}),
				"scope":      "openid email profile",
				"expires_in": 3600,
			})
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
	}))
	defer oidc.Close()
	a := newTestAuth(t, plugins.SSO(plugins.SSOOptions{
		Providers: []plugins.SSOProviderConfig{{
			ProviderID: "oidc-acme",
			Issuer:     oidc.URL,
			Domain:     "oidc.example.com",
			OIDCConfig: plugins.SSOOIDCConfig{
				ClientID:              "client-id",
				ClientSecret:          "client-secret",
				AuthorizationEndpoint: oidc.URL + "/authorize",
				TokenEndpoint:         oidc.URL + "/token",
			},
		}},
	}))
	signIn := post(t, a, "/sign-in/sso", `{"providerId":"oidc-acme"}`)
	if signIn.Code != http.StatusOK {
		t.Fatalf("sign-in status=%d body=%s", signIn.Code, signIn.Body.String())
	}
	var signInBody struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(signIn.Body.Bytes(), &signInBody); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(signInBody.URL)
	if err != nil {
		t.Fatal(err)
	}
	state = parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("url=%s", signInBody.URL)
	}
	callback := get(t, a, "/sso/oidc/callback/oidc-acme?code=code-1&state="+url.QueryEscape(state))
	if callback.Code != http.StatusOK {
		t.Fatalf("callback status=%d body=%s", callback.Code, callback.Body.String())
	}
	session := getWithCookies(t, a, "/get-session", callback.Result().Cookies())
	if session.Code != http.StatusOK {
		t.Fatalf("session status=%d body=%s", session.Code, session.Body.String())
	}
	var sessionBody struct {
		User types.User `json:"user"`
	}
	if err := json.Unmarshal(session.Body.Bytes(), &sessionBody); err != nil {
		t.Fatal(err)
	}
	if sessionBody.User.Email != "oidc-user@example.com" || !sessionBody.User.EmailVerified {
		t.Fatalf("user=%+v", sessionBody.User)
	}
}

func samlResponse(email string, name string) string {
	xml := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><saml:Subject><saml:NameID>` + email + `</saml:NameID></saml:Subject><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>` + email + `</saml:AttributeValue></saml:Attribute><saml:Attribute Name="name"><saml:AttributeValue>` + name + `</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`
	return base64.StdEncoding.EncodeToString([]byte(xml))
}

func oidcIDToken(claims map[string]any) string {
	payload := map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for key, value := range claims {
		payload[key] = value
	}
	raw, _ := json.Marshal(payload)
	return "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}
