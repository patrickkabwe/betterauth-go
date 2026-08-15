package plugins_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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

func samlResponse(email string, name string) string {
	xml := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><saml:Subject><saml:NameID>` + email + `</saml:NameID></saml:Subject><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>` + email + `</saml:AttributeValue></saml:Attribute><saml:Attribute Name="name"><saml:AttributeValue>` + name + `</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`
	return base64.StdEncoding.EncodeToString([]byte(xml))
}
