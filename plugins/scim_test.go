package plugins_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/plugins"
)

func TestSCIMUserLifecycle(t *testing.T) {
	a := newTestAuth(t, plugins.SCIM(plugins.SCIMOptions{Token: "scim-token"}))

	create := scimRequest(t, a, http.MethodPost, "/scim/v2/Users", `{
		"userName":"scim@example.com",
		"name":{"givenName":"SCIM","familyName":"User"},
		"emails":[{"value":"scim@example.com","primary":true}]
	}`, "scim-token")
	if create.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	userID, _ := created["id"].(string)
	if userID == "" || created["userName"] != "scim@example.com" || created["displayName"] != "SCIM User" {
		t.Fatalf("created=%+v", created)
	}

	list := scimRequest(t, a, http.MethodGet, "/scim/v2/Users", "", "scim-token")
	if list.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
	var listed map[string]any
	_ = json.Unmarshal(list.Body.Bytes(), &listed)
	if listed["totalResults"].(float64) != 1 {
		t.Fatalf("listed=%+v", listed)
	}

	patch := scimRequest(t, a, http.MethodPatch, "/scim/v2/Users/"+userID, `{
		"Operations":[{"op":"replace","path":"displayName","value":"Renamed User"},{"op":"replace","path":"active","value":false}]
	}`, "scim-token")
	if patch.Code != http.StatusOK {
		t.Fatalf("patch status=%d body=%s", patch.Code, patch.Body.String())
	}
	var patched map[string]any
	_ = json.Unmarshal(patch.Body.Bytes(), &patched)
	if patched["displayName"] != "Renamed User" || patched["active"] != false {
		t.Fatalf("patched=%+v", patched)
	}

	del := scimRequest(t, a, http.MethodDelete, "/scim/v2/Users/"+userID, "", "scim-token")
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", del.Code, del.Body.String())
	}
	getDeleted := scimRequest(t, a, http.MethodGet, "/scim/v2/Users/"+userID, "", "scim-token")
	if getDeleted.Code != http.StatusNotFound {
		t.Fatalf("get deleted status=%d body=%s", getDeleted.Code, getDeleted.Body.String())
	}
}

func TestSCIMRejectsMissingToken(t *testing.T) {
	a := newTestAuth(t, plugins.SCIM(plugins.SCIMOptions{Token: "scim-token"}))
	resp := scimRequest(t, a, http.MethodGet, "/scim/v2/ServiceProviderConfig", "", "")
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
}

func scimRequest(t *testing.T, a interface{ Handler() http.Handler }, method string, path string, body string, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(constants.HeaderContentType, "application/scim+json")
	if token != "" {
		req.Header.Set(constants.HeaderAuthorization, constants.TokenTypeBearer+" "+token)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	return w
}
