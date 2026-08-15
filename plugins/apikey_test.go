package plugins_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestAPIKeyCreateVerifyListAndDelete(t *testing.T) {
	a := newTestAuth(t, plugins.APIKey(plugins.APIKeyOptions{}))
	cookies := signUpPluginUser(t, a, "api-key@example.com")

	create := postWithCookies(t, a, "/api-key/create", `{"name":"CLI key","metadata":{"env":"test"}}`, cookies)
	if create.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	var created struct {
		Key    string       `json:"key"`
		APIKey types.APIKey `json:"apiKey"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Key == "" || created.APIKey.ID == "" || created.APIKey.Key != "" {
		t.Fatalf("created=%+v", created)
	}

	verify := post(t, a, "/api-key/verify", `{"key":"`+created.Key+`"}`)
	if verify.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", verify.Code, verify.Body.String())
	}

	list := getWithCookies(t, a, "/api-key/list", cookies)
	if list.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
	var listed []types.APIKey
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != created.APIKey.ID {
		t.Fatalf("listed=%+v", listed)
	}

	deleteResp := postWithCookies(t, a, "/api-key/delete", `{"id":"`+created.APIKey.ID+`"}`, cookies)
	if deleteResp.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", deleteResp.Code, deleteResp.Body.String())
	}
	verify = post(t, a, "/api-key/verify", `{"key":"`+created.Key+`"}`)
	if verify.Code != http.StatusForbidden {
		t.Fatalf("verify deleted status=%d body=%s", verify.Code, verify.Body.String())
	}
}

func TestAPIKeyCanResolveSessionFromHeader(t *testing.T) {
	a := newTestAuth(t, plugins.APIKey(plugins.APIKeyOptions{EnableSessionForAPIKeys: true}))
	cookies := signUpPluginUser(t, a, "api-key-session@example.com")
	create := postWithCookies(t, a, "/api-key/create", `{"name":"Session key"}`, cookies)
	if create.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	var created struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/get-session", nil)
	req.Header.Set("x-api-key", created.Key)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get-session status=%d body=%s", w.Code, w.Body.String())
	}
	var session struct {
		User types.User `json:"user"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.User.Email != "api-key-session@example.com" {
		t.Fatalf("session=%+v", session)
	}
}

func signUpPluginUser(t *testing.T, a *auth.Auth, email string) []*http.Cookie {
	t.Helper()
	body := `{"name":"API User","email":"` + email + `","password":"password123"}`
	resp := post(t, a, "/sign-up/email", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%s", resp.Code, resp.Body.String())
	}
	return resp.Result().Cookies()
}

func getWithCookies(t *testing.T, a *auth.Auth, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, strings.NewReader(""))
	req.Header.Set(constants.HeaderContentType, constants.MIMEJSON)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	return w
}
