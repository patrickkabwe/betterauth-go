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
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/plugins"
)

func postWithCookies(t *testing.T, a *auth.Auth, path string, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set(constants.HeaderContentType, constants.MIMEJSON)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	return w
}

func TestAnonymousSignInRejectsExistingAnonymousSession(t *testing.T) {
	a := newTestAuth(t, plugins.Anonymous(plugins.AnonymousOptions{}))
	w := post(t, a, "/sign-in/anonymous", `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	w = postWithCookies(t, a, "/sign-in/anonymous", `{}`, w.Result().Cookies())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestMagicLinkVerifyWithoutCallbackReturnsJSON(t *testing.T) {
	var sentLink string
	a := newTestAuth(t, plugins.MagicLink(plugins.MagicLinkOptions{
		SendMagicLink: func(_ context.Context, _ string, link string, _ string) error {
			sentLink = link
			return nil
		},
	}))
	w := post(t, a, "/sign-in/magic-link", `{"email":"verify-json@example.com"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	u, err := url.Parse(sentLink)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Del("callbackURL")
	w = get(t, a, "/magic-link/verify?"+query.Encode())
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token == "" {
		t.Fatal("expected token in JSON response")
	}
}
