package plugins_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/patrickkabwe/betterauth-go/plugins"
)

// TestMCPTokenUsesOAuthAccessToken verifies the MCP authorize/token flow issues
// an opaque access token stored in oauthAccessToken (not the verification table).
func TestMCPTokenUsesOAuthAccessToken(t *testing.T) {
	a := newTestAuth(t, plugins.MCP(plugins.MCPOptions{}))
	cookies := signUpPluginUser(t, a, "mcp-flow@example.com")
	user := currentPluginUser(t, a, cookies)

	path := "/mcp/authorize?redirect_uri=" + url.QueryEscape("https://app.example/cb") + "&state=xyz&scope=openid"
	w := getWithCookies(t, a, path, cookies)
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Fatalf("authorize status=%d body=%s", w.Code, w.Body.String())
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect %q", w.Header().Get("Location"))
	}

	tw := post(t, a, "/mcp/token", `{"grant_type":"authorization_code","code":"`+code+`"}`)
	if tw.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", tw.Code, tw.Body.String())
	}
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(tw.Body.Bytes(), &tr)
	if tr.AccessToken == "" {
		t.Fatalf("no access token: %s", tw.Body.String())
	}
	at, err := extStore(t, a).FindOAuthAccessToken(context.Background(), tr.AccessToken)
	if err != nil || at.UserID != user.ID || at.SessionID == "" {
		t.Fatalf("mcp access token not stored/bound: %+v err=%v", at, err)
	}
}
