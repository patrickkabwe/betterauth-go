package plugins_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestPasskeyGenerateRegisterOptions(t *testing.T) {
	a := newTestAuth(t, plugins.Passkey(plugins.PasskeyOptions{}))
	cookies := signUpPluginUser(t, a, "passkey@example.com")
	resp := getWithCookies(t, a, "/passkey/generate-register-options", cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if resp.Result().Cookies()[0].Name != "better-auth-passkey" {
		t.Fatalf("cookies=%+v", resp.Result().Cookies())
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["publicKey"] == nil {
		t.Fatalf("body=%s", resp.Body.String())
	}
}

func TestPasskeyGenerateAuthenticateOptions(t *testing.T) {
	a := newTestAuth(t, plugins.Passkey(plugins.PasskeyOptions{}))
	resp := get(t, a, "/passkey/generate-authenticate-options")
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if resp.Result().Cookies()[0].Name != "better-auth-passkey" {
		t.Fatalf("cookies=%+v", resp.Result().Cookies())
	}
}

func TestPasskeyListUpdateDelete(t *testing.T) {
	a := newTestAuth(t, plugins.Passkey(plugins.PasskeyOptions{}))
	cookies := signUpPluginUser(t, a, "passkey-manage@example.com")
	user := currentPluginUser(t, a, cookies)
	ext, ok := auth.ExtStore(a.Store())
	if !ok {
		t.Fatal("missing ext store")
	}
	now := time.Now().UTC()
	passkey := &types.Passkey{
		ID: "pk_test", UserID: user.ID, Name: "Laptop", CredentialID: "cred_test",
		CredentialJSON: "{}", CreatedAt: now, UpdatedAt: now,
	}
	if err := ext.CreatePasskey(context.Background(), passkey); err != nil {
		t.Fatal(err)
	}
	list := getWithCookies(t, a, "/passkey/list", cookies)
	if list.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
	if !jsonContains(list.Body.Bytes(), "Laptop") {
		t.Fatalf("list body=%s", list.Body.String())
	}
	update := postWithCookies(t, a, "/passkey/update", `{"id":"pk_test","name":"Security Key"}`, cookies)
	if update.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", update.Code, update.Body.String())
	}
	deleteResp := postWithCookies(t, a, "/passkey/delete", `{"id":"pk_test"}`, cookies)
	if deleteResp.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", deleteResp.Code, deleteResp.Body.String())
	}
}

func currentPluginUser(t *testing.T, a *auth.Auth, cookies []*http.Cookie) types.User {
	t.Helper()
	resp := getWithCookies(t, a, "/get-session", cookies)
	if resp.Code != http.StatusOK {
		t.Fatalf("session status=%d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		User types.User `json:"user"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.User
}

func jsonContains(data []byte, value string) bool {
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return false
	}
	return stringsContainsJSON(decoded, value)
}

func stringsContainsJSON(value any, needle string) bool {
	switch typed := value.(type) {
	case string:
		return typed == needle
	case []any:
		for _, item := range typed {
			if stringsContainsJSON(item, needle) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if stringsContainsJSON(item, needle) {
				return true
			}
		}
	}
	return false
}
