package auth_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestUsernamePluginSignUpStoresUsernameFields(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Username(plugins.UsernameOptions{})}
	})
	resp, data := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "Username User", "email": "username-signup@example.com", "password": "password123",
		"username": "New_User",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-up status = %d body=%s", resp.StatusCode, data)
	}
	var result types.SignUpResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.User.Additional[constants.FieldUsername] != "new_user" {
		t.Fatalf("username not normalized: %+v", result.User.Additional)
	}
	if result.User.Additional[constants.FieldDisplayUsername] != "New_User" {
		t.Fatalf("displayUsername default mismatch: %+v", result.User.Additional)
	}
}

func TestUsernamePluginSignUpRejectsDuplicateUsername(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Username(plugins.UsernameOptions{})}
	})
	resp, data := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "First User", "email": "username-first@example.com", "password": "password123",
		"username": "taken_user",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first sign-up status = %d body=%s", resp.StatusCode, data)
	}
	resp, _ = doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "Second User", "email": "username-second@example.com", "password": "password123",
		"username": "Taken_User",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate username status = %d", resp.StatusCode)
	}
}

func TestUsernamePluginUpdateUserStoresUsernameFields(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Username(plugins.UsernameOptions{})}
	})
	cookies := signUp(t, a, "username-update@example.com")
	resp, data := doRequest(a, http.MethodPost, "/update-user", map[string]any{
		"username": "Updated.Name", "displayUsername": "Updated Name",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodGet, "/get-session?disableCookieCache=true", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get-session status = %d body=%s", resp.StatusCode, data)
	}
	var session types.SessionResponse
	if err := json.Unmarshal(data, &session); err != nil {
		t.Fatal(err)
	}
	if session.User.Additional[constants.FieldUsername] != "updated.name" {
		t.Fatalf("username not updated: %+v", session.User.Additional)
	}
	if session.User.Additional[constants.FieldDisplayUsername] != "Updated Name" {
		t.Fatalf("displayUsername not updated: %+v", session.User.Additional)
	}
}

func TestUsernamePluginUpdateUserRejectsDuplicateUsername(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.Username(plugins.UsernameOptions{})}
	})
	resp, data := doRequest(a, http.MethodPost, "/update-user", map[string]any{
		"username": "owner",
	}, signUp(t, a, "username-owner-session@example.com"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner update status = %d body=%s", resp.StatusCode, data)
	}
	cookies := signUp(t, a, "username-duplicate@example.com")
	resp, _ = doRequest(a, http.MethodPost, "/update-user", map[string]any{
		"username": "OWNER",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("duplicate update status = %d", resp.StatusCode)
	}
}

func TestSignUpAdditionalFieldsAreParsedOnCreate(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.User.AdditionalFields = map[string]auth.AdditionalFieldDef{
			"plan": {Type: "string", Required: true},
		}
	})
	resp, _ := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "Missing Plan", "email": "missing-plan@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing required field status = %d", resp.StatusCode)
	}
	resp, data := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "With Plan", "email": "with-plan@example.com", "password": "password123", "plan": "pro",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-up status = %d body=%s", resp.StatusCode, data)
	}
	var result types.SignUpResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.User.Additional["plan"] != "pro" {
		t.Fatalf("plan not persisted: %+v", result.User.Additional)
	}
}
