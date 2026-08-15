package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/jwt"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestOK(t *testing.T) {
	a := newTestAuth()
	resp, data := doRequest(a, http.MethodGet, "/ok", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var result types.OKResponse
	if err := json.Unmarshal(data, &result); err != nil || !result.OK {
		t.Fatal("expected ok")
	}
}

func TestSignUpSignInSessionSignOut(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "test@example.com")

	resp, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	if resp.StatusCode != http.StatusOK || string(data) == "null" {
		t.Fatalf("expected session, got %s", data)
	}

	resp, _ = doRequest(a, http.MethodPost, "/sign-out", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("sign-out failed")
	}

	resp, data = doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	if string(data) != "null" {
		t.Fatalf("expected null, got %s", data)
	}

	resp, data = doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "test@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in failed: %s", data)
	}
}

func TestInvalidCredentials(t *testing.T) {
	a := newTestAuth()
	signUp(t, a, "test@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "test@example.com", "password": "wrong",
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestCORS(t *testing.T) {
	a := newTestAuth()
	req := httptest.NewRequest(http.MethodOptions, "/get-session", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.URL.Path = "/get-session"
	rr := httptest.NewRecorder()
	a.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Fatal("missing cors")
	}
}

func TestPasswordResetFlow(t *testing.T) {
	var resetData types.ResetPasswordEmailData
	a := newTestAuth(func(c *auth.Config) {
		c.EmailAndPassword.SendResetPassword = func(_ context.Context, data types.ResetPasswordEmailData) error {
			resetData = data
			return nil
		}
	})
	signUp(t, a, "reset@example.com")

	resp, _ := doRequest(a, http.MethodPost, "/request-password-reset", map[string]any{
		"email": "reset@example.com", "redirectTo": "http://localhost:3000/reset",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("request reset failed")
	}
	if resetData.Token == "" {
		t.Fatal("expected reset token emailed")
	}

	resp, _ = doRequest(a, http.MethodGet, "/reset-password/"+resetData.Token+"?callbackURL=http://localhost:3000/done", nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d", resp.StatusCode)
	}

	resp, _ = doRequest(a, http.MethodPost, "/reset-password", map[string]any{
		"token": resetData.Token, "newPassword": "newpassword99",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("reset password failed")
	}

	resp, data := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "reset@example.com", "password": "newpassword99",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in with new password failed: %s", data)
	}
}

func TestUpdateUserAndChangePassword(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "update@example.com")

	resp, _ := doRequest(a, http.MethodPost, "/update-user", map[string]any{
		"name": "Updated Name",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("update user failed")
	}

	resp, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	if sess.User.Name != "Updated Name" {
		t.Fatalf("name = %q", sess.User.Name)
	}

	resp, _ = doRequest(a, http.MethodPost, "/change-password", map[string]any{
		"currentPassword": "password123",
		"newPassword":     "changedpass1",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("change password failed")
	}

	resp, _ = doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "update@example.com", "password": "changedpass1",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("sign-in with changed password failed")
	}
}

func TestListAccounts(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "accounts@example.com")
	resp, data := doRequest(a, http.MethodGet, "/list-accounts", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("list accounts failed")
	}
	var accounts []types.AccountResponse
	if err := json.Unmarshal(data, &accounts); err != nil || len(accounts) != 1 {
		t.Fatalf("accounts = %s", data)
	}
	if accounts[0].ProviderID != constants.ProviderCredential {
		t.Fatal("expected credential provider")
	}
}

func TestVerifyPassword(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "verify@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/verify-password", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("verify password failed")
	}
}

func TestRequireEmailVerification(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.EmailAndPassword.RequireEmailVerification = true
	})
	signUp(t, a, "unverified@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "unverified@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d want 403", resp.StatusCode)
	}
}

func TestSignUpEmailAcceptsFormURLEncoded(t *testing.T) {
	a := newTestAuth()
	resp, data := doFormRequest(a, http.MethodPost, "/sign-up/email", url.Values{
		"name":     {"Form User"},
		"email":    {"form-signup@example.com"},
		"password": {"password123"},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
}

func TestSignInEmailAcceptsFormURLEncoded(t *testing.T) {
	a := newTestAuth()
	signUp(t, a, "form-signin@example.com")
	resp, data := doFormRequest(a, http.MethodPost, "/sign-in/email", url.Values{
		"email":    {"form-signin@example.com"},
		"password": {"password123"},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
}

func TestSignUpEmailSendsVerificationWhenRequired(t *testing.T) {
	sent := false
	a := newTestAuth(func(c *auth.Config) {
		c.EmailAndPassword.RequireEmailVerification = true
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, data types.VerificationEmailData) error {
			sent = data.User.Email == "verify-signup@example.com" && data.URL != "" && data.Token != ""
			return nil
		}
	})
	resp, data := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "Verify Signup", "email": "verify-signup@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
	if !sent {
		t.Fatal("expected verification email on sign up")
	}
}

func TestAutoSignInDisabled(t *testing.T) {
	auto := false
	a := newTestAuth(func(c *auth.Config) {
		c.EmailAndPassword.AutoSignIn = &auto
	})
	resp, data := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "No Session", "email": "nosession@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("sign-up failed")
	}
	var signUp types.SignUpResponse
	_ = json.Unmarshal(data, &signUp)
	if signUp.Token != nil {
		t.Fatal("expected no token when auto sign-in disabled")
	}
}

func TestVerifyEmailEndpoint(t *testing.T) {
	a := newTestAuth()
	signUp(t, a, "verifyme@example.com")

	token, err := jwt.SignHS256("test-secret-key-for-cookie-signing", map[string]any{
		"email": "verifyme@example.com",
	}, 3600)
	if err != nil {
		t.Fatal(err)
	}

	resp, data := doRequest(a, http.MethodGet, "/verify-email?token="+token, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify failed: %s", data)
	}
	var result types.VerifyEmailResponse
	_ = json.Unmarshal(data, &result)
	if result.User == nil || !result.User.EmailVerified {
		t.Fatal("email should be verified")
	}
}

func TestCustomHasher(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Hasher = plainHasher{}
	})
	signUp(t, a, "custom@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "custom@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("custom hasher sign-in failed")
	}
}

type plainHasher struct{}

func (plainHasher) Hash(password string) (string, error)       { return "plain:" + password, nil }
func (plainHasher) Verify(hash, password string) (bool, error) { return hash == "plain:"+password, nil }

func TestDeleteUserWithPassword(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "delete@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/delete-user", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("delete user failed")
	}
	resp, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	if string(data) != "null" {
		t.Fatal("session should be gone")
	}
}

func TestEnumerationProtection(t *testing.T) {
	auto := false
	a := newTestAuth(func(c *auth.Config) {
		c.EmailAndPassword.AutoSignIn = &auto
	})
	signUp(t, a, "exists@example.com")
	resp, data := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "Dup", "email": "exists@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected synthetic ok, got %d %s", resp.StatusCode, data)
	}
}

func TestListSessionsAndRevoke(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "sessions@example.com")

	resp, data := doRequest(a, http.MethodGet, "/list-sessions", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("list sessions failed")
	}
	var sessions []types.Session
	_ = json.Unmarshal(data, &sessions)
	if len(sessions) < 1 {
		t.Fatal("expected sessions")
	}

	resp, _ = doRequest(a, http.MethodPost, "/revoke-other-sessions", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("revoke other failed")
	}
}

func TestResetPasswordDisabled(t *testing.T) {
	a := newTestAuth()
	resp, _ := doRequest(a, http.MethodPost, "/request-password-reset", map[string]any{
		"email": "a@b.com",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestSendVerificationEmail(t *testing.T) {
	var sent bool
	a := newTestAuth(func(c *auth.Config) {
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, _ types.VerificationEmailData) error {
			sent = true
			return nil
		}
	})
	signUp(t, a, "send@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/send-verification-email", map[string]any{
		"email": "send@example.com",
	}, nil)
	if resp.StatusCode != http.StatusOK || !sent {
		t.Fatal("send verification failed")
	}
}

func TestSetPassword(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "setpw@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/set-password", map[string]any{
		"newPassword": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("set-password should fail when password exists, got %d", resp.StatusCode)
	}
}

func TestUnlinkAccount(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "unlink@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/unlink-account", map[string]any{
		"providerId": constants.ProviderCredential,
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unlink only account should fail, got %d", resp.StatusCode)
	}
}

func TestDeferSessionRefresh(t *testing.T) {
	cookiesDefault := signUp(t, newTestAuth(), "defer-default@example.com")
	resp, _ := doRequest(newTestAuth(), http.MethodPost, "/get-session", nil, cookiesDefault)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST get-session without defer should be 405, got %d", resp.StatusCode)
	}

	a := newTestAuth(func(c *auth.Config) {
		c.Session.DeferSessionRefresh = true
	})
	cookies := signUp(t, a, "defer@example.com")
	resp, data := doRequest(a, http.MethodPost, "/get-session", nil, cookies)
	if resp.StatusCode != http.StatusOK || string(data) == "null" {
		t.Fatalf("POST get-session with defer enabled failed: %s", data)
	}
}

func TestUpdateSession(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "upsess@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/update-session", map[string]any{
		"ipAddress": "10.0.0.1",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("update session failed")
	}
}
