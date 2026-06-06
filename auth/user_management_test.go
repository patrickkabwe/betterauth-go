package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/internal/jwt"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestUpdateUserAdditionalField(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.User.AdditionalFields = map[string]auth.AdditionalFieldDef{
			"role": {Type: "string", Input: boolPtr(true)},
		}
	})
	cookies := signUp(t, a, "addfield@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/update-user", map[string]any{
		"role": "admin",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	resp, data := doRequest(a, http.MethodGet, "/get-session?disableCookieCache=true", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	if sess.User.Additional["role"] != "admin" {
		t.Fatalf("role=%v", sess.User.Additional)
	}
}

func TestChangeEmailEnumerationProtection(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, _ types.VerificationEmailData) error {
			return nil
		}
	})
	signUp(t, a, "exists@example.com")
	cookies := signUp(t, a, "changer@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/change-email", map[string]any{
		"newEmail": "exists@example.com",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enumeration response expected, got %d", resp.StatusCode)
	}
}

func TestChangeEmailSameEmailRejected(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.User.ChangeEmail.Enabled = true
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, _ types.VerificationEmailData) error {
			return nil
		}
	})
	cookies := signUp(t, a, "same@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/change-email", map[string]any{
		"newEmail": "same@example.com",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestChangeEmailDisabled(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "disabled@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/change-email", map[string]any{
		"newEmail": "new@example.com",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestChangeEmailVerificationFlow(t *testing.T) {
	var verifyToken string
	a := newTestAuth(func(c *auth.Config) {
		c.User.ChangeEmail.Enabled = true
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, data types.VerificationEmailData) error {
			verifyToken = data.Token
			return nil
		}
	})
	cookies := signUp(t, a, "verifyflow@example.com")
	verifyUserEmail(t, a, "verifyflow@example.com")

	resp, _ := doRequest(a, http.MethodPost, "/change-email", map[string]any{
		"newEmail": "verified-new@example.com",
	}, cookies)
	if resp.StatusCode != http.StatusOK || verifyToken == "" {
		t.Fatal("change email did not send verification")
	}

	resp, data := doRequest(a, http.MethodGet, "/verify-email?token="+verifyToken, nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify change email status=%d %s", resp.StatusCode, data)
	}
	var result types.VerifyEmailResponse
	_ = json.Unmarshal(data, &result)
	if result.User.Email != "verified-new@example.com" || !result.User.EmailVerified {
		t.Fatalf("user=%+v", result.User)
	}
}

func TestChangeEmailConfirmationFlow(t *testing.T) {
	var confirmToken, secondToken string
	a := newTestAuth(func(c *auth.Config) {
		c.User.ChangeEmail.Enabled = true
		c.User.ChangeEmail.SendChangeEmailConfirmation = func(_ context.Context, data types.ChangeEmailData) error {
			confirmToken = data.Token
			return nil
		}
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, data types.VerificationEmailData) error {
			secondToken = data.Token
			return nil
		}
	})
	cookies := signUp(t, a, "confirm@example.com")
	verifyUserEmail(t, a, "confirm@example.com")

	resp, _ := doRequest(a, http.MethodPost, "/change-email", map[string]any{
		"newEmail": "confirmed-new@example.com",
	}, cookies)
	if resp.StatusCode != http.StatusOK || confirmToken == "" {
		t.Fatal("change email confirmation not sent")
	}

	resp, _ = doRequest(a, http.MethodGet, "/verify-email?token="+confirmToken, nil, cookies)
	if resp.StatusCode != http.StatusOK || secondToken == "" {
		t.Fatal("second verification email not sent")
	}

	resp, data := doRequest(a, http.MethodGet, "/verify-email?token="+secondToken, nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final verify status=%d %s", resp.StatusCode, data)
	}
	var result types.VerifyEmailResponse
	_ = json.Unmarshal(data, &result)
	if result.User.Email != "confirmed-new@example.com" || !result.User.EmailVerified {
		t.Fatalf("user=%+v", result.User)
	}
}

func TestChangeEmailWithoutVerification(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.User.ChangeEmail.Enabled = true
		c.User.ChangeEmail.UpdateEmailWithoutVerification = true
	})
	cookies := signUp(t, a, "unverified@example.com")

	resp, _ := doRequest(a, http.MethodPost, "/change-email", map[string]any{
		"newEmail": "updated-unverified@example.com",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}

	resp, data := doRequest(a, http.MethodGet, "/get-session?disableCookieCache=true", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	if sess.User.Email != "updated-unverified@example.com" {
		t.Fatalf("email=%s", sess.User.Email)
	}
}

func TestChangePasswordRevokeOtherSessions(t *testing.T) {
	a := newTestAuth()
	signUp(t, a, "revokeother@example.com")
	resp1, _ := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "revokeother@example.com", "password": "password123",
	}, nil)
	cookies1 := resp1.Cookies()
	resp2, _ := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "revokeother@example.com", "password": "password123",
	}, nil)
	cookies2 := resp2.Cookies()

	revoke := true
	resp, data := doRequest(a, http.MethodPost, "/change-password", map[string]any{
		"currentPassword":     "password123",
		"newPassword":         "newpass12345",
		"revokeOtherSessions": revoke,
	}, cookies1)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	var result types.ChangePasswordResponse
	_ = json.Unmarshal(data, &result)
	if result.Token == nil || *result.Token == "" {
		t.Fatal("expected new session token in response")
	}

	resp, data = doRequest(a, http.MethodGet, "/get-session", nil, cookies2)
	if resp.StatusCode != http.StatusOK || string(data) != "null" {
		t.Fatalf("old session should be revoked, status=%d body=%s", resp.StatusCode, data)
	}
	resp, _ = doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "revokeother@example.com", "password": "newpass12345",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("sign-in with new password failed")
	}
}

func TestDeleteUserHooks(t *testing.T) {
	var before, after bool
	a := newTestAuth(func(c *auth.Config) {
		c.User.DeleteUser.BeforeDelete = func(_ context.Context, _ types.User) error {
			before = true
			return nil
		}
		c.User.DeleteUser.AfterDelete = func(_ context.Context, _ types.User) error {
			after = true
			return nil
		}
	})
	cookies := signUp(t, a, "hooks@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/delete-user", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusOK || !before || !after {
		t.Fatalf("status=%d before=%v after=%v", resp.StatusCode, before, after)
	}
}

func TestDeleteUserDisabled(t *testing.T) {
	disabled := false
	a := newTestAuth(func(c *auth.Config) {
		c.User.DeleteUser.Enabled = &disabled
	})
	cookies := signUp(t, a, "deldisabled@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/delete-user", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestDeleteUserResponseFormat(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "respfmt@example.com")
	resp, data := doRequest(a, http.MethodPost, "/delete-user", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	var result types.DeleteUserResponse
	_ = json.Unmarshal(data, &result)
	if !result.Success || result.Message != "User deleted" {
		t.Fatalf("result=%+v", result)
	}
}

func boolPtr(v bool) *bool { return &v }

func verifyUserEmail(t testingT, a *auth.Auth, email string) {
	t.Helper()
	token, err := jwt.SignHS256(testSecret, map[string]any{"email": email}, time.Hour)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	resp, data := doRequest(a, http.MethodGet, "/verify-email?token="+token, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify status=%d %s", resp.StatusCode, data)
	}
}
