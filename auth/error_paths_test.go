package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/jwt"
	"github.com/patrickkabwe/betterauth-go/store/memory"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestSignUpCreateUserFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Store = wrapStore("CreateUser") })
	resp, _ := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "Fail", "email": "fail@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestSignUpCreateSessionFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Store = wrapStore("CreateSession") })
	resp, _ := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "Fail", "email": "sessfail@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestUpdateUserStoreFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Store = wrapStore("UpdateUser") })
	cookies := signUp(t, a, "upfail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/update-user", map[string]any{
		"name": "X",
	}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestChangePasswordHashFails(t *testing.T) {
	mem := memory.New()
	a1 := newTestAuth(func(c *auth.Config) { c.Store = mem })
	cookies := signUp(t, a1, "chfail@example.com")
	a2 := newTestAuth(func(c *auth.Config) { c.Store = mem; c.Hasher = errorHasher{} })
	resp, _ := doRequest(a2, http.MethodPost, "/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "newpass123",
	}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestChangePasswordUpdatePasswordFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Store = wrapStore("UpdateAccountPassword") })
	cookies := signUp(t, a, "uppassfail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "newpass123",
	}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestChangePasswordRevokeSessionsFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Store = wrapStore("DeleteAllSessionsByUserID") })
	cookies := signUp(t, a, "changerevokefail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "newpass123", "revokeOtherSessions": true,
	}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestSetPasswordHashFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Hasher = errorHasher{} })
	cookies := oauthOnlySession(t, a)
	resp, _ := doRequest(a, http.MethodPost, "/set-password", map[string]any{
		"newPassword": "newpass123",
	}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestSetPasswordCreateAccountFails(t *testing.T) {
	fs := wrapStore("CreateAccount").(*failStore)
	a := newTestAuth(func(c *auth.Config) { c.Store = fs })
	cookies := oauthOnlyCookies(t, fs, "oauth-create-fail", "oauth-create-fail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/set-password", map[string]any{
		"newPassword": "newpass123",
	}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestSetPasswordUpdateAccountFails(t *testing.T) {
	fs := wrapStore("UpdateAccountPassword").(*failStore)
	a := newTestAuth(func(c *auth.Config) { c.Store = fs })
	cookies := oauthOnlyCookies(t, fs, "oauth-update-fail", "oauth-update-fail@example.com")
	now := time.Now()
	if err := fs.inner.CreateAccount(context.Background(), &types.Account{
		ID:         "credential-without-password",
		AccountID:  "oauth-update-fail",
		ProviderID: constants.ProviderCredential,
		UserID:     "oauth-update-fail",
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}
	resp, _ := doRequest(a, http.MethodPost, "/set-password", map[string]any{
		"newPassword": "newpass123",
	}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestListSessionsStoreFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Store = wrapStore("ListSessions") })
	cookies := signUp(t, a, "lsfail@example.com")
	resp, _ := doRequest(a, http.MethodGet, "/list-sessions", nil, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestListAccountsStoreFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Store = wrapStore("ListAccounts") })
	cookies := signUp(t, a, "lafail@example.com")
	resp, _ := doRequest(a, http.MethodGet, "/list-accounts", nil, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestRevokeSessionDeleteFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Store = wrapStore("DeleteSession") })
	cookies := signUp(t, a, "revdel@example.com")
	_, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var session types.SessionResponse
	if err := json.Unmarshal(data, &session); err != nil {
		t.Fatal(err)
	}
	resp, _ := doRequest(a, http.MethodPost, "/revoke-session", map[string]any{
		"token": session.Session.Token,
	}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestRevokeSessionsDeleteFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Store = wrapStore("DeleteAllSessionsByUserID") })
	cookies := signUp(t, a, "revallfail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/revoke-sessions", nil, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestRevokeOtherSessionsDeleteFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Store = wrapStore("DeleteSessionsByUserID") })
	cookies := signUp(t, a, "revotherfail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/revoke-other-sessions", nil, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestUpdateSessionStoreFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Store = wrapStore("UpdateSession") })
	cookies := signUp(t, a, "usfail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/update-session", map[string]any{
		"userAgent": "test-agent",
	}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestRevokeSessionInvalidBody(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "rvfail@example.com")
	resp, _ := doRawRequest(a, http.MethodPost, "/revoke-session", "{", cookies, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestUnlinkAccountInvalidBody(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "ulfail@example.com")
	resp, _ := doRawRequest(a, http.MethodPost, "/unlink-account", "not-json", cookies, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestUnlinkAccountDeleteFails(t *testing.T) {
	allowUnlinkingAll := true
	a := newTestAuth(func(c *auth.Config) {
		c.Store = wrapStore("DeleteAccount")
		c.Account.AccountLinking.AllowUnlinkingAll = allowUnlinkingAll
	})
	cookies := signUp(t, a, "unlink-delete@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/unlink-account", map[string]any{
		"providerId": "credential",
	}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestSendVerificationInvalidBody(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, _ types.VerificationEmailData) error {
			return nil
		}
	})
	resp, _ := doRawRequest(a, http.MethodPost, "/send-verification-email", "{", nil, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestSendVerificationSendFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, _ types.VerificationEmailData) error {
			return berrors.ErrSmtpDown
		}
	})
	signUp(t, a, "sendfail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/send-verification-email", map[string]any{
		"email": "sendfail@example.com",
	}, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestChangeEmailInvalidBody(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, _ types.VerificationEmailData) error {
			return nil
		}
	})
	cookies := signUp(t, a, "cefail@example.com")
	resp, _ := doRawRequest(a, http.MethodPost, "/change-email", "{bad", cookies, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestVerifyPasswordNoCredential(t *testing.T) {
	a := newTestAuth()
	cookies := oauthOnlySession(t, a)
	resp, _ := doRequest(a, http.MethodPost, "/verify-password", map[string]any{
		"password": "anything",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestChangePasswordNewPasswordTooShort(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "cpshort@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "short",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestSignUpCreateAccountFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Store = wrapStore("CreateAccount") })
	resp, _ := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "Acc", "email": "accfail@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestRequestPasswordResetCreateVerificationFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Store = wrapStore("CreateVerification")
		c.EmailAndPassword.SendResetPassword = func(_ context.Context, _ types.ResetPasswordEmailData) error {
			return nil
		}
	})
	signUp(t, a, "rpverifycreate@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/request-password-reset", map[string]any{
		"email": "rpverifycreate@example.com",
	}, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestRequestPasswordResetSendFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.EmailAndPassword.SendResetPassword = func(_ context.Context, _ types.ResetPasswordEmailData) error {
			return berrors.ErrSmtpDown
		}
	})
	signUp(t, a, "rpsendfail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/request-password-reset", map[string]any{
		"email": "rpsendfail@example.com",
	}, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestResetPasswordHashFails(t *testing.T) {
	var resetData types.ResetPasswordEmailData
	mem := memory.New()
	a1 := newTestAuth(func(c *auth.Config) {
		c.Store = mem
		c.EmailAndPassword.SendResetPassword = func(_ context.Context, data types.ResetPasswordEmailData) error {
			resetData = data
			return nil
		}
	})
	signUp(t, a1, "rphash@example.com")
	_, _ = doRequest(a1, http.MethodPost, "/request-password-reset", map[string]any{
		"email": "rphash@example.com",
	}, nil)
	a2 := newTestAuth(func(c *auth.Config) { c.Store = mem; c.Hasher = errorHasher{} })
	resp, _ := doRequest(a2, http.MethodPost, "/reset-password", map[string]any{
		"token": resetData.Token, "newPassword": "newpassword1",
	}, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	resp, _ = doRequest(a1, http.MethodPost, "/reset-password", map[string]any{
		"token": resetData.Token, "newPassword": "newpassword1",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("reused token status=%d", resp.StatusCode)
	}
}

func TestResetPasswordCreateAccountFails(t *testing.T) {
	var resetData types.ResetPasswordEmailData
	fs := wrapStore("CreateAccount").(*failStore)
	a := newTestAuth(func(c *auth.Config) {
		c.Store = fs
		c.EmailAndPassword.SendResetPassword = func(_ context.Context, data types.ResetPasswordEmailData) error {
			resetData = data
			return nil
		}
	})
	_ = oauthOnlyCookies(t, fs, "reset-create-account-fail", "reset-create-account-fail@example.com")
	_, _ = doRequest(a, http.MethodPost, "/request-password-reset", map[string]any{
		"email": "reset-create-account-fail@example.com",
	}, nil)
	resp, _ := doRequest(a, http.MethodPost, "/reset-password", map[string]any{
		"token": resetData.Token, "newPassword": "newpassword1",
	}, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestResetPasswordUpdateAccountFails(t *testing.T) {
	var resetData types.ResetPasswordEmailData
	a := newTestAuth(func(c *auth.Config) {
		c.Store = wrapStore("UpdateAccountPassword")
		c.EmailAndPassword.SendResetPassword = func(_ context.Context, data types.ResetPasswordEmailData) error {
			resetData = data
			return nil
		}
	})
	signUp(t, a, "rpupdateaccountfail@example.com")
	_, _ = doRequest(a, http.MethodPost, "/request-password-reset", map[string]any{
		"email": "rpupdateaccountfail@example.com",
	}, nil)
	resp, _ := doRequest(a, http.MethodPost, "/reset-password", map[string]any{
		"token": resetData.Token, "newPassword": "newpassword1",
	}, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestResetPasswordTooLong(t *testing.T) {
	var resetData types.ResetPasswordEmailData
	a := newTestAuth(func(c *auth.Config) {
		c.EmailAndPassword.SendResetPassword = func(_ context.Context, data types.ResetPasswordEmailData) error {
			resetData = data
			return nil
		}
	})
	signUp(t, a, "rplong@example.com")
	_, _ = doRequest(a, http.MethodPost, "/request-password-reset", map[string]any{
		"email": "rplong@example.com",
	}, nil)
	long := strings.Repeat("a", 129)
	resp, _ := doRequest(a, http.MethodPost, "/reset-password", map[string]any{
		"token": resetData.Token, "newPassword": long,
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestResetPasswordRevokeSessionsFails(t *testing.T) {
	var resetData types.ResetPasswordEmailData
	a := newTestAuth(func(c *auth.Config) {
		c.Store = wrapStore("DeleteAllSessionsByUserID")
		c.EmailAndPassword.RevokeSessionsOnPasswordReset = true
		c.EmailAndPassword.SendResetPassword = func(_ context.Context, data types.ResetPasswordEmailData) error {
			resetData = data
			return nil
		}
	})
	signUp(t, a, "rprevoke@example.com")
	_, _ = doRequest(a, http.MethodPost, "/request-password-reset", map[string]any{
		"email": "rprevoke@example.com",
	}, nil)
	resp, _ := doRequest(a, http.MethodPost, "/reset-password", map[string]any{
		"token": resetData.Token, "newPassword": "newpassword1",
	}, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestDeleteUserWrongPassword(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "delwrong@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/delete-user", map[string]any{
		"password": "wrongpassword",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestDeleteUserDeleteUserFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Store = wrapStore("DeleteUser") })
	cookies := signUp(t, a, "deluserfail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/delete-user", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestDeleteUserDeleteSessionsFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Store = wrapStore("DeleteAllSessionsByUserID") })
	cookies := signUp(t, a, "delsessionsfail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/delete-user", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestDeleteUserAfterDeleteFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.User.DeleteUser.AfterDelete = func(_ context.Context, _ types.User) error {
			return berrors.ErrInjected
		}
	})
	cookies := signUp(t, a, "afterdeletefail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/delete-user", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestDeleteUserVerificationCreateFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Store = wrapStore("CreateVerification")
		c.User.DeleteUser.SendDeleteAccountURL = func(_ context.Context, _ types.User, _, _ string) error {
			return nil
		}
	})
	cookies := signUp(t, a, "delcreateverificationfail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/delete-user", map[string]any{}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestDeleteUserVerificationSendFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.User.DeleteUser.SendDeleteAccountURL = func(_ context.Context, _ types.User, _, _ string) error {
			return berrors.ErrSmtpDown
		}
	})
	cookies := signUp(t, a, "delsendfail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/delete-user", map[string]any{}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestDeleteUserTokenDeleteUserFails(t *testing.T) {
	fs := wrapStore("DeleteUser").(*failStore)
	a := newTestAuth(func(c *auth.Config) { c.Store = fs })
	cookies := signUp(t, a, "deltokdeletefail@example.com")
	resp, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session status=%d", resp.StatusCode)
	}
	var sess types.SessionResponse
	if err := json.Unmarshal(data, &sess); err != nil {
		t.Fatal(err)
	}
	token := createDeleteVerificationForStore(t, fs, "delete-user-fails", sess.User.ID)
	resp, _ = doRequest(a, http.MethodPost, "/delete-user", map[string]any{
		"token": token,
	}, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestDeleteUserCallbackVerificationDeleteFails(t *testing.T) {
	fs := wrapStore("DeleteVerificationByIdentifier").(*failStore)
	a := newTestAuth(func(c *auth.Config) { c.Store = fs })
	cookies := signUp(t, a, "delcbverificationfail@example.com")
	resp, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session status=%d", resp.StatusCode)
	}
	var sess types.SessionResponse
	if err := json.Unmarshal(data, &sess); err != nil {
		t.Fatal(err)
	}
	token := createDeleteVerificationForStore(t, fs, "delete-verification-fails", sess.User.ID)
	resp, _ = doRequest(a, http.MethodGet, "/delete-user/callback?token="+token, nil, cookies)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestVerifyEmailUpdateFails(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) { c.Store = wrapStore("UpdateUser") })
	signUp(t, a, "verfail@example.com")
	token, _ := jwt.SignHS256(testSecret, map[string]any{"email": "verfail@example.com"}, time.Hour)
	resp, _ := doRequest(a, http.MethodGet, "/verify-email?token="+token, nil, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestSetPasswordTooShort(t *testing.T) {
	a := newTestAuth()
	cookies := oauthOnlySession(t, a)
	resp, _ := doRequest(a, http.MethodPost, "/set-password", map[string]any{
		"newPassword": "short",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestDontRememberSessionCreation(t *testing.T) {
	a := newTestAuth()
	resp, _ := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "DR", "email": "dr@example.com", "password": "password123",
		"rememberMe": false,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("sign-up failed")
	}
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == "better-auth.dont_remember" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected dont_remember on sign-up")
	}
}

func oauthOnlyCookies(t testingT, fs *failStore, userID string, email string) []*http.Cookie {
	t.Helper()
	now := time.Now()
	if err := fs.inner.CreateUser(context.Background(), &types.User{
		ID: userID, Name: "OAuth User", Email: email,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := fs.inner.CreateAccount(context.Background(), &types.Account{
		ID: "github-" + userID, AccountID: "github-" + userID, ProviderID: "github",
		UserID: userID, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}
	token := "session-" + userID
	if err := fs.inner.CreateSession(context.Background(), &types.Session{
		ID: "session-" + userID, Token: token, UserID: userID,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return []*http.Cookie{sessionCookie(token)}
}

func createDeleteVerificationForStore(t testingT, fs *failStore, token string, userID string) string {
	t.Helper()
	now := time.Now()
	if err := fs.inner.CreateVerification(context.Background(), &types.Verification{
		ID: "verification-" + token, Identifier: "delete-account:" + token, Value: userID,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("create verification: %v", err)
	}
	return token
}
