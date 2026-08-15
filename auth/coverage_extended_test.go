package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/internal/cookie"
	"github.com/patrickkabwe/betterauth-go/internal/jwt"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/store/memory"
	"github.com/patrickkabwe/betterauth-go/types"
)

const testSecret = "test-secret-key-for-cookie-signing"

func sessionCookie(token string) *http.Cookie {
	return &http.Cookie{
		Name:  "better-auth.session_token",
		Value: cookie.SignCookie(token, testSecret),
	}
}

func oauthOnlySession(t testingT, a *auth.Auth) []*http.Cookie {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	st := a.Store().(*memory.Store)
	_ = st.CreateUser(ctx, &types.User{
		ID: "oauth1", Name: "OAuth User", Email: "oauth@example.com",
		CreatedAt: now, UpdatedAt: now,
	})
	_ = st.CreateAccount(ctx, &types.Account{
		ID: "gh1", AccountID: "gh-ext", ProviderID: "github",
		UserID: "oauth1", Scope: "read,write", CreatedAt: now, UpdatedAt: now,
	})
	token := "oauth-session-token"
	_ = st.CreateSession(ctx, &types.Session{
		ID: "s-oauth", Token: token, UserID: "oauth1",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	})
	return []*http.Cookie{sessionCookie(token)}
}

func doRawRequest(a *auth.Auth, method, path string, body string, cookies []*http.Cookie, headers map[string]string) (*http.Response, []byte) {
	var reader io.Reader
	if body != "" {
		reader = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, "http://example.com/api/auth"+path, reader)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path
		if i := strings.Index(path, "?"); i >= 0 {
			r.URL.RawQuery = path[i+1:]
			clean = path[:i]
		}
		r.URL.Path = clean
		a.Handler().ServeHTTP(w, r)
	}).ServeHTTP(rr, req)
	resp := rr.Result()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

func TestPasswordLengthValidation(t *testing.T) {
	a := newTestAuth()
	long := strings.Repeat("a", 129)
	resp, _ := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "Long", "email": "long@example.com", "password": long,
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("expected password too long error")
	}

	resp, _ = doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "", "email": "noname@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("expected name required error")
	}
}

func TestSignInBranches(t *testing.T) {
	a := newTestAuth()
	resp, _ := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "missing@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("unknown email should fail")
	}

	signUp(t, a, "nocred@example.com")
	ctx := context.Background()
	st := a.Store().(*memory.Store)
	user, _ := st.FindUserByEmail(ctx, "nocred@example.com")
	accs, _ := st.ListAccountsByUserID(ctx, user.ID)
	for _, acc := range accs {
		_ = st.DeleteAccount(ctx, acc.ID)
	}

	resp, _ = doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "nocred@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("no credential account should fail sign-in")
	}
}

func TestSignInCallbackURL(t *testing.T) {
	a := newTestAuth()
	signUp(t, a, "cb@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "cb@example.com", "password": "password123",
		"callbackURL": "http://localhost:3000/dashboard",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("sign-in failed")
	}
	if resp.Header.Get("Location") != "http://localhost:3000/dashboard" {
		t.Fatal("expected Location header")
	}
}

func TestRememberMeFalse(t *testing.T) {
	a := newTestAuth()
	rm := false
	signUp(t, a, "remember@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "remember@example.com", "password": "password123",
		"rememberMe": rm,
	}, nil)
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == "better-auth.dont_remember" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected dont_remember cookie")
	}
}

func TestSessionRefreshOnGetSession(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "refresh@example.com")
	ctx := context.Background()
	st := a.Store().(*memory.Store)
	_, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	// Force refresh: ExpiresAt near expiry makes update threshold elapsed.
	near := time.Now().Add(time.Hour)
	_, _ = st.UpdateSession(ctx, sess.Session.Token, store.SessionUpdate{ExpiresAt: &near})

	resp, _ := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("get-session failed")
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "expired@example.com")
	ctx := context.Background()
	st := a.Store().(*memory.Store)
	_, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	past := time.Now().Add(-time.Hour)
	_, _ = st.UpdateSession(ctx, sess.Session.Token, store.SessionUpdate{ExpiresAt: &past})

	resp, _ := doRequest(a, http.MethodGet, "/list-sessions", nil, cookies)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired session should be unauthorized, got %d", resp.StatusCode)
	}
}

func TestChangePasswordRevokeOthers(t *testing.T) {
	a := newTestAuth()
	signUp(t, a, "revokepw@example.com")
	cookies1, _ := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "revokepw@example.com", "password": "password123",
	}, nil)
	cookies2, _ := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "revokepw@example.com", "password": "password123",
	}, nil)
	_ = cookies2

	revoke := true
	resp, _ := doRequest(a, http.MethodPost, "/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "newpass123",
		"revokeOtherSessions": revoke,
	}, cookies1.Cookies())
	if resp.StatusCode != http.StatusOK {
		t.Fatal("change password failed")
	}
}

func TestChangePasswordWrongCurrent(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "wrongpw@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/change-password", map[string]any{
		"currentPassword": "wrong", "newPassword": "newpass123",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("expected invalid password")
	}
}

func TestSetPasswordOAuthUser(t *testing.T) {
	a := newTestAuth()
	cookies := oauthOnlySession(t, a)
	resp, _ := doRequest(a, http.MethodPost, "/set-password", map[string]any{
		"newPassword": "newpassword1",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("set password for oauth user failed")
	}
}

func TestDeleteUserWithToken(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "deltok@example.com")
	resp, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)

	token := createDeleteVerificationToken(t, a, sess.User.ID)
	resp, _ = doRequest(a, http.MethodPost, "/delete-user", map[string]any{
		"token": token,
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("delete with token failed")
	}
}

func TestDeleteUserSendEmail(t *testing.T) {
	var sent bool
	a := newTestAuth(func(c *auth.Config) {
		c.User.SendDeleteAccountURL = func(_ context.Context, _ types.User, _, _ string) error {
			sent = true
			return nil
		}
	})
	cookies := signUp(t, a, "delmail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/delete-user", map[string]any{}, cookies)
	if resp.StatusCode != http.StatusOK || !sent {
		t.Fatal("expected delete confirmation email")
	}
}

func TestDeleteUserInvalidToken(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "badtok@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/delete-user", map[string]any{
		"token": "invalid",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("expected invalid token")
	}
}

func TestDeleteUserCallbackNoCallback(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "delcb2@example.com")
	resp, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)

	token := createDeleteVerificationToken(t, a, sess.User.ID)
	resp, _ = doRequest(a, http.MethodGet, "/delete-user/callback?token="+token, nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete callback without redirect failed: %d %s", resp.StatusCode, data)
	}
}

func TestDeleteUserCallbackInvalidToken(t *testing.T) {
	a := newTestAuth()
	resp, _ := doRequest(a, http.MethodGet, "/delete-user/callback?token=bad", nil, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("expected invalid token error")
	}
}

func TestChangeEmailNotEnabled(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "nochange@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/change-email", map[string]any{
		"newEmail": "x@example.com",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("change email should fail when verification disabled")
	}
}

func TestVerifyEmailRedirect(t *testing.T) {
	a := newTestAuth()
	signUp(t, a, "redirect@example.com")
	token, _ := jwt.SignHS256(testSecret, map[string]any{"email": "redirect@example.com"}, time.Hour)
	resp, _ := doRequest(a, http.MethodGet, "/verify-email?token="+token+"&callbackURL=http://localhost:3000/ok", nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatal("expected redirect on verify")
	}
}

func TestVerifyEmailExpiredNoCallback(t *testing.T) {
	a := newTestAuth()
	token, _ := jwt.SignHS256(testSecret, map[string]any{"email": "a@b.com"}, -time.Hour)
	resp, _ := doRequest(a, http.MethodGet, "/verify-email?token="+token, nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestVerifyEmailUserNotFound(t *testing.T) {
	a := newTestAuth()
	token, _ := jwt.SignHS256(testSecret, map[string]any{"email": "ghost@example.com"}, time.Hour)
	resp, _ := doRequest(a, http.MethodGet, "/verify-email?token="+token+"&callbackURL=http://localhost:3000/cb", nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatal("expected redirect with error")
	}
}

func TestUpdateUserImage(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "img@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/update-user", map[string]any{
		"image": "http://example.com/avatar.png",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("update image failed")
	}

	resp, _ = doRequest(a, http.MethodPost, "/update-user", map[string]any{}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("empty update should fail")
	}
}

func TestUnlinkSecondaryAccount(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "multi@example.com")
	ctx := context.Background()
	st := a.Store().(*memory.Store)
	resp, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	now := time.Now()
	_ = st.CreateAccount(ctx, &types.Account{
		ID: "gh2", AccountID: "gh-ext", ProviderID: "github",
		UserID: sess.User.ID, Scope: "repo", CreatedAt: now, UpdatedAt: now,
	})

	resp, _ = doRequest(a, http.MethodPost, "/unlink-account", map[string]any{
		"providerId": "github",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("unlink github failed")
	}
}

func TestUnlinkAccountNotFound(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "unlinknf@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/unlink-account", map[string]any{
		"providerId": "twitter",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("unlink missing account should fail")
	}
}

func TestVerifyPasswordWrong(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "vwrong@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/verify-password", map[string]any{
		"password": "wrongpassword",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("wrong password should fail")
	}
}

func TestResetPasswordCallbackInvalid(t *testing.T) {
	a := newTestAuth()
	resp, _ := doRequest(a, http.MethodGet, "/reset-password/badtoken", nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("invalid reset token should redirect, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "http://localhost:8080/api/auth/error?error=INVALID_TOKEN" {
		t.Fatalf("location=%q", got)
	}
}

func TestResetPasswordTooShort(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.EmailAndPassword.SendResetPassword = func(_ context.Context, _ types.ResetPasswordEmailData) error {
			return nil
		}
	})
	signUp(t, a, "short@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/reset-password", map[string]any{
		"token": "nope", "newPassword": "short",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("short password should fail")
	}
}

func TestDuplicateSignUpFailsWhenAutoSignIn(t *testing.T) {
	a := newTestAuth()
	signUp(t, a, "dupfail@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "Dup", "email": "dupfail@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", resp.StatusCode)
	}
}

func TestErrorPageDefaultCode(t *testing.T) {
	a := newTestAuth()
	resp, data := doRequest(a, http.MethodGet, "/error", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(data), "UNKNOWN") {
		t.Fatal("error page default code failed")
	}
}

func TestParseJSONInvalidBody(t *testing.T) {
	a := newTestAuth()
	resp, _ := doRawRequest(a, http.MethodPost, "/sign-in/email", "{bad json", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid json status=%d", resp.StatusCode)
	}
}

func TestClientIPRealIP(t *testing.T) {
	a := newTestAuth()
	resp, _ := doRawRequest(a, http.MethodPost, "/sign-up/email",
		`{"name":"RealIP","email":"realip@example.com","password":"password123"}`,
		nil, map[string]string{"X-Real-IP": "198.51.100.1"})
	if resp.StatusCode != http.StatusOK {
		t.Fatal("sign-up failed")
	}
	_, data := doRequest(a, http.MethodGet, "/get-session", nil, resp.Cookies())
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	if sess.Session.IPAddress != "198.51.100.1" {
		t.Fatalf("ip=%q", sess.Session.IPAddress)
	}
}

func TestClientIPForwarded(t *testing.T) {
	a := newTestAuth()
	resp, _ := doRawRequest(a, http.MethodPost, "/sign-up/email",
		`{"name":"IP","email":"ip@example.com","password":"password123"}`,
		nil, map[string]string{"X-Forwarded-For": "203.0.113.1, 10.0.0.1"})
	if resp.StatusCode != http.StatusOK {
		t.Fatal("sign-up with forwarded IP failed")
	}
	cookies := resp.Cookies()
	resp, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	if sess.Session.IPAddress != "203.0.113.1" {
		t.Fatalf("ip=%q", sess.Session.IPAddress)
	}
}

func TestRevokeSessionWrongToken(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "revwrong@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/revoke-session", map[string]any{
		"token": "nonexistent-token",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("revoke unknown token still returns ok")
	}
}

func TestPasswordResetCreatesCredentialForOAuthUser(t *testing.T) {
	var resetData types.ResetPasswordEmailData
	a := newTestAuth(func(c *auth.Config) {
		c.EmailAndPassword.SendResetPassword = func(_ context.Context, data types.ResetPasswordEmailData) error {
			resetData = data
			return nil
		}
		c.EmailAndPassword.RevokeSessionsOnPasswordReset = true
	})
	cookies := oauthOnlySession(t, a)
	_ = cookies
	resp, _ := doRequest(a, http.MethodPost, "/request-password-reset", map[string]any{
		"email": "oauth@example.com",
	}, nil)
	if resp.StatusCode != http.StatusOK || resetData.Token == "" {
		t.Fatal("reset request failed")
	}
	resp, _ = doRequest(a, http.MethodPost, "/reset-password", map[string]any{
		"token": resetData.Token, "newPassword": "oauthnewpass1",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("reset for oauth user failed")
	}
}

func TestResetPasswordCallbackWithRedirect(t *testing.T) {
	var resetData types.ResetPasswordEmailData
	a := newTestAuth(func(c *auth.Config) {
		c.EmailAndPassword.SendResetPassword = func(_ context.Context, data types.ResetPasswordEmailData) error {
			resetData = data
			return nil
		}
	})
	signUp(t, a, "rpcb@example.com")
	_, _ = doRequest(a, http.MethodPost, "/request-password-reset", map[string]any{
		"email": "rpcb@example.com", "redirectTo": "http://localhost:3000/reset",
	}, nil)
	resp, _ := doRequest(a, http.MethodGet, "/reset-password/"+resetData.Token+"?callbackURL=http://localhost:3000/done", nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatal("reset callback redirect failed")
	}
}

func TestResetPasswordCallbackRequiresRedirect(t *testing.T) {
	var resetData types.ResetPasswordEmailData
	a := newTestAuth(func(c *auth.Config) {
		c.EmailAndPassword.SendResetPassword = func(_ context.Context, data types.ResetPasswordEmailData) error {
			resetData = data
			return nil
		}
	})
	signUp(t, a, "rpcb-missing@example.com")
	_, _ = doRequest(a, http.MethodPost, "/request-password-reset", map[string]any{
		"email": "rpcb-missing@example.com",
	}, nil)
	resp, _ := doRequest(a, http.MethodGet, "/reset-password/"+resetData.Token, nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "http://localhost:8080/api/auth/error?error=INVALID_TOKEN" {
		t.Fatalf("location=%q", got)
	}
}

func TestGetSessionExpiredReturnsNull(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "expnull@example.com")
	ctx := context.Background()
	st := a.Store().(*memory.Store)
	_, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	past := time.Now().Add(-time.Hour)
	_, _ = st.UpdateSession(ctx, sess.Session.Token, store.SessionUpdate{ExpiresAt: &past})
	resp, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	if resp.StatusCode != http.StatusOK || string(data) != "null" {
		t.Fatalf("expected null, got %s", data)
	}
}

func TestDeleteUserCallbackRedirectOnError(t *testing.T) {
	a := newTestAuth()
	resp, _ := doRequest(a, http.MethodGet, "/delete-user/callback?token=bad&callbackURL=http://localhost:3000/err", nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatal("expected redirect on invalid delete token")
	}
}

func TestListAccountsWithScopes(t *testing.T) {
	a := newTestAuth()
	cookies := oauthOnlySession(t, a)
	_, data := doRequest(a, http.MethodGet, "/list-accounts", nil, cookies)
	var accounts []types.AccountResponse
	_ = json.Unmarshal(data, &accounts)
	if len(accounts) != 1 || len(accounts[0].Scopes) != 2 {
		t.Fatalf("scopes=%v", accounts)
	}
}
