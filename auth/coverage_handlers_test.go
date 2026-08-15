package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/patrickkabwe/betterauth-go/auth"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/store/memory"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestValidationErrors(t *testing.T) {
	a := newTestAuth()
	resp, _ := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "X", "email": "bad", "password": "short",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid email status=%d", resp.StatusCode)
	}

	resp, _ = doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "X", "email": "good@example.com", "password": "",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("empty password")
	}

	a2 := newTestAuth(func(c *auth.Config) { c.DisableSignUp = true })
	resp, _ = doRequest(a2, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "X", "email": "x@y.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("disabled sign-up")
	}
}

func TestErrorPage(t *testing.T) {
	a := newTestAuth()
	resp, data := doRequest(a, http.MethodGet, "/error?error=INVALID_TOKEN", nil, nil)
	if resp.StatusCode != http.StatusOK || len(data) == 0 {
		t.Fatal("error page failed")
	}
}

func TestRevokeSessionAndSessions(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "revoke@example.com")

	resp, data := doRequest(a, http.MethodGet, "/list-sessions", nil, cookies)
	var sessions []types.Session
	_ = json.Unmarshal(data, &sessions)

	resp, _ = doRequest(a, http.MethodPost, "/revoke-session", map[string]any{
		"token": sessions[0].Token,
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("revoke session failed")
	}

	cookies = signUp(t, a, "revoke-all@example.com")
	resp, _ = doRequest(a, http.MethodPost, "/revoke-sessions", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("revoke sessions failed")
	}
}

func TestChangeEmail(t *testing.T) {
	var sent types.VerificationEmailData
	a := newTestAuth(func(c *auth.Config) {
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, data types.VerificationEmailData) error {
			sent = data
			return nil
		}
	})
	cookies := signUp(t, a, "change@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/change-email", map[string]any{
		"newEmail": "new@example.com",
	}, cookies)
	if resp.StatusCode != http.StatusOK || sent.Token == "" {
		t.Fatal("change email failed")
	}
}

func TestVerifyEmailRedirectErrors(t *testing.T) {
	a := newTestAuth()
	resp, _ := doRequest(a, http.MethodGet, "/verify-email?token=bad&callbackURL=http://localhost:3000/cb", nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect status=%d", resp.StatusCode)
	}
}

func TestDeleteUserCallback(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "delcb@example.com")
	resp, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)

	token := createDeleteVerificationToken(t, a, sess.User.ID)
	resp, _ = doRequest(a, http.MethodGet, "/delete-user/callback?token="+token+"&callbackURL=http://localhost:3000/done", nil, cookies)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("delete callback status=%d", resp.StatusCode)
	}
}

func TestUnauthorizedRoutes(t *testing.T) {
	a := newTestAuth()
	resp, _ := doRequest(a, http.MethodGet, "/list-sessions", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestResetPasswordInvalidToken(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.EmailAndPassword.SendResetPassword = func(_ context.Context, _ types.ResetPasswordEmailData) error {
			return nil
		}
	})
	resp, _ := doRequest(a, http.MethodPost, "/reset-password", map[string]any{
		"token": "nope", "newPassword": "longpassword1",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestUpdateUserValidation(t *testing.T) {
	a := newTestAuth()
	cookies := signUp(t, a, "val@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/update-user", map[string]any{
		"email": "hack@example.com",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("email update should fail")
	}
}

func TestAuthAccessors(t *testing.T) {
	a := newTestAuth()
	if a.Store() == nil || a.BasePath() != "/api/auth" {
		t.Fatal("accessors failed")
	}
}

func TestRequireEmailVerificationSendOnSignIn(t *testing.T) {
	var sent bool
	a := newTestAuth(func(c *auth.Config) {
		c.EmailAndPassword.RequireEmailVerification = true
		c.EmailVerification.SendOnSignIn = true
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, _ types.VerificationEmailData) error {
			sent = true
			return nil
		}
	})
	signUp(t, a, "sendonsignin@example.com")
	doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "sendonsignin@example.com", "password": "password123",
	}, nil)
	if !sent {
		t.Fatal("expected verification email on sign-in")
	}
}

func TestDuplicateSignUpWithRequireVerification(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.EmailAndPassword.RequireEmailVerification = true
	})
	signUp(t, a, "dupver@example.com")
	existing, err := a.Store().FindUserByEmail(context.Background(), "dupver@example.com")
	if err != nil {
		t.Fatal(err)
	}
	storedImage := "https://example.com/stored.png"
	storedImagePtr := &storedImage
	storedName := "Stored Name"
	verified := true
	if _, err := a.Store().UpdateUser(context.Background(), existing.ID, store.UserUpdate{
		Name:          &storedName,
		Image:         &storedImagePtr,
		EmailVerified: &verified,
	}); err != nil {
		t.Fatal(err)
	}

	requestImage := "https://example.com/request.png"
	resp, data := doRequest(a, http.MethodPost, "/sign-up/email", map[string]any{
		"name": "Requested Name", "email": "DupVer@Example.com", "password": "password123", "image": requestImage,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("enumeration response expected")
	}
	var result types.SignUpResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.User.Name != "Requested Name" || result.User.Email != "dupver@example.com" || result.User.EmailVerified {
		t.Fatalf("user=%+v", result.User)
	}
	if result.User.Image == nil || *result.User.Image != requestImage {
		t.Fatalf("image=%v", result.User.Image)
	}
}

func TestMemoryStoreNotFound(t *testing.T) {
	s := memory.New()
	_, err := s.FindUserByEmail(context.Background(), "missing@example.com")
	if err != berrors.ErrNotFound {
		t.Fatal("expected not found")
	}
}

func TestSendVerificationUnknownEmail(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, _ types.VerificationEmailData) error {
			return nil
		}
	})
	resp, _ := doRequest(a, http.MethodPost, "/send-verification-email", map[string]any{
		"email": "unknown@example.com",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatal("should return ok for unknown email")
	}
}

func TestSendVerificationNotEnabled(t *testing.T) {
	a := newTestAuth()
	resp, _ := doRequest(a, http.MethodPost, "/send-verification-email", map[string]any{
		"email": "a@b.com",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("expected not enabled error")
	}
}
