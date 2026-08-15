package auth_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestSendVerificationEmailDoesNotSendToVerifiedUserWithoutSession(t *testing.T) {
	sent := false
	a := newTestAuth(func(c *auth.Config) {
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, _ types.VerificationEmailData) error {
			sent = true
			return nil
		}
	})
	signUp(t, a, "verified-send@example.com")
	verified := true
	user, err := a.Store().FindUserByEmail(context.Background(), "verified-send@example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Store().UpdateUser(context.Background(), user.ID, store.UserUpdate{EmailVerified: &verified})
	if err != nil {
		t.Fatal(err)
	}

	resp, data := doRequest(a, http.MethodPost, "/send-verification-email", map[string]any{
		"email": "verified-send@example.com",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
	if sent {
		t.Fatal("verification email was sent to an already verified user")
	}
}

func TestSendVerificationEmailRejectsSessionEmailMismatch(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, _ types.VerificationEmailData) error {
			return nil
		}
	})
	cookies := signUp(t, a, "session-owner@example.com")

	resp, _ := doRequest(a, http.MethodPost, "/send-verification-email", map[string]any{
		"email": "different@example.com",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestSendVerificationEmailRejectsVerifiedSession(t *testing.T) {
	sent := false
	a := newTestAuth(func(c *auth.Config) {
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, _ types.VerificationEmailData) error {
			sent = true
			return nil
		}
	})
	cookies := signUp(t, a, "verified-session@example.com")
	verified := true
	user, err := a.Store().FindUserByEmail(context.Background(), "verified-session@example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Store().UpdateUser(context.Background(), user.ID, store.UserUpdate{EmailVerified: &verified})
	if err != nil {
		t.Fatal(err)
	}

	resp, _ := doRequest(a, http.MethodPost, "/send-verification-email", map[string]any{
		"email": "verified-session@example.com",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if sent {
		t.Fatal("verification email was sent for an already verified session")
	}
}
