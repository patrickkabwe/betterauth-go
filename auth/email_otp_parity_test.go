package auth_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestEmailOTPPluginCheckAcceptsChangeEmailType(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{})}
	})
	now := time.Now()
	err := a.Store().CreateUser(context.Background(), &types.User{
		ID: "email-otp-change", Name: "Change Email", Email: "otp-change@example.com",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = a.CreateVerification(context.Background(), constants.VerificationEmailOTP+constants.EmailOTPTypeEmailChange+":otp-change@example.com", "123456", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	resp, data := doRequest(a, http.MethodPost, "/email-otp/check-verification-otp", map[string]any{
		"email": "otp-change@example.com", "otp": "123456", "type": "change-email",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
}

func TestEmailOTPPluginSendVerificationOTPSignInTypeCanSignIn(t *testing.T) {
	var sentEmail string
	var sentOTP string
	var sentType string
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{
			SendOTP: func(_ context.Context, email string, otp string, typ string) error {
				sentEmail = email
				sentOTP = otp
				sentType = typ
				return nil
			},
		})}
	})
	now := time.Now()
	err := a.Store().CreateUser(context.Background(), &types.User{
		ID:            "email-otp-sign-in",
		Name:          "Sign In",
		Email:         "sign-in@example.com",
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, data := doRequest(a, http.MethodPost, "/email-otp/send-verification-otp", map[string]any{
		"email": "SIGN-IN@example.com",
		"type":  "sign-in",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send status=%d body=%s", resp.StatusCode, data)
	}
	if sentEmail != "sign-in@example.com" {
		t.Fatalf("sent email %q", sentEmail)
	}
	if sentType != "sign-in" {
		t.Fatalf("sent type %q", sentType)
	}
	if sentOTP == "" {
		t.Fatal("expected OTP to be sent")
	}

	resp, data = doRequest(a, http.MethodPost, "/sign-in/email-otp", map[string]any{
		"email": "sign-in@example.com",
		"otp":   sentOTP,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in status=%d body=%s", resp.StatusCode, data)
	}
}

func TestEmailOTPPluginSendVerificationOTPRejectsChangeEmailType(t *testing.T) {
	var sent bool
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{
			SendOTP: func(_ context.Context, _ string, _ string, _ string) error {
				sent = true
				return nil
			},
		})}
	})

	resp, data := doRequest(a, http.MethodPost, "/email-otp/send-verification-otp", map[string]any{
		"email": "change@example.com",
		"type":  "change-email",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
	if sent {
		t.Fatal("change-email OTP should use the request-email-change endpoint")
	}
}

func TestEmailOTPPluginPasswordResetDoesNotSendForUnknownEmail(t *testing.T) {
	var sent bool
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{
			SendOTP: func(_ context.Context, _ string, _ string, _ string) error {
				sent = true
				return nil
			},
		})}
	})
	err := a.CreateVerification(context.Background(), constants.VerificationEmailOTP+constants.EmailOTPTypeForgetPassword+":missing@example.com", "123456", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	resp, data := doRequest(a, http.MethodPost, "/email-otp/request-password-reset", map[string]any{
		"email": "missing@example.com",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
	if sent {
		t.Fatal("password reset OTP should not be sent for unknown email")
	}
	_, err = a.Store().FindVerificationByIdentifier(context.Background(), constants.VerificationEmailOTP+constants.EmailOTPTypeForgetPassword+":missing@example.com")
	if !errors.Is(err, berrors.ErrNotFound) {
		t.Fatalf("verification error=%v", err)
	}
}
