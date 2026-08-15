package auth_test

import (
	"context"
	"encoding/json"
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

func TestEmailOTPPluginSendVerificationOTPGeneratesNumericCode(t *testing.T) {
	var sentOTP string
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{
			OTPLength: 8,
			SendOTP: func(_ context.Context, _ string, otp string, _ string) error {
				sentOTP = otp
				return nil
			},
		})}
	})
	now := time.Now()
	err := a.Store().CreateUser(context.Background(), &types.User{
		ID:            "email-otp-numeric",
		Name:          "Numeric",
		Email:         "numeric@example.com",
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, data := doRequest(a, http.MethodPost, "/email-otp/send-verification-otp", map[string]any{
		"email": "numeric@example.com",
		"type":  "email-verification",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
	if len(sentOTP) != 8 {
		t.Fatalf("otp length=%d value=%q", len(sentOTP), sentOTP)
	}
	for _, char := range sentOTP {
		if char < '0' || char > '9' {
			t.Fatalf("otp should be numeric: %q", sentOTP)
		}
	}
}

func TestEmailOTPPluginSendVerificationOTPReturnsProviderError(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{
			SendOTP: func(_ context.Context, _ string, _ string, _ string) error {
				return errors.New("provider failed")
			},
		})}
	})
	now := time.Now()
	err := a.Store().CreateUser(context.Background(), &types.User{
		ID:            "email-otp-provider-error",
		Name:          "Provider Error",
		Email:         "email-otp-provider-error@example.com",
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, data := doRequest(a, http.MethodPost, "/email-otp/send-verification-otp", map[string]any{
		"email": "email-otp-provider-error@example.com",
		"type":  "email-verification",
	}, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
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

func TestEmailOTPPluginSendVerificationOTPDoesNotSendVerificationForUnknownUser(t *testing.T) {
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
		"email": "unknown-verification@example.com",
		"type":  "email-verification",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
	if sent {
		t.Fatal("email verification OTP should not be sent for unknown user")
	}
	_, err := a.Store().FindVerificationByIdentifier(context.Background(), constants.VerificationEmailOTP+constants.EmailOTPTypeVerification+":unknown-verification@example.com")
	if !errors.Is(err, berrors.ErrNotFound) {
		t.Fatalf("verification error=%v", err)
	}
}

func TestEmailOTPPluginSendVerificationOTPDoesNotSendSignInWhenSignUpDisabled(t *testing.T) {
	var sent bool
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{
			DisableSignUp: true,
			SendOTP: func(_ context.Context, _ string, _ string, _ string) error {
				sent = true
				return nil
			},
		})}
	})

	resp, data := doRequest(a, http.MethodPost, "/email-otp/send-verification-otp", map[string]any{
		"email": "disabled-unknown@example.com",
		"type":  "sign-in",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
	if sent {
		t.Fatal("sign-in OTP should not be sent for unknown user when sign-up is disabled")
	}
	_, err := a.Store().FindVerificationByIdentifier(context.Background(), constants.VerificationEmailOTP+constants.EmailOTPTypeSignIn+":disabled-unknown@example.com")
	if !errors.Is(err, berrors.ErrNotFound) {
		t.Fatalf("verification error=%v", err)
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

func TestEmailOTPPluginSignInCreatesVerifiedUser(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{})}
	})
	err := a.CreateVerification(context.Background(), constants.VerificationEmailOTP+constants.EmailOTPTypeSignIn+":new-sign-in@example.com", "123456", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	resp, data := doRequest(a, http.MethodPost, "/sign-in/email-otp", map[string]any{
		"email": "new-sign-in@example.com",
		"otp":   "123456",
		"name":  "New Sign In",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
	user, err := a.Store().FindUserByEmail(context.Background(), "new-sign-in@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if user.Name != "New Sign In" || !user.EmailVerified {
		t.Fatalf("user=%+v", user)
	}
}

func TestEmailOTPPluginSignInRespectsDisableSignUp(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{
			DisableSignUp: true,
		})}
	})
	err := a.CreateVerification(context.Background(), constants.VerificationEmailOTP+constants.EmailOTPTypeSignIn+":disabled-sign-in@example.com", "123456", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	resp, data := doRequest(a, http.MethodPost, "/sign-in/email-otp", map[string]any{
		"email": "disabled-sign-in@example.com",
		"otp":   "123456",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
	_, err = a.Store().FindUserByEmail(context.Background(), "disabled-sign-in@example.com")
	if !errors.Is(err, berrors.ErrNotFound) {
		t.Fatalf("user lookup error=%v", err)
	}
}

func TestEmailOTPPluginCheckTracksAttempts(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{
			AllowedAttempts: 1,
		})}
	})
	now := time.Now()
	err := a.Store().CreateUser(context.Background(), &types.User{
		ID:            "email-otp-attempts",
		Name:          "Attempts",
		Email:         "attempts@example.com",
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = a.CreateVerification(context.Background(), constants.VerificationEmailOTP+constants.EmailOTPTypeVerification+":attempts@example.com", "123456:0", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	resp, data := doRequest(a, http.MethodPost, "/email-otp/check-verification-otp", map[string]any{
		"email": "attempts@example.com",
		"otp":   "000000",
		"type":  "email-verification",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("first status=%d body=%s", resp.StatusCode, data)
	}
	verification, err := a.Store().FindVerificationByIdentifier(context.Background(), constants.VerificationEmailOTP+constants.EmailOTPTypeVerification+":attempts@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if verification.Value != "123456:1" {
		t.Fatalf("verification value %q", verification.Value)
	}

	resp, data = doRequest(a, http.MethodPost, "/email-otp/check-verification-otp", map[string]any{
		"email": "attempts@example.com",
		"otp":   "000000",
		"type":  "email-verification",
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("second status=%d body=%s", resp.StatusCode, data)
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "TOO_MANY_ATTEMPTS" {
		t.Fatalf("code %q", body.Code)
	}
	_, err = a.Store().FindVerificationByIdentifier(context.Background(), constants.VerificationEmailOTP+constants.EmailOTPTypeVerification+":attempts@example.com")
	if !errors.Is(err, berrors.ErrNotFound) {
		t.Fatalf("verification error=%v", err)
	}
}

func TestEmailOTPPluginCheckDeletesExpiredOTP(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{})}
	})
	now := time.Now()
	err := a.Store().CreateUser(context.Background(), &types.User{
		ID:            "email-otp-expired",
		Name:          "Expired",
		Email:         "expired@example.com",
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatal(err)
	}
	identifier := constants.VerificationEmailOTP + constants.EmailOTPTypeVerification + ":expired@example.com"
	err = a.Store().CreateVerification(context.Background(), &types.Verification{
		ID:         "expired-email-otp",
		Identifier: identifier,
		Value:      "123456:0",
		ExpiresAt:  now.Add(-time.Minute),
		CreatedAt:  now.Add(-time.Hour),
		UpdatedAt:  now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, data := doRequest(a, http.MethodPost, "/email-otp/check-verification-otp", map[string]any{
		"email": "expired@example.com",
		"otp":   "123456",
		"type":  "email-verification",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "OTP_EXPIRED" {
		t.Fatalf("code %q", body.Code)
	}
	_, err = a.Store().FindVerificationByIdentifier(context.Background(), identifier)
	if !errors.Is(err, berrors.ErrNotFound) {
		t.Fatalf("verification error=%v", err)
	}
}

func TestEmailOTPPluginResetPasswordCreatesCredentialAndVerifiesEmail(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{})}
	})
	now := time.Now()
	err := a.Store().CreateUser(context.Background(), &types.User{
		ID:            "email-otp-reset-create",
		Name:          "Reset Create",
		Email:         "reset-create@example.com",
		EmailVerified: false,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = a.CreateVerification(context.Background(), constants.VerificationEmailOTP+constants.EmailOTPTypeForgetPassword+":reset-create@example.com", "123456:0", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	resp, data := doRequest(a, http.MethodPost, "/email-otp/reset-password", map[string]any{
		"email":    "reset-create@example.com",
		"otp":      "123456",
		"password": "updatedpassword123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
	account, err := a.Store().FindAccountByUserAndProvider(context.Background(), "email-otp-reset-create", constants.ProviderCredential)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := a.VerifyPassword(account.Password, "updatedpassword123")
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected updated password to verify")
	}
	user, err := a.Store().FindUserByEmail(context.Background(), "reset-create@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !user.EmailVerified {
		t.Fatal("expected reset password to mark email verified")
	}
}

func TestEmailOTPPluginChangeEmailUsesNewEmailAndCurrentEmailBinding(t *testing.T) {
	var sentEmail string
	var sentOTP string
	var sentType string
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{
			ChangeEmail: plugins.EmailOTPChangeEmailOptions{Enabled: true},
			SendOTP: func(_ context.Context, email string, otp string, typ string) error {
				sentEmail = email
				sentOTP = otp
				sentType = typ
				return nil
			},
		})}
	})
	cookies := signUp(t, a, "change-current@example.com")

	resp, data := doRequest(a, http.MethodPost, "/email-otp/request-email-change", map[string]any{
		"newEmail": "change-next@example.com",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("request status=%d body=%s", resp.StatusCode, data)
	}
	if sentEmail != "change-next@example.com" || sentType != constants.EmailOTPTypeEmailChange || sentOTP == "" {
		t.Fatalf("sent email=%q type=%q otp=%q", sentEmail, sentType, sentOTP)
	}
	verification, err := a.Store().FindVerificationByIdentifier(context.Background(), constants.VerificationEmailOTP+constants.EmailOTPTypeEmailChange+":change-current@example.com-change-next@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if verification.Value != sentOTP+":0" {
		t.Fatalf("verification value %q", verification.Value)
	}

	resp, data = doRequest(a, http.MethodPost, "/email-otp/change-email", map[string]any{
		"newEmail": "change-next@example.com",
		"otp":      sentOTP,
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("change status=%d body=%s", resp.StatusCode, data)
	}
	user, err := a.Store().FindUserByEmail(context.Background(), "change-next@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !user.EmailVerified {
		t.Fatal("expected changed email to be verified")
	}
}

func TestEmailOTPPluginRequestEmailChangeSkipsExistingEmail(t *testing.T) {
	var sent bool
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{
			ChangeEmail: plugins.EmailOTPChangeEmailOptions{Enabled: true},
			SendOTP: func(_ context.Context, _ string, _ string, _ string) error {
				sent = true
				return nil
			},
		})}
	})
	cookies := signUp(t, a, "change-skip-current@example.com")
	_ = signUp(t, a, "change-skip-existing@example.com")

	resp, data := doRequest(a, http.MethodPost, "/email-otp/request-email-change", map[string]any{
		"newEmail": "change-skip-existing@example.com",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, data)
	}
	if sent {
		t.Fatal("existing target email should not receive change-email OTP")
	}
	_, err := a.Store().FindVerificationByIdentifier(context.Background(), constants.VerificationEmailOTP+constants.EmailOTPTypeEmailChange+":change-skip-current@example.com-change-skip-existing@example.com")
	if !errors.Is(err, berrors.ErrNotFound) {
		t.Fatalf("verification error=%v", err)
	}
}
