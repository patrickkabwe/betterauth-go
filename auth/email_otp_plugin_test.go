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
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestEmailOTPPluginSignInCreatesUserWithAdditionalFields(t *testing.T) {
	var sentOTP string
	var sentType string
	a := newTestAuth(func(c *auth.Config) {
		c.User.AdditionalFields = map[string]auth.AdditionalFieldDef{
			"plan": {Type: "string", Required: true},
		}
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{
			SendOTP: func(_ context.Context, _ string, otp string, typ string) error {
				sentOTP = otp
				sentType = typ
				return nil
			},
		})}
	})
	resp, data := doRequest(a, http.MethodPost, "/email-otp/send-verification-otp", map[string]any{
		"email": "otp-signup@example.com", "type": "sign-in",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send status = %d body=%s", resp.StatusCode, data)
	}
	if sentType != "sign-in" || len(sentOTP) != 6 {
		t.Fatalf("sent otp = %q %q", sentType, sentOTP)
	}
	resp, data = doRequest(a, http.MethodPost, "/sign-in/email-otp", map[string]any{
		"email": "otp-signup@example.com", "otp": sentOTP, "name": "OTP User", "plan": "pro",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in status = %d body=%s", resp.StatusCode, data)
	}
	var result struct {
		Token string     `json:"token"`
		User  types.User `json:"user"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Token == "" || !result.User.EmailVerified || result.User.Additional["plan"] != "pro" {
		t.Fatalf("unexpected sign-in response: %+v", result)
	}
}

func TestEmailOTPPluginSignInTracksAttempts(t *testing.T) {
	var sentOTP string
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{
			SendOTP: func(_ context.Context, _ string, otp string, _ string) error {
				sentOTP = otp
				return nil
			},
		})}
	})
	resp, data := doRequest(a, http.MethodPost, "/email-otp/send-verification-otp", map[string]any{
		"email": "otp-attempts@example.com", "type": "sign-in",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send status = %d body=%s", resp.StatusCode, data)
	}
	wrongOTP := "000000"
	if sentOTP == wrongOTP {
		wrongOTP = "111111"
	}
	for i := 0; i < 3; i++ {
		resp, data = doRequest(a, http.MethodPost, "/sign-in/email-otp", map[string]any{
			"email": "otp-attempts@example.com", "otp": wrongOTP,
		}, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("attempt %d status = %d body=%s", i+1, resp.StatusCode, data)
		}
	}
	resp, data = doRequest(a, http.MethodPost, "/sign-in/email-otp", map[string]any{
		"email": "otp-attempts@example.com", "otp": wrongOTP,
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("too many status = %d body=%s", resp.StatusCode, data)
	}
	var apiErr struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(data, &apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.Code != "TOO_MANY_ATTEMPTS" {
		t.Fatalf("code = %q", apiErr.Code)
	}
}

func TestEmailOTPPluginPasswordResetUpdatesPassword(t *testing.T) {
	var sentOTP string
	var sentType string
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{
			SendOTP: func(_ context.Context, _ string, otp string, typ string) error {
				sentOTP = otp
				sentType = typ
				return nil
			},
		})}
	})
	signUp(t, a, "otp-reset@example.com")
	resp, data := doRequest(a, http.MethodPost, "/email-otp/request-password-reset", map[string]any{
		"email": "otp-reset@example.com",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("request status = %d body=%s", resp.StatusCode, data)
	}
	if sentType != "forget-password" || len(sentOTP) != 6 {
		t.Fatalf("sent reset otp = %q %q", sentType, sentOTP)
	}
	resp, data = doRequest(a, http.MethodPost, "/email-otp/reset-password", map[string]any{
		"email": "otp-reset@example.com", "otp": sentOTP, "password": "newpassword123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "otp-reset@example.com", "password": "newpassword123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in status = %d body=%s", resp.StatusCode, data)
	}
}

func TestEmailOTPPluginPasswordResetDoesNotSendForUnknownEmail(t *testing.T) {
	sent := false
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{
			SendOTP: func(_ context.Context, _ string, _ string, _ string) error {
				sent = true
				return nil
			},
		})}
	})
	resp, data := doRequest(a, http.MethodPost, "/email-otp/request-password-reset", map[string]any{
		"email": "otp-unknown@example.com",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("request status = %d body=%s", resp.StatusCode, data)
	}
	if sent {
		t.Fatal("unexpected OTP send for unknown email")
	}
	_, err := a.Store().FindVerificationByIdentifier(context.Background(), "forget-password-otp-otp-unknown@example.com")
	if !errors.Is(err, berrors.ErrNotFound) {
		t.Fatalf("verification err = %v", err)
	}
}

func TestEmailOTPPluginPasswordResetCreatesCredentialAccount(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.EmailOTP(plugins.EmailOTPOptions{})}
	})
	err := a.Store().CreateUser(context.Background(), &types.User{
		ID: "email-otp-no-account", Name: "No Account", Email: "otp-no-account@example.com",
		EmailVerified: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = a.CreateVerification(context.Background(), "forget-password-otp-otp-no-account@example.com", "654321:0", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	resp, data := doRequest(a, http.MethodPost, "/email-otp/reset-password", map[string]any{
		"email": "otp-no-account@example.com", "otp": "654321", "password": "createdpassword123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset status = %d body=%s", resp.StatusCode, data)
	}
	account, err := a.Store().FindAccountByUserAndProvider(context.Background(), "email-otp-no-account", constants.ProviderCredential)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := a.VerifyPassword(account.Password, "createdpassword123")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("created credential account password does not match")
	}
	users, err := a.Store().ListUsers(context.Background(), store.ListUsersOpts{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || !users[0].EmailVerified {
		t.Fatalf("user not verified: %+v", users)
	}
}
