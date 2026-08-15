package auth_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
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
	err = a.CreateVerification(context.Background(), "change-email-otp-otp-change@example.com", "123456:0", time.Hour)
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
