package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/types"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestTwoFactorPluginOTPRequiresStoredCode(t *testing.T) {
	var sentOTP string
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.TwoFactor(plugins.TwoFactorOptions{
			SendOTP: func(_ context.Context, _ *types.User, otp string) error {
				sentOTP = otp
				return nil
			},
		})}
	})
	cookies := signUp(t, a, "two-factor-otp@example.com")
	resp, data := doRequest(a, http.MethodPost, "/two-factor/enable", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-otp", map[string]any{
		"code": "000000",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("verify without send status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/send-otp", map[string]any{}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send status = %d body=%s", resp.StatusCode, data)
	}
	if len(sentOTP) != 6 {
		t.Fatalf("sent otp = %q", sentOTP)
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-otp", map[string]any{
		"code": sentOTP,
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", resp.StatusCode, data)
	}
	var result struct {
		Token string     `json:"token"`
		User  types.User `json:"user"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Token == "" || result.User.Additional[constants.FieldTwoFactorEnabled] != true {
		t.Fatalf("unexpected verify response: %+v", result)
	}
}

func TestTwoFactorPluginEnableReturnsStoredBackupCodes(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.TwoFactor(plugins.TwoFactorOptions{})}
	})
	cookies := signUp(t, a, "two-factor-backup-enable@example.com")
	resp, data := doRequest(a, http.MethodPost, "/two-factor/enable", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable status = %d body=%s", resp.StatusCode, data)
	}
	var enabled struct {
		TOTPURI     string   `json:"totpURI"`
		BackupCodes []string `json:"backupCodes"`
	}
	if err := json.Unmarshal(data, &enabled); err != nil {
		t.Fatal(err)
	}
	if enabled.TOTPURI == "" || len(enabled.BackupCodes) != 10 {
		t.Fatalf("unexpected enable response: %+v", enabled)
	}
	for _, code := range enabled.BackupCodes {
		if !validBackupCodeShape(code) {
			t.Fatalf("backup code shape = %q", code)
		}
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-backup-code", map[string]any{
		"code": enabled.BackupCodes[0],
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify backup code status = %d body=%s", resp.StatusCode, data)
	}
	resp, _ = doRequest(a, http.MethodPost, "/two-factor/verify-backup-code", map[string]any{
		"code": enabled.BackupCodes[0],
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("reused backup code status = %d", resp.StatusCode)
	}
}

func TestTwoFactorPluginTOTPOptions(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.TwoFactor(plugins.TwoFactorOptions{
			TOTPDigits: 8,
			TOTPPeriod: time.Minute,
		})}
	})
	cookies := signUp(t, a, "two-factor-totp-options@example.com")
	resp, data := doRequest(a, http.MethodPost, "/two-factor/enable", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable status = %d body=%s", resp.StatusCode, data)
	}
	var enabled struct {
		TOTPURI string `json:"totpURI"`
	}
	if err := json.Unmarshal(data, &enabled); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(enabled.TOTPURI)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("digits") != "8" || parsed.Query().Get("period") != "60" {
		t.Fatalf("totp query = %s", parsed.RawQuery)
	}
	secret := parsed.Query().Get("secret")
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Digits: otp.DigitsEight,
		Period: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-totp", map[string]any{
		"code": code,
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify totp status = %d body=%s", resp.StatusCode, data)
	}
}

func TestTwoFactorPluginSkipVerificationOnEnable(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.TwoFactor(plugins.TwoFactorOptions{
			SkipVerificationOnEnable: true,
		})}
	})
	cookies := signUp(t, a, "two-factor-skip-enable@example.com")
	resp, data := doRequest(a, http.MethodPost, "/two-factor/enable", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodGet, "/get-session?disableCookieCache=true", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get-session status = %d body=%s", resp.StatusCode, data)
	}
	var session types.SessionResponse
	if err := json.Unmarshal(data, &session); err != nil {
		t.Fatal(err)
	}
	if session.User.Additional[constants.FieldTwoFactorEnabled] != true {
		t.Fatalf("twoFactorEnabled = %+v", session.User.Additional)
	}
	resp, data = doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "two-factor-skip-enable@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in status = %d body=%s", resp.StatusCode, data)
	}
	var challenge struct {
		TwoFactorRedirect bool     `json:"twoFactorRedirect"`
		TwoFactorMethods  []string `json:"twoFactorMethods"`
	}
	if err := json.Unmarshal(data, &challenge); err != nil {
		t.Fatal(err)
	}
	if !challenge.TwoFactorRedirect || !containsString(challenge.TwoFactorMethods, "totp") {
		t.Fatalf("unexpected challenge: %+v body=%s", challenge, data)
	}
}

func TestTwoFactorPluginOTPTracksAttempts(t *testing.T) {
	var sentOTP string
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.TwoFactor(plugins.TwoFactorOptions{
			SendOTP: func(_ context.Context, _ *types.User, otp string) error {
				sentOTP = otp
				return nil
			},
		})}
	})
	cookies := signUp(t, a, "two-factor-attempts@example.com")
	resp, data := doRequest(a, http.MethodPost, "/two-factor/enable", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/send-otp", map[string]any{}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send status = %d body=%s", resp.StatusCode, data)
	}
	wrongOTP := "000000"
	if sentOTP == wrongOTP {
		wrongOTP = "111111"
	}
	for i := 0; i < 5; i++ {
		resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-otp", map[string]any{
			"code": wrongOTP,
		}, cookies)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("attempt %d status = %d body=%s", i+1, resp.StatusCode, data)
		}
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-otp", map[string]any{
		"code": wrongOTP,
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("too many status = %d body=%s", resp.StatusCode, data)
	}
	var apiErr struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(data, &apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.Code != "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE" {
		t.Fatalf("code = %q", apiErr.Code)
	}
}

func TestTwoFactorPluginEmailSignInRequiresSecondFactor(t *testing.T) {
	var sentOTP string
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.TwoFactor(plugins.TwoFactorOptions{
			SendOTP: func(_ context.Context, _ *types.User, otp string) error {
				sentOTP = otp
				return nil
			},
		})}
	})
	cookies := signUp(t, a, "two-factor-sign-in@example.com")
	enableTwoFactorWithOTP(t, a, cookies, &sentOTP)

	resp, data := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "two-factor-sign-in@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in status = %d body=%s", resp.StatusCode, data)
	}
	var challenge struct {
		Token             string   `json:"token"`
		TwoFactorRedirect bool     `json:"twoFactorRedirect"`
		TwoFactorMethods  []string `json:"twoFactorMethods"`
	}
	if err := json.Unmarshal(data, &challenge); err != nil {
		t.Fatal(err)
	}
	if !challenge.TwoFactorRedirect || challenge.Token != "" {
		t.Fatalf("unexpected challenge response: %+v", challenge)
	}
	if !containsString(challenge.TwoFactorMethods, "otp") {
		t.Fatalf("methods = %+v", challenge.TwoFactorMethods)
	}
	challengeCookies := resp.Cookies()
	resp, data = doRequest(a, http.MethodPost, "/two-factor/send-otp", map[string]any{}, challengeCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send challenge otp status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-otp", map[string]any{
		"code": sentOTP,
	}, challengeCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify challenge otp status = %d body=%s", resp.StatusCode, data)
	}
	var result struct {
		Token string     `json:"token"`
		User  types.User `json:"user"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Token == "" || result.User.Email != "two-factor-sign-in@example.com" {
		t.Fatalf("unexpected verify response: %+v", result)
	}
	resp, data = doRequest(a, http.MethodGet, "/get-session", nil, resp.Cookies())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get-session status = %d body=%s", resp.StatusCode, data)
	}
}

func TestTwoFactorPluginTrustedDeviceSkipsSecondFactor(t *testing.T) {
	var sentOTP string
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.TwoFactor(plugins.TwoFactorOptions{
			SendOTP: func(_ context.Context, _ *types.User, otp string) error {
				sentOTP = otp
				return nil
			},
		})}
	})
	cookies := signUp(t, a, "two-factor-trust@example.com")
	enableTwoFactorWithOTP(t, a, cookies, &sentOTP)

	resp, data := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "two-factor-trust@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in status = %d body=%s", resp.StatusCode, data)
	}
	challengeCookies := resp.Cookies()
	resp, data = doRequest(a, http.MethodPost, "/two-factor/send-otp", map[string]any{}, challengeCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send challenge otp status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-otp", map[string]any{
		"code": sentOTP, "trustDevice": true,
	}, challengeCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify challenge otp status = %d body=%s", resp.StatusCode, data)
	}
	trustedCookies := resp.Cookies()
	resp, data = doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "two-factor-trust@example.com", "password": "password123",
	}, trustedCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("trusted sign-in status = %d body=%s", resp.StatusCode, data)
	}
	var result struct {
		Token             string `json:"token"`
		TwoFactorRedirect bool   `json:"twoFactorRedirect"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.TwoFactorRedirect || result.Token == "" {
		t.Fatalf("unexpected trusted sign-in response: %+v body=%s", result, data)
	}
}

func TestTwoFactorPluginSignInOTPAccountLockout(t *testing.T) {
	var sentOTP string
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.TwoFactor(plugins.TwoFactorOptions{
			SendOTP: func(_ context.Context, _ *types.User, otp string) error {
				sentOTP = otp
				return nil
			},
			AccountLockout: &plugins.TwoFactorAccountLockoutOptions{
				MaxFailedAttempts: 2,
				Duration:          time.Hour,
			},
		})}
	})
	cookies := signUp(t, a, "two-factor-lockout@example.com")
	enableTwoFactorWithOTP(t, a, cookies, &sentOTP)

	resp, data := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "two-factor-lockout@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in status = %d body=%s", resp.StatusCode, data)
	}
	challengeCookies := resp.Cookies()
	resp, data = doRequest(a, http.MethodPost, "/two-factor/send-otp", map[string]any{}, challengeCookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send status = %d body=%s", resp.StatusCode, data)
	}
	wrongOTP := "000000"
	if sentOTP == wrongOTP {
		wrongOTP = "111111"
	}
	for i := 0; i < 2; i++ {
		resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-otp", map[string]any{
			"code": wrongOTP,
		}, challengeCookies)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("attempt %d status = %d body=%s", i+1, resp.StatusCode, data)
		}
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-otp", map[string]any{
		"code": sentOTP,
	}, challengeCookies)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("locked status = %d body=%s", resp.StatusCode, data)
	}
	var apiErr struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(data, &apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.Code != "ACCOUNT_TEMPORARILY_LOCKED" {
		t.Fatalf("code = %q", apiErr.Code)
	}
}

func TestTwoFactorPluginSignInTOTPChallengeAttemptCap(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.TwoFactor(plugins.TwoFactorOptions{})}
	})
	cookies := signUp(t, a, "two-factor-totp-cap@example.com")
	secret, _ := enableTwoFactorWithTOTP(t, a, cookies)

	resp, data := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "two-factor-totp-cap@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in status = %d body=%s", resp.StatusCode, data)
	}
	challengeCookies := resp.Cookies()
	for i := 0; i < 5; i++ {
		resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-totp", map[string]any{
			"code": "000000",
		}, challengeCookies)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("attempt %d status = %d body=%s", i+1, resp.StatusCode, data)
		}
	}
	validCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-totp", map[string]any{
		"code": validCode,
	}, challengeCookies)
	assertTooManySecondFactorAttempts(t, resp, data)
	resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-totp", map[string]any{
		"code": "000000",
	}, challengeCookies)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cancelled challenge status = %d body=%s", resp.StatusCode, data)
	}
}

func TestTwoFactorPluginSignInBackupCodeChallengeAttemptCap(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.TwoFactor(plugins.TwoFactorOptions{})}
	})
	cookies := signUp(t, a, "two-factor-backup-cap@example.com")
	_, backupCodes := enableTwoFactorWithTOTP(t, a, cookies)

	resp, data := doRequest(a, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "two-factor-backup-cap@example.com", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in status = %d body=%s", resp.StatusCode, data)
	}
	challengeCookies := resp.Cookies()
	for i := 0; i < 5; i++ {
		resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-backup-code", map[string]any{
			"code": "wrong-code",
		}, challengeCookies)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("attempt %d status = %d body=%s", i+1, resp.StatusCode, data)
		}
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-backup-code", map[string]any{
		"code": backupCodes[0],
	}, challengeCookies)
	assertTooManySecondFactorAttempts(t, resp, data)
	resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-backup-code", map[string]any{
		"code": "wrong-code",
	}, challengeCookies)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cancelled challenge status = %d body=%s", resp.StatusCode, data)
	}
}

func TestTwoFactorPluginManagementRequiresPassword(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.TwoFactor(plugins.TwoFactorOptions{})}
	})
	cookies := signUp(t, a, "two-factor-password@example.com")
	resp, data := doRequest(a, http.MethodPost, "/two-factor/enable", map[string]any{}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing password status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/enable", map[string]any{
		"password": "wrong-password",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong password status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/enable", map[string]any{
		"password": "password123", "issuer": "Custom Issuer",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/get-totp-uri", map[string]any{}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("get totp without password status = %d body=%s", resp.StatusCode, data)
	}
}

func enableTwoFactorWithOTP(t *testing.T, a *auth.Auth, cookies []*http.Cookie, sentOTP *string) {
	t.Helper()
	resp, data := doRequest(a, http.MethodPost, "/two-factor/enable", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/send-otp", map[string]any{}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-otp", map[string]any{
		"code": *sentOTP,
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", resp.StatusCode, data)
	}
}

func enableTwoFactorWithTOTP(t *testing.T, a *auth.Auth, cookies []*http.Cookie) (string, []string) {
	t.Helper()
	resp, data := doRequest(a, http.MethodPost, "/two-factor/enable", map[string]any{
		"password": "password123",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable status = %d body=%s", resp.StatusCode, data)
	}
	var enabled struct {
		TOTPURI     string   `json:"totpURI"`
		BackupCodes []string `json:"backupCodes"`
	}
	if err := json.Unmarshal(data, &enabled); err != nil {
		t.Fatal(err)
	}
	secret := totpSecretFromURI(t, enabled.TOTPURI)
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp, data = doRequest(a, http.MethodPost, "/two-factor/verify-totp", map[string]any{
		"code": code,
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify totp status = %d body=%s", resp.StatusCode, data)
	}
	return secret, enabled.BackupCodes
}

func totpSecretFromURI(t *testing.T, rawURI string) string {
	t.Helper()
	parsed, err := url.Parse(rawURI)
	if err != nil {
		t.Fatal(err)
	}
	secret := parsed.Query().Get("secret")
	if secret == "" {
		t.Fatalf("totp uri missing secret: %s", rawURI)
	}
	return secret
}

func assertTooManySecondFactorAttempts(t *testing.T, resp *http.Response, data []byte) {
	t.Helper()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("too many status = %d body=%s", resp.StatusCode, data)
	}
	var apiErr struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(data, &apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.Code != "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE" {
		t.Fatalf("code = %q", apiErr.Code)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func validBackupCodeShape(code string) bool {
	return len(code) == 11 && code[5] == '-'
}
