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
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestPhoneNumberPluginUpdateUserRejectsDirectPhoneNumberChange(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.PhoneNumber(plugins.PhoneNumberOptions{})}
	})
	cookies := signUp(t, a, "phone-update-reject@example.com")
	resp, data := doRequest(a, http.MethodPost, "/update-user", map[string]any{
		"phoneNumber": "+1234567890",
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", resp.StatusCode, data)
	}
	var apiErr struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(data, &apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.Code != "PHONE_NUMBER_CANNOT_BE_UPDATED" {
		t.Fatalf("code = %q", apiErr.Code)
	}
}

func TestPhoneNumberPluginUpdateUserAllowsClearingPhoneNumber(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.PhoneNumber(plugins.PhoneNumberOptions{})}
	})
	cookies := signUp(t, a, "phone-update-clear@example.com")
	users, err := a.Store().ListUsers(context.Background(), store.ListUsersOpts{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Fatalf("users = %d", len(users))
	}
	_, err = a.Store().UpdateUser(context.Background(), users[0].ID, store.UserUpdate{
		Additional: map[string]any{
			constants.FieldPhoneNumber:   "+1234567890",
			constants.FieldPhoneVerified: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, data := doRequest(a, http.MethodPost, "/update-user", map[string]any{
		"phoneNumber": nil,
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodGet, "/get-session?disableCookieCache=true", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get-session status = %d body=%s", resp.StatusCode, data)
	}
	var session types.SessionResponse
	if err := json.Unmarshal(data, &session); err != nil {
		t.Fatal(err)
	}
	if session.User.Additional[constants.FieldPhoneNumber] != nil {
		t.Fatalf("phoneNumber not cleared: %+v", session.User.Additional)
	}
	if session.User.Additional[constants.FieldPhoneVerified] != false {
		t.Fatalf("phoneNumberVerified not reset: %+v", session.User.Additional)
	}
}

func TestPhoneNumberPluginVerifyUpdatesCurrentUser(t *testing.T) {
	var sentCode string
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.PhoneNumber(plugins.PhoneNumberOptions{
			SendOTP: func(_ context.Context, _ string, otp string) error {
				sentCode = otp
				return nil
			},
		})}
	})
	cookies := signUp(t, a, "phone-verify-update@example.com")
	resp, data := doRequest(a, http.MethodPost, "/phone-number/send-otp", map[string]any{
		"phoneNumber": "+1234567893",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send status = %d body=%s", resp.StatusCode, data)
	}
	if len(sentCode) != 6 {
		t.Fatalf("sent code = %q", sentCode)
	}
	resp, data = doRequest(a, http.MethodPost, "/phone-number/verify", map[string]any{
		"phoneNumber": "+1234567893", "code": sentCode, "updatePhoneNumber": true,
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", resp.StatusCode, data)
	}
	var result struct {
		Status bool       `json:"status"`
		Token  string     `json:"token"`
		User   types.User `json:"user"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Status || result.Token == "" {
		t.Fatalf("unexpected verify response: %+v", result)
	}
	if result.User.Additional[constants.FieldPhoneNumber] != "+1234567893" ||
		result.User.Additional[constants.FieldPhoneVerified] != true {
		t.Fatalf("phone fields not verified: %+v", result.User.Additional)
	}
}

func TestPhoneNumberPluginSendOTPReturnsProviderError(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.PhoneNumber(plugins.PhoneNumberOptions{
			SendOTP: func(_ context.Context, _ string, _ string) error {
				return errors.New("sms provider failed")
			},
		})}
	})
	resp, data := doRequest(a, http.MethodPost, "/phone-number/send-otp", map[string]any{
		"phoneNumber": "+1234567897",
	}, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("send status = %d body=%s", resp.StatusCode, data)
	}
}

func TestPhoneNumberPluginVerifyTracksOTPAttempts(t *testing.T) {
	var sentCode string
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.PhoneNumber(plugins.PhoneNumberOptions{
			SendOTP: func(_ context.Context, _ string, otp string) error {
				sentCode = otp
				return nil
			},
		})}
	})
	cookies := signUp(t, a, "phone-attempts@example.com")
	resp, data := doRequest(a, http.MethodPost, "/phone-number/send-otp", map[string]any{
		"phoneNumber": "+1234567894",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send status = %d body=%s", resp.StatusCode, data)
	}
	wrongCode := "000000"
	if sentCode == wrongCode {
		wrongCode = "111111"
	}
	for i := 0; i < 3; i++ {
		resp, data = doRequest(a, http.MethodPost, "/phone-number/verify", map[string]any{
			"phoneNumber": "+1234567894", "code": wrongCode, "updatePhoneNumber": true,
		}, cookies)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("attempt %d status = %d body=%s", i+1, resp.StatusCode, data)
		}
	}
	resp, data = doRequest(a, http.MethodPost, "/phone-number/verify", map[string]any{
		"phoneNumber": "+1234567894", "code": wrongCode, "updatePhoneNumber": true,
	}, cookies)
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

func TestPhoneNumberPluginVerifyUsesCustomVerifier(t *testing.T) {
	var seenPhone string
	var seenCode string
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.PhoneNumber(plugins.PhoneNumberOptions{
			VerifyOTP: func(_ context.Context, phone string, otp string) (bool, error) {
				seenPhone = phone
				seenCode = otp
				return true, nil
			},
		})}
	})
	cookies := signUp(t, a, "phone-custom-verify@example.com")
	users, err := a.Store().ListUsers(context.Background(), store.ListUsersOpts{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	err = a.CreateVerification(context.Background(), "+1234567895", "internal:0", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	resp, data := doRequest(a, http.MethodPost, "/phone-number/verify", map[string]any{
		"phoneNumber": "+1234567895", "code": "external", "updatePhoneNumber": true,
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", resp.StatusCode, data)
	}
	if seenPhone != "+1234567895" || seenCode != "external" {
		t.Fatalf("custom verifier args = %q %q", seenPhone, seenCode)
	}
	updated, err := a.Store().FindUserByID(context.Background(), users[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Additional[constants.FieldPhoneNumber] != "+1234567895" ||
		updated.Additional[constants.FieldPhoneVerified] != true {
		t.Fatalf("phone fields not updated: %+v", updated.Additional)
	}
	if _, err := a.Store().FindVerificationByIdentifier(context.Background(), "+1234567895"); err == nil {
		t.Fatal("expected internal OTP cleanup after custom verification")
	}
}

func TestPhoneNumberPluginVerifyRejectsCustomVerifierFailure(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.PhoneNumber(plugins.PhoneNumberOptions{
			VerifyOTP: func(_ context.Context, _ string, _ string) (bool, error) {
				return false, nil
			},
		})}
	})
	cookies := signUp(t, a, "phone-custom-reject@example.com")
	resp, data := doRequest(a, http.MethodPost, "/phone-number/verify", map[string]any{
		"phoneNumber": "+1234567896", "code": "external", "updatePhoneNumber": true,
	}, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("verify status = %d body=%s", resp.StatusCode, data)
	}
}

func TestPhoneNumberPluginSendOTPUsesPhoneValidator(t *testing.T) {
	sendCalled := false
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.PhoneNumber(plugins.PhoneNumberOptions{
			PhoneNumberValidator: func(_ context.Context, phone string) (bool, error) {
				return phone == "+1234567801", nil
			},
			SendOTP: func(_ context.Context, _ string, _ string) error {
				sendCalled = true
				return nil
			},
		})}
	})
	resp, data := doRequest(a, http.MethodPost, "/phone-number/send-otp", map[string]any{
		"phoneNumber": "+1234567802",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("send status = %d body=%s", resp.StatusCode, data)
	}
	var apiErr struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(data, &apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.Code != "INVALID_PHONE_NUMBER" || sendCalled {
		t.Fatalf("unexpected validator result: code=%q sendCalled=%v", apiErr.Code, sendCalled)
	}
}

func TestPhoneNumberPluginVerifySignsUpUserOnVerification(t *testing.T) {
	var sentCode string
	var callbackPhone string
	var callbackUserID string
	a := newTestAuth(func(c *auth.Config) {
		c.User.AdditionalFields = map[string]auth.AdditionalFieldDef{
			"lastName": {Type: "string", Required: true},
		}
		c.Plugins = []auth.Plugin{plugins.PhoneNumber(plugins.PhoneNumberOptions{
			SendOTP: func(_ context.Context, _ string, otp string) error {
				sentCode = otp
				return nil
			},
			CallbackOnVerification: func(_ context.Context, phone string, user *types.User) error {
				callbackPhone = phone
				callbackUserID = user.ID
				return nil
			},
			SignUpOnVerification: &plugins.PhoneNumberSignUpOnVerificationOptions{
				GetTempEmail: func(phone string) string {
					return "temp-" + phone + "@example.com"
				},
				GetTempName: func(phone string) string {
					return "Phone " + phone
				},
			},
		})}
	})
	resp, data := doRequest(a, http.MethodPost, "/phone-number/send-otp", map[string]any{
		"phoneNumber": "+1234567803",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/phone-number/verify", map[string]any{
		"phoneNumber": "+1234567803", "code": sentCode, "lastName": "Doe",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", resp.StatusCode, data)
	}
	var result struct {
		Status bool       `json:"status"`
		Token  string     `json:"token"`
		User   types.User `json:"user"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Status || result.Token == "" {
		t.Fatalf("unexpected verify response: %+v", result)
	}
	if result.User.Email != "temp-+1234567803@example.com" || result.User.Name != "Phone +1234567803" {
		t.Fatalf("temporary user mismatch: %+v", result.User)
	}
	if result.User.Additional["lastName"] != "Doe" ||
		result.User.Additional[constants.FieldPhoneNumber] != "+1234567803" ||
		result.User.Additional[constants.FieldPhoneVerified] != true {
		t.Fatalf("additional fields mismatch: %+v", result.User.Additional)
	}
	if callbackPhone != "+1234567803" || callbackUserID != result.User.ID {
		t.Fatalf("callback = %q %q", callbackPhone, callbackUserID)
	}
}

func TestPhoneNumberPluginPasswordResetUpdatesPassword(t *testing.T) {
	var sentPhone string
	var sentCode string
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.PhoneNumber(plugins.PhoneNumberOptions{
			SendPasswordResetOTP: func(_ context.Context, phone string, otp string) error {
				sentPhone = phone
				sentCode = otp
				return nil
			},
		})}
	})
	cookies := signUp(t, a, "phone-reset@example.com")
	users, err := a.Store().ListUsers(context.Background(), store.ListUsersOpts{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Store().UpdateUser(context.Background(), users[0].ID, store.UserUpdate{
		Additional: map[string]any{
			constants.FieldPhoneNumber:   "+1234567898",
			constants.FieldPhoneVerified: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, data := doRequest(a, http.MethodPost, "/phone-number/request-password-reset", map[string]any{
		"phoneNumber": "+1234567898",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("request status = %d body=%s", resp.StatusCode, data)
	}
	if sentPhone != "+1234567898" || len(sentCode) != 6 {
		t.Fatalf("sent reset otp = %q %q", sentPhone, sentCode)
	}
	resp, data = doRequest(a, http.MethodPost, "/phone-number/reset-password", map[string]any{
		"phoneNumber": "+1234567898", "otp": sentCode, "newPassword": "newpassword123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/sign-in/phone-number", map[string]any{
		"phoneNumber": "+1234567898", "password": "password123",
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password status = %d body=%s", resp.StatusCode, data)
	}
	resp, data = doRequest(a, http.MethodPost, "/sign-in/phone-number", map[string]any{
		"phoneNumber": "+1234567898", "password": "newpassword123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("new password status = %d body=%s", resp.StatusCode, data)
	}
}

func TestPhoneNumberPluginPasswordResetDoesNotSendForUnknownPhone(t *testing.T) {
	sent := false
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.PhoneNumber(plugins.PhoneNumberOptions{
			SendPasswordResetOTP: func(_ context.Context, _ string, _ string) error {
				sent = true
				return nil
			},
		})}
	})
	resp, data := doRequest(a, http.MethodPost, "/phone-number/request-password-reset", map[string]any{
		"phoneNumber": "+1234567899",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("request status = %d body=%s", resp.StatusCode, data)
	}
	var result struct {
		Status bool `json:"status"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Status || sent {
		t.Fatalf("unexpected unknown phone result: status=%v sent=%v", result.Status, sent)
	}
}

func TestPhoneNumberPluginPasswordResetCreatesCredentialAccount(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Plugins = []auth.Plugin{plugins.PhoneNumber(plugins.PhoneNumberOptions{})}
	})
	now := time.Now()
	err := a.Store().CreateUser(context.Background(), &types.User{
		ID: "phone-reset-no-account", Name: "Phone Reset", Email: "phone-reset-no-account@example.com",
		CreatedAt: now, UpdatedAt: now,
		Additional: map[string]any{
			constants.FieldPhoneNumber:   "+1234567800",
			constants.FieldPhoneVerified: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = a.CreateVerification(context.Background(), "+1234567800-request-password-reset", "654321:0", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	resp, data := doRequest(a, http.MethodPost, "/phone-number/reset-password", map[string]any{
		"phoneNumber": "+1234567800", "otp": "654321", "newPassword": "createdpassword123",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset status = %d body=%s", resp.StatusCode, data)
	}
	account, err := a.Store().FindAccountByUserAndProvider(context.Background(), "phone-reset-no-account", constants.ProviderCredential)
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
}
