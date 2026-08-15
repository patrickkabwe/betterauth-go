package plugins_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/store/memory"
	"github.com/patrickkabwe/betterauth-go/types"
)

func newTestAuth(t *testing.T, p ...auth.Plugin) *auth.Auth {
	t.Helper()
	a, err := auth.New(auth.Config{
		Secret:  "test-secret-key-32-chars-minimum!!",
		BaseURL: "http://localhost:8080",
		Store:   memory.New(),
		Plugins: p,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func post(t *testing.T, a *auth.Auth, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set(constants.HeaderContentType, constants.MIMEJSON)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	return w
}

func get(t *testing.T, a *auth.Auth, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	return w
}

func TestAnonymousSignIn(t *testing.T) {
	a := newTestAuth(t, plugins.Anonymous(plugins.AnonymousOptions{}))
	w := post(t, a, "/sign-in/anonymous", `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if _, ok := resp["user"]; !ok {
		t.Fatal("expected user in response")
	}
}

func TestMagicLinkSend(t *testing.T) {
	var sent bool
	a := newTestAuth(t, plugins.MagicLink(plugins.MagicLinkOptions{
		SendMagicLink: func(_ context.Context, _, _, _ string) error {
			sent = true
			return nil
		},
	}))
	w := post(t, a, "/sign-in/magic-link", `{"email":"test@example.com"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if !sent {
		t.Fatal("expected magic link to be sent")
	}
}

func TestUsernameAvailability(t *testing.T) {
	a := newTestAuth(t, plugins.Username(plugins.UsernameOptions{}))
	w := post(t, a, "/is-username-available", `{"username":"newuser"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var resp struct {
		Available bool `json:"available"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Available {
		t.Fatal("expected username to be available")
	}
}

func TestUsernameAvailabilityRejectsInvalidDefaultUsername(t *testing.T) {
	a := newTestAuth(t, plugins.Username(plugins.UsernameOptions{}))
	w := post(t, a, "/is-username-available", `{"username":"new-user"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestUsernameAvailabilityRejectsWhitespaceUsername(t *testing.T) {
	a := newTestAuth(t, plugins.Username(plugins.UsernameOptions{}))
	w := post(t, a, "/is-username-available", `{"username":" newuser"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestUsernameSignInRejectsInvalidUsernameShape(t *testing.T) {
	a := newTestAuth(t, plugins.Username(plugins.UsernameOptions{}))
	w := post(t, a, "/sign-in/username", `{"username":"bad-user","password":"password123"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestPhoneNumberSendOTPRequiresSender(t *testing.T) {
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{}))
	w := post(t, a, "/phone-number/send-otp", `{"phoneNumber":"+1234567890"}`)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var resp struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != "SEND_OTP_NOT_IMPLEMENTED" {
		t.Fatalf("code %q", resp.Code)
	}
}

func TestPhoneNumberSendOTPResponseMatchesUpstream(t *testing.T) {
	var sent bool
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{
		SendOTP: func(_ context.Context, phone string, otp string) error {
			if phone != "+1234567890" {
				t.Fatalf("phone %q", phone)
			}
			if len(otp) != 6 {
				t.Fatalf("otp length %d", len(otp))
			}
			sent = true
			return nil
		},
	}))
	w := post(t, a, "/phone-number/send-otp", `{"phoneNumber":"+1234567890"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var resp struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Message != "code sent" {
		t.Fatalf("message %q", resp.Message)
	}
	if !sent {
		t.Fatal("expected otp sender to be called")
	}
}

func TestPhoneNumberSendOTPReturnsProviderError(t *testing.T) {
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{
		SendOTP: func(_ context.Context, _ string, _ string) error {
			return errors.New("provider failed")
		},
	}))
	w := post(t, a, "/phone-number/send-otp", `{"phoneNumber":"+1234567890"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestPhoneNumberVerifyUsesCode(t *testing.T) {
	sentCode := ""
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{
		SendOTP: func(_ context.Context, _ string, otp string) error {
			sentCode = otp
			return nil
		},
		SignUpOnVerification: &plugins.PhoneNumberSignUpOnVerificationOptions{
			GetTempEmail: func(phone string) string {
				return "temp-" + phone + "@example.com"
			},
		},
	}))
	w := post(t, a, "/phone-number/send-otp", `{"phoneNumber":"+1234567890"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("send status %d body %s", w.Code, w.Body.String())
	}
	w = post(t, a, "/phone-number/verify", `{"phoneNumber":"+1234567890","code":"`+sentCode+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("verify status %d body %s", w.Code, w.Body.String())
	}
	var resp struct {
		Status bool   `json:"status"`
		Token  string `json:"token"`
		User   struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Status {
		t.Fatal("expected verified status")
	}
	if resp.Token == "" {
		t.Fatal("expected session token")
	}
	if resp.User.ID == "" {
		t.Fatal("expected user")
	}
	user, err := a.Store().FindUserByID(context.Background(), resp.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if user.Additional[constants.FieldPhoneNumber] != "+1234567890" || user.Additional[constants.FieldPhoneVerified] != true {
		t.Fatalf("phone fields not verified: %+v", user.Additional)
	}
}

func TestPhoneNumberVerifyDisableSessionReturnsNullToken(t *testing.T) {
	sentCode := ""
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{
		SendOTP: func(_ context.Context, _ string, otp string) error {
			sentCode = otp
			return nil
		},
		SignUpOnVerification: &plugins.PhoneNumberSignUpOnVerificationOptions{
			GetTempEmail: func(phone string) string {
				return "temp-" + phone + "@example.com"
			},
		},
	}))
	w := post(t, a, "/phone-number/send-otp", `{"phoneNumber":"+1234567890"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("send status %d body %s", w.Code, w.Body.String())
	}
	w = post(t, a, "/phone-number/verify", `{"phoneNumber":"+1234567890","code":"`+sentCode+`","disableSession":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("verify status %d body %s", w.Code, w.Body.String())
	}
	var resp struct {
		Status bool    `json:"status"`
		Token  *string `json:"token"`
		User   struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Status {
		t.Fatal("expected verified status")
	}
	if resp.Token != nil {
		t.Fatalf("token should be null: %q", *resp.Token)
	}
	if resp.User.ID == "" {
		t.Fatal("expected user")
	}
}

func TestPhoneNumberVerifyUpdatesExistingUser(t *testing.T) {
	sentCode := ""
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{
		SendOTP: func(_ context.Context, _ string, otp string) error {
			sentCode = otp
			return nil
		},
	}))
	now := time.Now()
	err := a.Store().CreateUser(context.Background(), &types.User{
		ID: "phone-verify-user", Name: "Phone User", Email: "verify@example.com",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
		Additional: map[string]any{
			constants.FieldPhoneNumber:   "+1234567890",
			constants.FieldPhoneVerified: false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	w := post(t, a, "/phone-number/send-otp", `{"phoneNumber":"+1234567890"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("send status %d body %s", w.Code, w.Body.String())
	}
	w = post(t, a, "/phone-number/verify", `{"phoneNumber":"+1234567890","code":"`+sentCode+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("verify status %d body %s", w.Code, w.Body.String())
	}
	user, err := a.Store().FindUserByID(context.Background(), "phone-verify-user")
	if err != nil {
		t.Fatal(err)
	}
	if user.Additional[constants.FieldPhoneVerified] != true {
		t.Fatalf("phone not verified: %+v", user.Additional)
	}
}

func TestPhoneNumberVerifyUpdatesCurrentUserPhoneNumber(t *testing.T) {
	sentCode := ""
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{
		SendOTP: func(_ context.Context, _ string, otp string) error {
			sentCode = otp
			return nil
		},
	}))
	createPhoneCredentialUser(t, a, "phone-update-user", "+1234567890", "password123")

	w := post(t, a, "/sign-in/phone-number", `{"phoneNumber":"+1234567890","password":"password123"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("sign in status %d body %s", w.Code, w.Body.String())
	}
	cookie := w.Header().Get("Set-Cookie")
	w = post(t, a, "/phone-number/send-otp", `{"phoneNumber":"+1234567891"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("send status %d body %s", w.Code, w.Body.String())
	}
	req := httptest.NewRequest(http.MethodPost, "/phone-number/verify", strings.NewReader(`{"phoneNumber":"+1234567891","code":"`+sentCode+`","updatePhoneNumber":true}`))
	req.Header.Set(constants.HeaderContentType, constants.MIMEJSON)
	req.Header.Set("Cookie", cookie)
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("verify status %d body %s", w.Code, w.Body.String())
	}
	user, err := a.Store().FindUserByID(context.Background(), "phone-update-user")
	if err != nil {
		t.Fatal(err)
	}
	if user.Additional[constants.FieldPhoneNumber] != "+1234567891" || user.Additional[constants.FieldPhoneVerified] != true {
		t.Fatalf("phone fields not updated: %+v", user.Additional)
	}
}

func TestPhoneNumberVerifyRejectsOTPShape(t *testing.T) {
	sentCode := ""
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{
		SendOTP: func(_ context.Context, _ string, otp string) error {
			sentCode = otp
			return nil
		},
	}))
	w := post(t, a, "/phone-number/send-otp", `{"phoneNumber":"+1234567890"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("send status %d body %s", w.Code, w.Body.String())
	}
	w = post(t, a, "/phone-number/verify", `{"phoneNumber":"+1234567890","otp":"`+sentCode+`"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("verify status %d body %s", w.Code, w.Body.String())
	}
}

func TestPhoneNumberRequestPasswordResetSendsOTPForExistingUser(t *testing.T) {
	sentPhone := ""
	sentCode := ""
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{
		SendPasswordResetOTP: func(_ context.Context, phone string, otp string) error {
			sentPhone = phone
			sentCode = otp
			return nil
		},
	}))
	createPhoneCredentialUser(t, a, "phone-reset-user", "+1234567890", "password123")

	w := post(t, a, "/phone-number/request-password-reset", `{"phoneNumber":"+1234567890"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var resp struct {
		Status bool `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Status {
		t.Fatal("expected reset request status")
	}
	if sentPhone != "+1234567890" {
		t.Fatalf("sent phone %q", sentPhone)
	}
	if len(sentCode) != 6 {
		t.Fatalf("sent code length %d", len(sentCode))
	}
}

func TestPhoneNumberRequestPasswordResetDoesNotSendForUnknownUser(t *testing.T) {
	var sent bool
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{
		SendPasswordResetOTP: func(_ context.Context, _ string, _ string) error {
			sent = true
			return nil
		},
	}))
	w := post(t, a, "/phone-number/request-password-reset", `{"phoneNumber":"+1234567899"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var resp struct {
		Status bool `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Status {
		t.Fatal("expected reset request status")
	}
	if sent {
		t.Fatal("reset otp should not be sent for unknown phone numbers")
	}
	verification, err := a.Store().FindVerificationByIdentifier(context.Background(), "+1234567899-request-password-reset")
	if err != nil {
		t.Fatal(err)
	}
	if len(verification.Value) != 6 {
		t.Fatalf("verification code length %d", len(verification.Value))
	}
}

func TestPhoneNumberResetPasswordUpdatesCredentialPassword(t *testing.T) {
	resetCode := ""
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{
		SendPasswordResetOTP: func(_ context.Context, _ string, otp string) error {
			resetCode = otp
			return nil
		},
	}))
	createPhoneCredentialUser(t, a, "phone-reset-user", "+1234567890", "password123")

	w := post(t, a, "/phone-number/request-password-reset", `{"phoneNumber":"+1234567890"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("request status %d body %s", w.Code, w.Body.String())
	}
	w = post(t, a, "/phone-number/reset-password", `{"phoneNumber":"+1234567890","otp":"`+resetCode+`","newPassword":"updatedpassword123"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("reset status %d body %s", w.Code, w.Body.String())
	}
	var resp struct {
		Status bool `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Status {
		t.Fatal("expected reset status")
	}
	account, err := a.Store().FindAccountByUserAndProvider(context.Background(), "phone-reset-user", constants.ProviderCredential)
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
	valid, err = a.VerifyPassword(account.Password, "password123")
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("old password should not verify")
	}
}

func TestPhoneNumberSignInUsesPassword(t *testing.T) {
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{}))
	createPhoneCredentialUser(t, a, "phone-signin-user", "+1234567890", "password123")

	w := post(t, a, "/sign-in/phone-number", `{"phoneNumber":"+1234567890","password":"password123"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
		User  struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token == "" {
		t.Fatal("expected token")
	}
	if resp.User.ID != "phone-signin-user" {
		t.Fatalf("user id %q", resp.User.ID)
	}
}

func TestPhoneNumberSignInRejectsOTPShape(t *testing.T) {
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{}))
	w := post(t, a, "/sign-in/phone-number", `{"phoneNumber":"+1234567890","otp":"123456"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestOneTimeTokenFlow(t *testing.T) {
	a := newTestAuth(t, plugins.OneTimeToken(plugins.OneTimeTokenOptions{}))
	// create user via anonymous first
	w := post(t, a, "/sign-in/anonymous", `{}`)
	var anon struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &anon)

	// need session - anonymous plugin not loaded, use sign-up
	a2, _ := auth.New(auth.Config{
		Secret: "test-secret-key-32-chars-minimum!!", BaseURL: "http://localhost:8080",
		Store: memory.New(),
		Plugins: []auth.Plugin{
			plugins.Anonymous(plugins.AnonymousOptions{}),
			plugins.OneTimeToken(plugins.OneTimeTokenOptions{}),
		},
	})
	w = post(t, a2, "/sign-in/anonymous", `{}`)
	cookie := w.Header().Get("Set-Cookie")

	req := httptest.NewRequest(http.MethodGet, "/one-time-token/generate", nil)
	req.Header.Set("Cookie", cookie)
	w2 := httptest.NewRecorder()
	a2.Handler().ServeHTTP(w2, req)
	if w2.Code != http.StatusOK {
		t.Fatalf("generate status %d", w2.Code)
	}
}

func TestOpenAPISchema(t *testing.T) {
	a := newTestAuth(t, plugins.OpenAPI(plugins.OpenAPIOptions{}))
	w := get(t, a, "/open-api/generate-schema")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
}

func TestOrganizationCreate(t *testing.T) {
	a, _ := auth.New(auth.Config{
		Secret: "test-secret-key-32-chars-minimum!!", BaseURL: "http://localhost:8080",
		Store: memory.New(),
		Plugins: []auth.Plugin{
			plugins.Anonymous(plugins.AnonymousOptions{}),
			plugins.Organization(plugins.OrganizationOptions{}),
		},
	})
	w := post(t, a, "/sign-in/anonymous", `{}`)
	cookie := w.Header().Get("Set-Cookie")
	req := httptest.NewRequest(http.MethodPost, "/organization/create", strings.NewReader(`{"name":"Acme","slug":"acme"}`))
	req.Header.Set(constants.HeaderContentType, constants.MIMEJSON)
	req.Header.Set("Cookie", cookie)
	w2 := httptest.NewRecorder()
	a.Handler().ServeHTTP(w2, req)
	if w2.Code != http.StatusOK {
		t.Fatalf("create org status %d body %s", w2.Code, w2.Body.String())
	}
}

func TestBearerPluginRegistered(t *testing.T) {
	a := newTestAuth(t, plugins.Bearer(plugins.BearerOptions{}))
	if len(a.Plugins()) != 1 || a.Plugins()[0].ID() != constants.PluginBearer {
		t.Fatal("bearer plugin not registered")
	}
}

func TestAllPluginsCount(t *testing.T) {
	all := plugins.All(plugins.AllOptions{})
	if len(all) != 24 {
		t.Fatalf("expected 24 plugins, got %d", len(all))
	}
}

func createPhoneCredentialUser(t *testing.T, a *auth.Auth, userID string, phoneNumber string, password string) {
	t.Helper()
	now := time.Now()
	err := a.Store().CreateUser(context.Background(), &types.User{
		ID: userID, Name: "Phone User", Email: "phone@example.com",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
		Additional: map[string]any{
			constants.FieldPhoneNumber:   phoneNumber,
			constants.FieldPhoneVerified: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	hashedPassword, err := a.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	err = a.Store().CreateAccount(context.Background(), &types.Account{
		ID: "phone-signin-account", AccountID: userID, ProviderID: constants.ProviderCredential,
		UserID: userID, Password: hashedPassword, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
}
