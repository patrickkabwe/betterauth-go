package plugins_test

import (
	"context"
	"encoding/json"
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

func TestUsernameSignInCallbackURL(t *testing.T) {
	a := newTestAuth(t, plugins.Username(plugins.UsernameOptions{}))
	now := time.Now()
	password, err := a.HashPassword("password123")
	if err != nil {
		t.Fatal(err)
	}
	err = a.Store().CreateUser(context.Background(), &types.User{
		ID: "username-user", Name: "Username", Email: "username@example.com",
		CreatedAt: now, UpdatedAt: now,
		Additional: map[string]any{
			constants.FieldUsername: "username",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = a.Store().CreateAccount(context.Background(), &types.Account{
		ID: "username-account", AccountID: "username-user", ProviderID: constants.ProviderCredential,
		UserID: "username-user", Password: password, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	w := post(t, a, "/sign-in/username", `{"username":"username","password":"password123","callbackURL":"/dashboard"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	if location := w.Header().Get("Location"); location != "/dashboard" {
		t.Fatalf("Location = %q", location)
	}
	var resp struct {
		Redirect bool   `json:"redirect"`
		Token    string `json:"token"`
		URL      string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Redirect || resp.URL != "/dashboard" || resp.Token == "" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestUsernameSignInRequiresVerifiedEmail(t *testing.T) {
	a, err := auth.New(auth.Config{
		Secret:  "test-secret-key-32-chars-minimum!!",
		BaseURL: "http://localhost:8080",
		Store:   memory.New(),
		EmailAndPassword: auth.EmailAndPasswordConfig{
			RequireEmailVerification: true,
		},
		Plugins: []auth.Plugin{plugins.Username(plugins.UsernameOptions{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	password, err := a.HashPassword("password123")
	if err != nil {
		t.Fatal(err)
	}
	err = a.Store().CreateUser(context.Background(), &types.User{
		ID: "unverified-username-user", Name: "Username", Email: "unverified-username@example.com",
		EmailVerified: false, CreatedAt: now, UpdatedAt: now,
		Additional: map[string]any{
			constants.FieldUsername: "unverified",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = a.Store().CreateAccount(context.Background(), &types.Account{
		ID: "unverified-username-account", AccountID: "unverified-username-user", ProviderID: constants.ProviderCredential,
		UserID: "unverified-username-user", Password: password, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	w := post(t, a, "/sign-in/username", `{"username":"unverified","password":"password123"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestPhoneNumberSignInUsesPassword(t *testing.T) {
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{}))
	now := time.Now()
	password, err := a.HashPassword("password123")
	if err != nil {
		t.Fatal(err)
	}
	err = a.Store().CreateUser(context.Background(), &types.User{
		ID: "phone-signin-user", Name: "Phone", Email: "phone-signin@example.com",
		CreatedAt: now, UpdatedAt: now,
		Additional: map[string]any{
			constants.FieldPhoneNumber:   "+1234567890",
			constants.FieldPhoneVerified: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = a.Store().CreateAccount(context.Background(), &types.Account{
		ID: "phone-signin-account", AccountID: "phone-signin-user", ProviderID: constants.ProviderCredential,
		UserID: "phone-signin-user", Password: password, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
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
	if resp.Token == "" || resp.User.ID != "phone-signin-user" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestPhoneNumberSignInRejectsOTPShape(t *testing.T) {
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{}))
	w := post(t, a, "/sign-in/phone-number", `{"phoneNumber":"+1234567890","otp":"123456"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestPhoneNumberSignInRequiresPhoneVerification(t *testing.T) {
	var sentCode string
	a := newTestAuth(t, plugins.PhoneNumber(plugins.PhoneNumberOptions{
		RequireVerification: true,
		SendOTP: func(_ context.Context, _ string, otp string) error {
			sentCode = otp
			return nil
		},
	}))
	now := time.Now()
	password, err := a.HashPassword("password123")
	if err != nil {
		t.Fatal(err)
	}
	err = a.Store().CreateUser(context.Background(), &types.User{
		ID: "phone-unverified-user", Name: "Phone", Email: "phone-unverified@example.com",
		CreatedAt: now, UpdatedAt: now,
		Additional: map[string]any{
			constants.FieldPhoneNumber:   "+1234567891",
			constants.FieldPhoneVerified: false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = a.Store().CreateAccount(context.Background(), &types.Account{
		ID: "phone-unverified-account", AccountID: "phone-unverified-user", ProviderID: constants.ProviderCredential,
		UserID: "phone-unverified-user", Password: password, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	w := post(t, a, "/sign-in/phone-number", `{"phoneNumber":"+1234567891","password":"password123"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	if len(sentCode) != 6 {
		t.Fatalf("sent code = %q", sentCode)
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
