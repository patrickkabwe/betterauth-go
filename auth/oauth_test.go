package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

type staticOAuthProvider struct {
	id                    string
	user                  provider.OAuthUser
	tokens                provider.OAuthTokens
	authURL               string
	opts                  provider.AuthorizationURLOpts
	seenTokens            provider.OAuthTokens
	disableImplicitSignUp bool
	disableSignUp         bool
	overrideUserInfo      bool
}

func (p *staticOAuthProvider) ID() string { return p.id }

func (p *staticOAuthProvider) CreateAuthorizationURL(_ context.Context, opts provider.AuthorizationURLOpts) (string, error) {
	p.opts = opts
	base := p.authURL
	if base == "" {
		base = "https://oauth.example.com/authorize"
	}
	u, _ := url.Parse(base)
	q := u.Query()
	q.Set("state", opts.State)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (p *staticOAuthProvider) ValidateAuthorizationCode(_ context.Context, _, _, _ string) (*provider.OAuthTokens, error) {
	t := p.tokens
	return &t, nil
}

func (p *staticOAuthProvider) GetUserInfo(_ context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error) {
	p.seenTokens = tokens
	return &provider.UserInfo{User: p.user, Data: map[string]any{"provider": p.id}}, nil
}

func (p *staticOAuthProvider) RefreshAccessToken(_ context.Context, _ string) (*provider.OAuthTokens, error) {
	exp := time.Now().Add(time.Hour)
	return &provider.OAuthTokens{AccessToken: "refreshed", AccessTokenExpiresAt: &exp}, nil
}

func (p *staticOAuthProvider) VerifyIDToken(_ context.Context, _, _ string) (bool, error) {
	return true, nil
}

func (p *staticOAuthProvider) DisableImplicitSignUp() bool { return p.disableImplicitSignUp }

func (p *staticOAuthProvider) DisableSignUp() bool { return p.disableSignUp }

func (p *staticOAuthProvider) OverrideUserInfoOnSignIn() bool { return p.overrideUserInfo }

func oauthTestAuth(t *testing.T, p provider.SocialProvider) *auth.Auth {
	t.Helper()
	return newTestAuth(func(c *auth.Config) {
		c.SocialProviders = map[string]provider.SocialProvider{p.ID(): p}
		c.Account.AccountLinking.TrustedProviders = []string{p.ID()}
	})
}

func TestSignInSocialRedirect(t *testing.T) {
	p := &staticOAuthProvider{
		id:   "mock",
		user: provider.OAuthUser{ID: "mock-1", Email: "oauth@example.com", EmailVerified: true, Name: "OAuth"},
	}
	a := oauthTestAuth(t, p)

	disable := true
	resp, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider":        "mock",
		"callbackURL":     "http://localhost:3000/done",
		"disableRedirect": disable,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	var result types.SocialSignInResponse
	_ = json.Unmarshal(data, &result)
	if result.URL == "" || result.Redirect {
		t.Fatalf("result=%+v", result)
	}
}

func TestSignInSocialPassesLoginHint(t *testing.T) {
	p := &staticOAuthProvider{
		id:   "mock",
		user: provider.OAuthUser{ID: "mock-1", Email: "oauth@example.com", EmailVerified: true, Name: "OAuth"},
	}
	a := oauthTestAuth(t, p)

	disable := true
	resp, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider":        "mock",
		"loginHint":       "hint@example.com",
		"disableRedirect": disable,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	if p.opts.LoginHint != "hint@example.com" {
		t.Fatalf("login hint = %q", p.opts.LoginHint)
	}
}

func TestSignInSocialStateCreateFails(t *testing.T) {
	p := &staticOAuthProvider{
		id:   "mock",
		user: provider.OAuthUser{ID: "mock-state-fail", Email: "oauth-state-fail@example.com", EmailVerified: true, Name: "OAuth State Fail"},
	}
	a := newTestAuth(func(c *auth.Config) {
		c.Store = wrapStore("CreateVerification")
		c.SocialProviders = map[string]provider.SocialProvider{p.ID(): p}
		c.Account.AccountLinking.TrustedProviders = []string{p.ID()}
	})

	disable := true
	resp, _ := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider":        "mock",
		"callbackURL":     "http://localhost:3000/done",
		"disableRedirect": disable,
	}, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestSignInSocialDisableImplicitSignUpRequiresRequestSignUp(t *testing.T) {
	p := &staticOAuthProvider{
		id:                    "mock",
		user:                  provider.OAuthUser{ID: "mock-implicit", Email: "oauth-implicit@example.com", EmailVerified: true, Name: "OAuth Implicit"},
		tokens:                provider.OAuthTokens{AccessToken: "at-implicit"},
		disableImplicitSignUp: true,
	}
	a := oauthTestAuth(t, p)

	disable := true
	_, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider":        "mock",
		"callbackURL":     "http://localhost:3000/done",
		"disableRedirect": disable,
	}, nil)
	var signIn types.SocialSignInResponse
	_ = json.Unmarshal(data, &signIn)
	parsed, err := url.Parse(signIn.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("missing state in auth url")
	}

	resp, _ := doRequest(a, http.MethodGet, "/callback/mock?code=abc&state="+url.QueryEscape(state), nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status=%d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	if !strings.Contains(location, "error=signup_disabled") {
		t.Fatalf("redirect=%s", location)
	}
}

func TestSignInSocialRequestSignUpOverridesDisableImplicitSignUp(t *testing.T) {
	p := &staticOAuthProvider{
		id:                    "mock",
		user:                  provider.OAuthUser{ID: "mock-request", Email: "oauth-request@example.com", EmailVerified: true, Name: "OAuth Request"},
		tokens:                provider.OAuthTokens{AccessToken: "at-request"},
		disableImplicitSignUp: true,
	}
	a := oauthTestAuth(t, p)

	disable := true
	_, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider":        "mock",
		"callbackURL":     "http://localhost:3000/done",
		"disableRedirect": disable,
		"requestSignUp":   true,
	}, nil)
	var signIn types.SocialSignInResponse
	_ = json.Unmarshal(data, &signIn)
	parsed, err := url.Parse(signIn.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("missing state in auth url")
	}

	resp, _ := doRequest(a, http.MethodGet, "/callback/mock?code=abc&state="+url.QueryEscape(state), nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status=%d", resp.StatusCode)
	}
	if location := resp.Header.Get("Location"); !strings.HasPrefix(location, "http://localhost:3000/done") {
		t.Fatalf("redirect=%s", location)
	}
}

func TestSignInSocialIDTokenHonorsDisableSignUp(t *testing.T) {
	p := &staticOAuthProvider{
		id:            "mock",
		user:          provider.OAuthUser{ID: "mock-disabled", Email: "oauth-disabled@example.com", EmailVerified: true, Name: "OAuth Disabled"},
		disableSignUp: true,
	}
	a := oauthTestAuth(t, p)

	resp, _ := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider": "mock",
		"idToken":  map[string]any{"token": "valid-id-token", "accessToken": "at-disabled"},
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestSignInSocialIDTokenPassesUserDataToProvider(t *testing.T) {
	p := &staticOAuthProvider{
		id:   "mock",
		user: provider.OAuthUser{ID: "mock-id-user", Email: "oauth-id-user@example.com", EmailVerified: true, Name: "OAuth ID User"},
	}
	a := oauthTestAuth(t, p)

	resp, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider": "mock",
		"idToken": map[string]any{
			"token":       "valid-id-token",
			"accessToken": "at-id-user",
			"user": map[string]any{
				"name":  map[string]any{"firstName": "Ada", "lastName": "Lovelace"},
				"email": "ada@example.com",
			},
		},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	name, ok := p.seenTokens.User["name"].(map[string]any)
	if !ok || name["firstName"] != "Ada" || p.seenTokens.User["email"] != "ada@example.com" {
		t.Fatalf("user data=%+v", p.seenTokens.User)
	}
}

func TestSignInSocialSendsVerificationForUnverifiedNewUser(t *testing.T) {
	p := &staticOAuthProvider{
		id:   "mock",
		user: provider.OAuthUser{ID: "mock-unverified-signup", Email: "oauth-unverified-signup@example.com", EmailVerified: false, Name: "OAuth Unverified Signup"},
	}
	sendOnSignUp := true
	var sent types.VerificationEmailData
	a := newTestAuth(func(c *auth.Config) {
		c.SocialProviders = map[string]provider.SocialProvider{p.ID(): p}
		c.Account.AccountLinking.TrustedProviders = []string{p.ID()}
		c.EmailVerification.SendOnSignUp = &sendOnSignUp
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, data types.VerificationEmailData) error {
			sent = data
			return nil
		}
	})

	resp, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider":    "mock",
		"callbackURL": "http://localhost:3000/social-done",
		"idToken":     map[string]any{"token": "valid-id-token", "accessToken": "at-unverified-signup"},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	if sent.User.Email != "oauth-unverified-signup@example.com" {
		t.Fatalf("sent user=%+v", sent.User)
	}
	if sent.Token == "" {
		t.Fatal("missing verification token")
	}
	if !strings.Contains(sent.URL, "/verify-email?") || !strings.Contains(sent.URL, "callbackURL=http%3A%2F%2Flocalhost%3A3000%2Fsocial-done") {
		t.Fatalf("verification url=%s", sent.URL)
	}
}

func TestSignInSocialVerificationSendFails(t *testing.T) {
	p := &staticOAuthProvider{
		id:   "mock",
		user: provider.OAuthUser{ID: "mock-verification-send-fail", Email: "oauth-verification-send-fail@example.com", EmailVerified: false, Name: "OAuth Verification Send Fail"},
	}
	sendOnSignUp := true
	a := newTestAuth(func(c *auth.Config) {
		c.SocialProviders = map[string]provider.SocialProvider{p.ID(): p}
		c.Account.AccountLinking.TrustedProviders = []string{p.ID()}
		c.EmailVerification.SendOnSignUp = &sendOnSignUp
		c.EmailVerification.SendVerificationEmail = func(_ context.Context, _ types.VerificationEmailData) error {
			return errors.New("smtp unavailable")
		}
	})

	resp, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider": "mock",
		"idToken":  map[string]any{"token": "valid-id-token", "accessToken": "at-verification-send-fail"},
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	if !strings.Contains(string(data), "unable to create user") {
		t.Fatalf("body=%s", data)
	}
}

func TestSignInSocialUserLookupFails(t *testing.T) {
	p := &staticOAuthProvider{
		id:   "mock",
		user: provider.OAuthUser{ID: "mock-lookup-fail", Email: "oauth-lookup-fail@example.com", EmailVerified: true, Name: "OAuth Lookup Fail"},
	}
	a := newTestAuth(func(c *auth.Config) {
		c.Store = wrapStore("FindUserByEmail")
		c.SocialProviders = map[string]provider.SocialProvider{p.ID(): p}
		c.Account.AccountLinking.TrustedProviders = []string{p.ID()}
	})

	resp, _ := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider": "mock",
		"idToken":  map[string]any{"token": "valid-id-token", "accessToken": "at-lookup-fail"},
	}, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestSignInSocialImplicitLinkRequiresVerifiedLocalEmail(t *testing.T) {
	p := &staticOAuthProvider{
		id:   "mock",
		user: provider.OAuthUser{ID: "mock-unverified-local", Email: "oauth-local-unverified@example.com", EmailVerified: true, Name: "OAuth Local Unverified"},
	}
	a := oauthTestAuth(t, p)
	signUp(t, a, "oauth-local-unverified@example.com")

	resp, _ := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider": "mock",
		"idToken":  map[string]any{"token": "valid-id-token", "accessToken": "at-unverified-local"},
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestSignInSocialImplicitLinkCanSkipLocalEmailVerification(t *testing.T) {
	p := &staticOAuthProvider{
		id:   "mock",
		user: provider.OAuthUser{ID: "mock-skip-local", Email: "oauth-skip-local@example.com", EmailVerified: true, Name: "OAuth Skip Local"},
	}
	requireLocal := false
	a := newTestAuth(func(c *auth.Config) {
		c.SocialProviders = map[string]provider.SocialProvider{p.ID(): p}
		c.Account.AccountLinking.TrustedProviders = []string{p.ID()}
		c.Account.AccountLinking.RequireLocalEmailVerified = &requireLocal
	})
	signUp(t, a, "oauth-skip-local@example.com")

	resp, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider": "mock",
		"idToken":  map[string]any{"token": "valid-id-token", "accessToken": "at-skip-local"},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
}

func TestSignInSocialDisableImplicitLinkingBlocksTrustedProvider(t *testing.T) {
	p := &staticOAuthProvider{
		id:   "mock",
		user: provider.OAuthUser{ID: "mock-disable-link", Email: "oauth-disable-link@example.com", EmailVerified: true, Name: "OAuth Disable Link"},
	}
	a := oauthTestAuth(t, p)
	cookies := signUp(t, a, "oauth-disable-link@example.com")
	userID := mustUserID(t, a, cookies)
	verified := true
	if _, err := a.Store().UpdateUser(context.Background(), userID, store.UserUpdate{EmailVerified: &verified}); err != nil {
		t.Fatalf("verify user: %v", err)
	}
	a = newTestAuth(func(c *auth.Config) {
		c.Store = a.Store()
		c.SocialProviders = map[string]provider.SocialProvider{p.ID(): p}
		c.Account.AccountLinking.TrustedProviders = []string{p.ID()}
		c.Account.AccountLinking.DisableImplicitLinking = true
	})

	resp, _ := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider": "mock",
		"idToken":  map[string]any{"token": "valid-id-token", "accessToken": "at-disable-link"},
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestSignInSocialImplicitLinkReturnsUpdatedUserInfo(t *testing.T) {
	image := "https://example.com/implicit.png"
	p := &staticOAuthProvider{
		id:   "mock",
		user: provider.OAuthUser{ID: "mock-update-link", Email: "oauth-update-link@example.com", EmailVerified: true, Name: "Provider Name", Image: &image},
	}
	a := newTestAuth(func(c *auth.Config) {
		c.SocialProviders = map[string]provider.SocialProvider{p.ID(): p}
		c.Account.AccountLinking.TrustedProviders = []string{p.ID()}
		c.Account.AccountLinking.UpdateUserInfoOnLink = true
	})
	cookies := signUp(t, a, "oauth-update-link@example.com")
	userID := mustUserID(t, a, cookies)
	verified := true
	if _, err := a.Store().UpdateUser(context.Background(), userID, store.UserUpdate{EmailVerified: &verified}); err != nil {
		t.Fatalf("verify user: %v", err)
	}

	resp, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider": "mock",
		"idToken":  map[string]any{"token": "valid-id-token", "accessToken": "at-update-link"},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	var result types.SocialSignInResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.User.Name != "Provider Name" || result.User.Image == nil || *result.User.Image != image {
		t.Fatalf("user=%+v", result.User)
	}
}

func TestOAuthCallbackCreatesSession(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	p := &staticOAuthProvider{
		id: "mock",
		user: provider.OAuthUser{
			ID: "mock-user-1", Email: "oauth-cb-unique@example.com", EmailVerified: true, Name: "OAuth CB",
		},
		tokens: provider.OAuthTokens{
			AccessToken: "at", RefreshToken: "rt", IDToken: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJtb2NrLXVzZXItMSIsImVtYWlsIjoib2F1dGgtY2JAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6Ik9BdXRoIENCIiwiaWF0IjoxfQ.",
			AccessTokenExpiresAt: &exp,
		},
	}
	a := oauthTestAuth(t, p)

	disable := true
	resp, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider":        "mock",
		"callbackURL":     "http://localhost:3000/done",
		"disableRedirect": disable,
	}, nil)
	var signIn types.SocialSignInResponse
	_ = json.Unmarshal(data, &signIn)
	parsed, err := url.Parse(signIn.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("missing state in auth url")
	}

	resp, _ = doRequest(a, http.MethodGet, "/callback/mock?code=abc&state="+url.QueryEscape(state), nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status=%d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http://localhost:3000/done") {
		t.Fatalf("redirect=%s", loc)
	}

	cookies := resp.Cookies()
	resp, data = doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	if sess.User.Email != "oauth-cb-unique@example.com" {
		t.Fatalf("session=%+v", sess)
	}
}

func TestOAuthCallbackOverridesUserInfoOnSignIn(t *testing.T) {
	image := "https://example.com/updated.png"
	p := &staticOAuthProvider{
		id:               "mock",
		user:             provider.OAuthUser{ID: "mock-override", Email: "oauth-override@example.com", EmailVerified: true, Name: "Updated OAuth", Image: &image},
		overrideUserInfo: true,
	}
	a := oauthTestAuth(t, p)
	cookies := signUp(t, a, "oauth-override@example.com")
	userID := mustUserID(t, a, cookies)
	initialName := "Initial OAuth"
	verified := true
	if _, err := a.Store().UpdateUser(context.Background(), userID, store.UserUpdate{Name: &initialName, EmailVerified: &verified}); err != nil {
		t.Fatalf("update user: %v", err)
	}

	disable := true
	resp, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider":        "mock",
		"callbackURL":     "http://localhost:3000/done",
		"disableRedirect": disable,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	var signIn types.SocialSignInResponse
	if err := json.Unmarshal(data, &signIn); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(signIn.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("missing state in auth url")
	}

	resp, _ = doRequest(a, http.MethodGet, "/callback/mock?code=abc&state="+url.QueryEscape(state), nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status=%d", resp.StatusCode)
	}
	user, err := a.Store().FindUserByEmail(context.Background(), "oauth-override@example.com")
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if user.Name != "Updated OAuth" || user.Image == nil || *user.Image != image {
		t.Fatalf("user=%+v", user)
	}
}

func TestSignInSocialFlattensAdditionalDataInOAuthState(t *testing.T) {
	p := &staticOAuthProvider{
		id:   "mock",
		user: provider.OAuthUser{ID: "mock-additional", Email: "oauth-additional@example.com", EmailVerified: true, Name: "OAuth Additional"},
	}
	a := oauthTestAuth(t, p)

	disable := true
	resp, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider":        "mock",
		"callbackURL":     "http://localhost:3000/done",
		"disableRedirect": disable,
		"additionalData": map[string]any{
			"invitedBy": "user-123",
		},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	var signIn types.SocialSignInResponse
	if err := json.Unmarshal(data, &signIn); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(signIn.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("missing state in auth url")
	}
	verification, err := a.Store().FindVerificationByIdentifier(context.Background(), constants.VerificationOAuthState+state)
	if err != nil {
		t.Fatalf("find state: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(verification.Value), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["invitedBy"] != "user-123" {
		t.Fatalf("payload=%+v", payload)
	}
	if _, ok := payload["additionalData"]; ok {
		t.Fatalf("additionalData should be flattened: %+v", payload)
	}
	if payload["callbackURL"] != "http://localhost:3000/done" || payload["oauthState"] != state {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestSignInSocialAdditionalDataCannotOverrideOAuthState(t *testing.T) {
	p := &staticOAuthProvider{
		id:   "mock",
		user: provider.OAuthUser{ID: "mock-reserved", Email: "oauth-reserved@example.com", EmailVerified: true, Name: "OAuth Reserved"},
	}
	a := oauthTestAuth(t, p)

	disable := true
	resp, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider":         "mock",
		"callbackURL":      "http://localhost:3000/done",
		"errorCallbackURL": "http://localhost:3000/error",
		"disableRedirect":  disable,
		"additionalData": map[string]any{
			"codeVerifier":  "bad-code-verifier",
			"callbackURL":   "bad-callback",
			"errorURL":      "bad-error",
			"newUserURL":    "bad-new-user",
			"link":          map[string]any{"email": "bad@example.com", "userId": "bad-user"},
			"requestSignUp": true,
			"expiresAt":     "bad-expiry",
			"oauthState":    "bad-state",
		},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	var signIn types.SocialSignInResponse
	if err := json.Unmarshal(data, &signIn); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(signIn.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("missing state in auth url")
	}
	verification, err := a.Store().FindVerificationByIdentifier(context.Background(), constants.VerificationOAuthState+state)
	if err != nil {
		t.Fatalf("find state: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(verification.Value), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["callbackURL"] != "http://localhost:3000/done" || payload["errorURL"] != "http://localhost:3000/error" || payload["oauthState"] != state {
		t.Fatalf("payload=%+v", payload)
	}
	if payload["codeVerifier"] == "bad-code-verifier" || payload["newUserURL"] == "bad-new-user" || payload["requestSignUp"] == true || payload["expiresAt"] == "bad-expiry" {
		t.Fatalf("reserved fields were overridden: %+v", payload)
	}
	if _, ok := payload["link"]; ok {
		t.Fatalf("link should not be overridden: %+v", payload)
	}
}

func TestOAuthCallbackProviderErrorUsesStateErrorCallbackURL(t *testing.T) {
	p := &staticOAuthProvider{
		id:   "mock",
		user: provider.OAuthUser{ID: "mock-err", Email: "oauth-error@example.com", EmailVerified: true, Name: "OAuth Error"},
	}
	a := oauthTestAuth(t, p)

	disable := true
	_, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider":         "mock",
		"callbackURL":      "http://localhost:3000/done",
		"errorCallbackURL": "http://localhost:3000/oauth-error",
		"disableRedirect":  disable,
	}, nil)
	var signIn types.SocialSignInResponse
	_ = json.Unmarshal(data, &signIn)
	parsed, err := url.Parse(signIn.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("missing state in auth url")
	}

	resp, _ := doRequest(a, http.MethodGet, "/callback/mock?error=access_denied&error_description=User+denied+access&state="+url.QueryEscape(state), nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status=%d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	if !strings.HasPrefix(location, "http://localhost:3000/oauth-error") || !strings.Contains(location, "error=access_denied") || !strings.Contains(location, "error_description=User+denied+access") {
		t.Fatalf("redirect=%s", location)
	}
}

func TestOAuthCallbackExpiredStateRedirectsToMismatch(t *testing.T) {
	p := &staticOAuthProvider{
		id: "mock",
		user: provider.OAuthUser{
			ID: "mock-expired", Email: "oauth-expired@example.com", EmailVerified: true, Name: "OAuth Expired",
		},
	}
	a := oauthTestAuth(t, p)

	disable := true
	_, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider":        "mock",
		"callbackURL":     "http://localhost:3000/done",
		"disableRedirect": disable,
	}, nil)
	var signIn types.SocialSignInResponse
	_ = json.Unmarshal(data, &signIn)
	parsed, err := url.Parse(signIn.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("missing state in auth url")
	}

	verification, err := a.Store().FindVerificationByIdentifier(context.Background(), constants.VerificationOAuthState+state)
	if err != nil {
		t.Fatalf("find state: %v", err)
	}
	verification.ExpiresAt = time.Now().Add(-time.Minute)
	if err := a.Store().CreateVerification(context.Background(), verification); err != nil {
		t.Fatalf("expire state: %v", err)
	}

	resp, _ := doRequest(a, http.MethodGet, "/callback/mock?code=abc&state="+url.QueryEscape(state), nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status=%d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	if !strings.Contains(location, "error=state_mismatch") {
		t.Fatalf("redirect=%s", location)
	}
}

func TestOAuthCallbackStateDeleteFails(t *testing.T) {
	p := &staticOAuthProvider{
		id: "mock",
		user: provider.OAuthUser{
			ID: "mock-delete-fail", Email: "oauth-delete-fail@example.com", EmailVerified: true, Name: "OAuth Delete Fail",
		},
	}
	a := newTestAuth(func(c *auth.Config) {
		c.Store = wrapStore("DeleteVerificationByIdentifier")
		c.SocialProviders = map[string]provider.SocialProvider{p.ID(): p}
		c.Account.AccountLinking.TrustedProviders = []string{p.ID()}
	})

	disable := true
	_, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider":        "mock",
		"callbackURL":     "http://localhost:3000/done",
		"disableRedirect": disable,
	}, nil)
	var signIn types.SocialSignInResponse
	_ = json.Unmarshal(data, &signIn)
	parsed, err := url.Parse(signIn.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("missing state in auth url")
	}

	resp, _ := doRequest(a, http.MethodGet, "/callback/mock?code=abc&state="+url.QueryEscape(state), nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status=%d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	if !strings.Contains(location, "error=state_mismatch") {
		t.Fatalf("redirect=%s", location)
	}
}

func TestOAuthCallbackPassesUserDataToProvider(t *testing.T) {
	p := &staticOAuthProvider{
		id: "mock",
		user: provider.OAuthUser{
			ID: "mock-user-data", Email: "oauth-user-data@example.com", EmailVerified: true, Name: "OAuth User Data",
		},
		tokens: provider.OAuthTokens{AccessToken: "at-user"},
	}
	a := oauthTestAuth(t, p)

	disable := true
	_, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider":        "mock",
		"callbackURL":     "http://localhost:3000/done",
		"disableRedirect": disable,
	}, nil)
	var signIn types.SocialSignInResponse
	_ = json.Unmarshal(data, &signIn)
	parsed, err := url.Parse(signIn.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("missing state in auth url")
	}
	userData := url.QueryEscape(`{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"ada@example.com"}`)

	resp, _ := doRequest(a, http.MethodGet, "/callback/mock?code=abc&state="+url.QueryEscape(state)+"&user="+userData, nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status=%d", resp.StatusCode)
	}
	name, ok := p.seenTokens.User["name"].(map[string]any)
	if !ok || name["firstName"] != "Ada" || p.seenTokens.User["email"] != "ada@example.com" {
		t.Fatalf("user data=%+v", p.seenTokens.User)
	}
}

func TestOAuthPostCallbackRedirectsToGet(t *testing.T) {
	p := &staticOAuthProvider{
		id: "mock",
		user: provider.OAuthUser{
			ID: "mock-user-post", Email: "oauth-post@example.com", EmailVerified: true, Name: "OAuth Post",
		},
	}
	a := oauthTestAuth(t, p)

	disable := true
	_, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider":        "mock",
		"callbackURL":     "http://localhost:3000/done",
		"disableRedirect": disable,
	}, nil)
	var signIn types.SocialSignInResponse
	_ = json.Unmarshal(data, &signIn)
	parsed, err := url.Parse(signIn.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	resp, _ := doFormRequest(a, http.MethodPost, "/callback/mock", url.Values{
		"code":  {"abc"},
		"state": {state},
	}, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Path != "/api/auth/callback/mock" || location.Query().Get("code") != "abc" || location.Query().Get("state") != state {
		t.Fatalf("location = %s", location.String())
	}
}

func TestOAuthPostCallbackQueryOverridesBody(t *testing.T) {
	p := &staticOAuthProvider{
		id:   "mock",
		user: provider.OAuthUser{ID: "mock-user-post-query", Email: "oauth-post-query@example.com", EmailVerified: true, Name: "OAuth Post Query"},
	}
	a := oauthTestAuth(t, p)

	resp, _ := doFormRequest(a, http.MethodPost, "/callback/mock?code=query-code&state=query-state", url.Values{
		"code":  {"body-code"},
		"state": {"body-state"},
	}, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("code") != "query-code" || location.Query().Get("state") != "query-state" {
		t.Fatalf("location = %s", location.String())
	}
}

func TestGoogleProviderWiring(t *testing.T) {
	a := newTestAuth(func(c *auth.Config) {
		c.Google = auth.GoogleProviderConfig{ClientID: "gid", ClientSecret: "gsecret"}
	})
	resp, data := doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider": "google", "disableRedirect": true,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
}
