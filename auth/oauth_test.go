package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/types"
)

type staticOAuthProvider struct {
	id         string
	user       provider.OAuthUser
	tokens     provider.OAuthTokens
	authURL    string
	opts       provider.AuthorizationURLOpts
	seenTokens provider.OAuthTokens
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
