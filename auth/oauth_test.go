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
	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/types"
)

type staticOAuthProvider struct {
	id      string
	user    provider.OAuthUser
	tokens  provider.OAuthTokens
	authURL string
}

func (p *staticOAuthProvider) ID() string { return p.id }

func (p *staticOAuthProvider) CreateAuthorizationURL(_ context.Context, opts provider.AuthorizationURLOpts) (string, error) {
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

func (p *staticOAuthProvider) GetUserInfo(_ context.Context, _ provider.OAuthTokens) (*provider.UserInfo, error) {
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
