package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

type testSocialProvider struct {
	id          string
	authURL     string
	verifyToken func(ctx context.Context, token, nonce string) (bool, error)
	userInfo    func(ctx context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error)
	refresh     func(ctx context.Context, refreshToken string) (*provider.OAuthTokens, error)
}

func (p *testSocialProvider) ID() string { return p.id }

func (p *testSocialProvider) CreateAuthorizationURL(_ context.Context, _ provider.AuthorizationURLOpts) (string, error) {
	return p.authURL, nil
}

func (p *testSocialProvider) VerifyIDToken(ctx context.Context, token, nonce string) (bool, error) {
	if p.verifyToken != nil {
		return p.verifyToken(ctx, token, nonce)
	}
	return token == "valid-id-token", nil
}

func (p *testSocialProvider) GetUserInfo(ctx context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error) {
	if p.userInfo != nil {
		return p.userInfo(ctx, tokens)
	}
	return &provider.UserInfo{
		User: provider.OAuthUser{
			ID: "gh-123", Name: "GitHub User", Email: "linker@example.com", EmailVerified: true,
		},
		Data: map[string]any{"login": "linker"},
	}, nil
}

func (p *testSocialProvider) RefreshAccessToken(ctx context.Context, refreshToken string) (*provider.OAuthTokens, error) {
	if p.refresh != nil {
		return p.refresh(ctx, refreshToken)
	}
	exp := time.Now().Add(time.Hour)
	return &provider.OAuthTokens{
		AccessToken: "new-access", RefreshToken: "new-refresh", AccessTokenExpiresAt: &exp,
		Scopes: []string{"read"},
	}, nil
}

func testAuthWithGoogle(t *testing.T, opts ...func(*auth.Config)) *auth.Auth {
	t.Helper()
	providers := map[string]provider.SocialProvider{
		"google": &testSocialProvider{id: "google", authURL: "https://accounts.google.com/o/oauth2/auth"},
	}
	all := append([]func(*auth.Config){
		func(c *auth.Config) {
			c.SocialProviders = providers
			c.Account.AccountLinking.TrustedProviders = []string{"google"}
		},
	}, opts...)
	return newTestAuth(all...)
}

func TestLinkSocialWithIDToken(t *testing.T) {
	a := testAuthWithGoogle(t)
	cookies := signUp(t, a, "linker@example.com")

	resp, data := doRequest(a, http.MethodPost, "/link-social", map[string]any{
		"provider": "google",
		"idToken": map[string]any{
			"token":        "valid-id-token",
			"accessToken":  "at-1",
			"refreshToken": "rt-1",
		},
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	var result types.LinkSocialResponse
	_ = json.Unmarshal(data, &result)
	if !result.Status || result.Redirect {
		t.Fatalf("result=%+v", result)
	}

	resp, data = doRequest(a, http.MethodGet, "/list-accounts", nil, cookies)
	var accounts []types.AccountResponse
	_ = json.Unmarshal(data, &accounts)
	if len(accounts) != 2 {
		t.Fatalf("accounts=%v", accounts)
	}
}

func TestLinkSocialDifferentEmailRejected(t *testing.T) {
	a := testAuthWithGoogle(t, func(c *auth.Config) {
		c.SocialProviders = map[string]provider.SocialProvider{
			"google": &testSocialProvider{
				id: "google",
				userInfo: func(_ context.Context, _ provider.OAuthTokens) (*provider.UserInfo, error) {
					return &provider.UserInfo{
						User: provider.OAuthUser{ID: "x", Email: "other@example.com", EmailVerified: true},
					}, nil
				},
			},
		}
	})
	cookies := signUp(t, a, "linker@example.com")
	resp, _ := doRequest(a, http.MethodPost, "/link-social", map[string]any{
		"provider": "google",
		"idToken":  map[string]any{"token": "valid-id-token"},
	}, cookies)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestLinkSocialRedirect(t *testing.T) {
	a := testAuthWithGoogle(t)
	cookies := signUp(t, a, "redirect@example.com")
	resp, data := doRequest(a, http.MethodPost, "/link-social", map[string]any{
		"provider": "google",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	var result types.LinkSocialResponse
	_ = json.Unmarshal(data, &result)
	if result.URL == "" || !result.Redirect {
		t.Fatalf("result=%+v", result)
	}
}

func TestGetAccessToken(t *testing.T) {
	a := testAuthWithGoogle(t)
	cookies := signUp(t, a, "linker@example.com")
	resp, data := linkGoogleAccount(t, a, cookies, "stored-at", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d %s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/get-access-token", map[string]any{
		"providerId": "google",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	var result types.AccessTokenResponse
	_ = json.Unmarshal(data, &result)
	if result.AccessToken == "" {
		t.Fatalf("result=%+v", result)
	}
}

func TestRefreshTokenEndpoint(t *testing.T) {
	a := testAuthWithGoogle(t)
	cookies := signUp(t, a, "linker@example.com")
	resp, data := linkGoogleAccount(t, a, cookies, "", "rt-old")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d %s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodPost, "/refresh-token", map[string]any{
		"providerId": "google",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	var result types.RefreshTokenResponse
	_ = json.Unmarshal(data, &result)
	if result.AccessToken != "new-access" || result.ProviderID != "google" {
		t.Fatalf("result=%+v", result)
	}
}

func TestAccountInfo(t *testing.T) {
	a := testAuthWithGoogle(t)
	cookies := signUp(t, a, "linker@example.com")
	resp, data := linkGoogleAccount(t, a, cookies, "at-info", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d %s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodGet, "/account-info?providerId=google", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	var result types.AccountInfoResponse
	_ = json.Unmarshal(data, &result)
	if result.User.ID != "gh-123" || result.Data["login"] != "linker" {
		t.Fatalf("result=%+v", result)
	}
}

func TestGetAccessTokenAutoRefresh(t *testing.T) {
	expired := time.Now().Add(-time.Minute)
	a := testAuthWithGoogle(t)
	cookies := signUp(t, a, "linker@example.com")
	resp, data := linkGoogleAccount(t, a, cookies, "expired-at", "rt-1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d %s", resp.StatusCode, data)
	}

	ctx := context.Background()
	st := a.Store()
	accounts, _ := st.ListAccountsByUserID(ctx, mustUserID(t, a, cookies))
	for _, acc := range accounts {
		if acc.ProviderID == "google" {
			_, _ = st.UpdateAccount(ctx, acc.ID, store.AccountUpdate{
				AccessTokenExpiresAt: &expired,
			})
		}
	}

	resp, data = doRequest(a, http.MethodPost, "/get-access-token", map[string]any{
		"providerId": "google",
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	var result types.AccessTokenResponse
	_ = json.Unmarshal(data, &result)
	if result.AccessToken != "new-access" || len(result.Scopes) != 1 || result.Scopes[0] != "read" {
		t.Fatalf("expected refreshed token, got %+v", result)
	}
}

func linkGoogleAccount(t testingT, a *auth.Auth, cookies []*http.Cookie, accessToken, refreshToken string) (*http.Response, []byte) {
	t.Helper()
	body := map[string]any{
		"provider": "google",
		"idToken": map[string]any{
			"token": "valid-id-token",
		},
	}
	idToken := body["idToken"].(map[string]any)
	if accessToken != "" {
		idToken["accessToken"] = accessToken
	}
	if refreshToken != "" {
		idToken["refreshToken"] = refreshToken
	}
	return doRequest(a, http.MethodPost, "/link-social", body, cookies)
}

func mustUserID(t *testing.T, a *auth.Auth, cookies []*http.Cookie) string {
	t.Helper()
	_, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	return sess.User.ID
}
