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

func TestSignInSocialIDTokenPreservesStoredAccountTokens(t *testing.T) {
	a := testAuthWithGoogle(t, func(c *auth.Config) {
		c.SocialProviders = map[string]provider.SocialProvider{
			"google": &testSocialProvider{
				id:          "google",
				verifyToken: func(_ context.Context, _, _ string) (bool, error) { return true, nil },
			},
		}
	})
	cookies := signUp(t, a, "linker@example.com")
	resp, data := doRequest(a, http.MethodPost, "/link-social", map[string]any{
		"provider": "google",
		"idToken": map[string]any{
			"token":        "old-id-token",
			"accessToken":  "old-at",
			"refreshToken": "old-rt",
			"scopes":       []string{"profile", "email"},
		},
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d %s", resp.StatusCode, data)
	}
	userID := mustUserID(t, a, cookies)
	accountID := linkedAccountID(t, a, cookies, "google")

	resp, data = doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider": "google",
		"idToken": map[string]any{
			"token":       "new-id-token",
			"accessToken": "new-at",
		},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in status=%d %s", resp.StatusCode, data)
	}

	accounts, err := a.Store().ListAccountsByUserID(context.Background(), userID)
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	for _, account := range accounts {
		if account.ProviderID != "google" || account.AccountID != accountID {
			continue
		}
		if account.AccessToken != "new-at" || account.RefreshToken != "old-rt" || account.IDToken != "old-id-token" || account.Scope != "profile,email" {
			t.Fatalf("account=%+v", account)
		}
		return
	}
	t.Fatalf("linked account not found")
}

func TestSignInSocialLinkedAccountUpdateFails(t *testing.T) {
	fs := wrapStore("UpdateAccount").(*failStore)
	a := testAuthWithGoogle(t, func(c *auth.Config) {
		c.Store = fs
		c.SocialProviders = map[string]provider.SocialProvider{
			"google": &testSocialProvider{
				id:          "google",
				verifyToken: func(_ context.Context, _, _ string) (bool, error) { return true, nil },
			},
		}
	})
	cookies := signUp(t, a, "linker@example.com")
	resp, data := doRequest(a, http.MethodPost, "/link-social", map[string]any{
		"provider": "google",
		"idToken": map[string]any{
			"token":       "old-id-token",
			"accessToken": "old-at",
		},
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d %s", resp.StatusCode, data)
	}

	resp, _ = doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider": "google",
		"idToken": map[string]any{
			"token":       "new-id-token",
			"accessToken": "new-at",
		},
	}, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestSignInSocialEmailVerificationUpdateFails(t *testing.T) {
	fs := wrapStore("").(*failStore)
	a := testAuthWithGoogle(t, func(c *auth.Config) {
		c.Store = fs
		c.SocialProviders = map[string]provider.SocialProvider{
			"google": &testSocialProvider{
				id:          "google",
				verifyToken: func(_ context.Context, _, _ string) (bool, error) { return true, nil },
			},
		}
	})
	cookies := signUp(t, a, "linker@example.com")
	resp, data := doRequest(a, http.MethodPost, "/link-social", map[string]any{
		"provider": "google",
		"idToken": map[string]any{
			"token":       "old-id-token",
			"accessToken": "old-at",
		},
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d %s", resp.StatusCode, data)
	}
	fs.failOn = "UpdateUser"

	resp, _ = doRequest(a, http.MethodPost, "/sign-in/social", map[string]any{
		"provider": "google",
		"idToken": map[string]any{
			"token":       "new-id-token",
			"accessToken": "new-at",
		},
	}, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestLinkSocialDoesNotUpdateUserInfoByDefault(t *testing.T) {
	a := testAuthWithGoogle(t, func(c *auth.Config) {
		c.SocialProviders = map[string]provider.SocialProvider{
			"google": &testSocialProvider{
				id: "google",
				userInfo: func(_ context.Context, _ provider.OAuthTokens) (*provider.UserInfo, error) {
					return &provider.UserInfo{
						User: provider.OAuthUser{ID: "gh-default-profile", Name: "Provider Profile", Email: "link-default-profile@example.com", EmailVerified: true},
					}, nil
				},
			},
		}
	})
	cookies := signUp(t, a, "link-default-profile@example.com")
	resp, data := doRequest(a, http.MethodGet, "/get-session?disableCookieCache=true", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session status=%d %s", resp.StatusCode, data)
	}
	var sess types.SessionResponse
	if err := json.Unmarshal(data, &sess); err != nil {
		t.Fatal(err)
	}
	emptyName := ""
	if _, err := a.Store().UpdateUser(context.Background(), sess.User.ID, store.UserUpdate{Name: &emptyName}); err != nil {
		t.Fatalf("update user: %v", err)
	}

	resp, data = doRequest(a, http.MethodPost, "/link-social", map[string]any{
		"provider": "google",
		"idToken": map[string]any{
			"token": "valid-id-token",
		},
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d %s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodGet, "/get-session?disableCookieCache=true", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session status=%d %s", resp.StatusCode, data)
	}
	if err := json.Unmarshal(data, &sess); err != nil {
		t.Fatal(err)
	}
	if sess.User.Name != "" {
		t.Fatalf("name=%q", sess.User.Name)
	}
}

func TestLinkSocialUpdatesUserInfoWhenEnabled(t *testing.T) {
	image := "https://example.com/avatar.png"
	a := testAuthWithGoogle(t, func(c *auth.Config) {
		c.Account.AccountLinking.UpdateUserInfoOnLink = true
		c.SocialProviders = map[string]provider.SocialProvider{
			"google": &testSocialProvider{
				id: "google",
				userInfo: func(_ context.Context, _ provider.OAuthTokens) (*provider.UserInfo, error) {
					return &provider.UserInfo{
						User: provider.OAuthUser{
							ID: "gh-profile", Name: "Provider Profile", Email: "link-profile@example.com", EmailVerified: true, Image: &image,
						},
					}, nil
				},
			},
		}
	})
	cookies := signUp(t, a, "link-profile@example.com")
	resp, data := doRequest(a, http.MethodPost, "/link-social", map[string]any{
		"provider": "google",
		"idToken": map[string]any{
			"token": "valid-id-token",
		},
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d %s", resp.StatusCode, data)
	}

	resp, data = doRequest(a, http.MethodGet, "/get-session?disableCookieCache=true", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session status=%d %s", resp.StatusCode, data)
	}
	var sess types.SessionResponse
	if err := json.Unmarshal(data, &sess); err != nil {
		t.Fatal(err)
	}
	if sess.User.Name != "Provider Profile" || sess.User.Image == nil || *sess.User.Image != image {
		t.Fatalf("user=%+v", sess.User)
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

	accountID := linkedAccountID(t, a, cookies, "google")
	resp, data = doRequest(a, http.MethodGet, "/account-info?providerId=google&accountId="+accountID, nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	var result types.AccountInfoResponse
	_ = json.Unmarshal(data, &result)
	if result.User.ID != "gh-123" || result.Data["login"] != "linker" {
		t.Fatalf("result=%+v", result)
	}
}

func TestAccountInfoRequiresAccountID(t *testing.T) {
	a := testAuthWithGoogle(t)
	cookies := signUp(t, a, "linker@example.com")
	resp, data := linkGoogleAccount(t, a, cookies, "at-info", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d %s", resp.StatusCode, data)
	}

	resp, _ = doRequest(a, http.MethodGet, "/account-info?providerId=google", nil, cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestAccountInfoPassesScopesToProvider(t *testing.T) {
	var seenScopes []string
	a := testAuthWithGoogle(t, func(c *auth.Config) {
		c.SocialProviders = map[string]provider.SocialProvider{
			"google": &testSocialProvider{
				id: "google",
				userInfo: func(_ context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error) {
					seenScopes = append([]string(nil), tokens.Scopes...)
					return &provider.UserInfo{
						User: provider.OAuthUser{ID: "gh-scoped", Name: "Scoped", Email: "linker@example.com", EmailVerified: true},
						Data: map[string]any{"login": "scoped"},
					}, nil
				},
			},
		}
	})
	cookies := signUp(t, a, "linker@example.com")
	resp, data := doRequest(a, http.MethodPost, "/link-social", map[string]any{
		"provider": "google",
		"idToken": map[string]any{
			"token":       "valid-id-token",
			"accessToken": "scoped-at",
			"scopes":      []string{"profile", "email"},
		},
	}, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d %s", resp.StatusCode, data)
	}
	accountID := linkedAccountID(t, a, cookies, "google")

	resp, data = doRequest(a, http.MethodGet, "/account-info?providerId=google&accountId="+accountID, nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d %s", resp.StatusCode, data)
	}
	if len(seenScopes) != 2 || seenScopes[0] != "profile" || seenScopes[1] != "email" {
		t.Fatalf("scopes=%v", seenScopes)
	}
}

func TestAccountRoutesRejectUserIDWithoutSession(t *testing.T) {
	a := testAuthWithGoogle(t)
	cookies := signUp(t, a, "linker@example.com")
	resp, data := linkGoogleAccount(t, a, cookies, "at-info", "rt-info")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("link status=%d %s", resp.StatusCode, data)
	}
	userID := mustUserID(t, a, cookies)
	accountID := linkedAccountID(t, a, cookies, "google")

	resp, _ = doRequest(a, http.MethodGet, "/account-info?accountId="+accountID+"&userId="+userID, nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("account-info status=%d", resp.StatusCode)
	}

	resp, _ = doRequest(a, http.MethodPost, "/get-access-token", map[string]any{
		"providerId": "google",
		"userId":     userID,
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("get-access-token status=%d", resp.StatusCode)
	}

	resp, _ = doRequest(a, http.MethodPost, "/refresh-token", map[string]any{
		"providerId": "google",
		"userId":     userID,
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh-token status=%d", resp.StatusCode)
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
	if result.AccessToken != "new-access" || len(result.Scopes) != 0 {
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

func linkedAccountID(t testingT, a *auth.Auth, cookies []*http.Cookie, providerID string) string {
	t.Helper()
	resp, data := doRequest(a, http.MethodGet, "/list-accounts", nil, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status=%d %s", resp.StatusCode, data)
	}
	var accounts []types.AccountResponse
	if err := json.Unmarshal(data, &accounts); err != nil {
		t.Fatalf("decode accounts: %v", err)
	}
	for _, account := range accounts {
		if account.ProviderID == providerID {
			return account.AccountID
		}
	}
	t.Fatalf("provider account not found: %s", providerID)
	return ""
}

func mustUserID(t *testing.T, a *auth.Auth, cookies []*http.Cookie) string {
	t.Helper()
	_, data := doRequest(a, http.MethodGet, "/get-session", nil, cookies)
	var sess types.SessionResponse
	_ = json.Unmarshal(data, &sess)
	return sess.User.ID
}
