package plugins_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/provider"
)

func newGenericOAuthCallbackServer(t *testing.T, accountID string, name string, email string, tokenResponse string) (*httptest.Server, *bool) {
	t.Helper()
	tokenRequestSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenRequestSeen = true
			if r.Method != http.MethodPost {
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			if err := r.ParseForm(); err != nil {
				http.Error(w, "form", http.StatusBadRequest)
				return
			}
			if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "code" {
				http.Error(w, "form", http.StatusBadRequest)
				return
			}
			if r.Form.Get("redirect_uri") != "http://localhost:8080/api/auth/oauth2/callback/oidc" {
				http.Error(w, "redirect_uri", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(tokenResponse))
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer access-token" {
				http.Error(w, "authorization", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]any{
				"sub":            accountID,
				"name":           name,
				"email":          email,
				"email_verified": true,
				"picture":        "https://idp.example.com/avatar.png",
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	return server, &tokenRequestSeen
}

func genericOAuthTestIDToken(claims map[string]any) string {
	raw, _ := json.Marshal(claims)
	return "hdr." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

func completeGenericOAuthSignIn(t *testing.T, a *auth.Auth, providerID string) *httptest.ResponseRecorder {
	t.Helper()
	signIn := post(t, a, "/sign-in/oauth2", `{"providerId":"`+providerID+`","callbackURL":"https://app.example.com/dashboard"}`)
	if signIn.Code != http.StatusOK {
		t.Fatalf("status %d body %s", signIn.Code, signIn.Body.String())
	}
	var signInBody struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(signIn.Body.Bytes(), &signInBody); err != nil {
		t.Fatal(err)
	}
	signInURL, err := url.Parse(signInBody.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := signInURL.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", signInBody.URL)
	}
	callback := get(t, a, "/oauth2/callback/"+providerID+"?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	return callback
}

func postForm(t *testing.T, a *auth.Auth, path string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	req.Header.Set(constants.HeaderContentType, "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	return w
}

func TestGenericOAuthSignInAuthorizationURLConfig(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize?prompt=old&tenant=workspace",
				TokenURL:         "https://idp.example.com/oauth/token",
				UserInfoURL:      "https://idp.example.com/oauth/userinfo",
				RedirectURI:      "https://app.example.com/oauth/callback",
				Scopes:           []string{"openid", "email"},
				ResponseType:     "id_token",
				ResponseMode:     "form_post",
				PKCE:             true,
				Prompt:           "select_account",
				AccessType:       "offline",
				AuthorizationURLParams: map[string]string{
					"audience":      "api",
					"response_type": "code",
				},
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"/dashboard","disableRedirect":true,"scopes":["calendar"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL      string `json:"url"`
		Redirect bool   `json:"redirect"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Redirect {
		t.Fatalf("redirect=%v", body.Redirect)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "https" || parsed.Host != "idp.example.com" || parsed.Path != "/oauth/authorize" {
		t.Fatalf("url=%s", body.URL)
	}
	query := parsed.Query()
	if query.Get("client_id") != "client" || query.Get("response_type") != "code" || query.Get("scope") != "calendar openid email" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("prompt") != "select_account" || query.Get("tenant") != "workspace" || query.Get("audience") != "api" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("response_mode") != "form_post" || query.Get("access_type") != "offline" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("redirect_uri") != "https://app.example.com/oauth/callback" {
		t.Fatalf("redirect_uri=%q", query.Get("redirect_uri"))
	}
	if query.Get("state") == "" {
		t.Fatalf("state missing: %s", query.Encode())
	}
	if values := query["prompt"]; len(values) != 1 {
		t.Fatalf("prompt values=%v", values)
	}
}

func TestGenericOAuthLinkReturnsAuthorizationURL(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize?tenant=workspace",
				TokenURL:         "https://idp.example.com/oauth/token",
				Scopes:           []string{"openid", "email"},
				PKCE:             true,
				Prompt:           "consent",
				AccessType:       "offline",
				AuthorizationURLParams: map[string]string{
					"audience": "api",
				},
			},
		},
	}))

	signUp := post(t, a, "/sign-up/email", `{"name":"Link User","email":"generic-oauth-link@example.com","password":"password123"}`)
	if signUp.Code != http.StatusOK {
		t.Fatalf("status %d body %s", signUp.Code, signUp.Body.String())
	}
	w := postWithCookies(t, a, "/oauth2/link", `{"providerId":"oidc","callbackURL":"https://app.example.com/settings","scopes":["repo"]}`, signUp.Result().Cookies())
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL      string `json:"url"`
		Redirect bool   `json:"redirect"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Redirect {
		t.Fatalf("redirect=%v", body.Redirect)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "https" || parsed.Host != "idp.example.com" || parsed.Path != "/oauth/authorize" {
		t.Fatalf("url=%s", body.URL)
	}
	query := parsed.Query()
	if query.Get("client_id") != "client" || query.Get("response_type") != "code" || query.Get("scope") != "repo" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("prompt") != "consent" || query.Get("access_type") != "offline" || query.Get("audience") != "api" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("tenant") != "workspace" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("redirect_uri") != "http://localhost:8080/api/auth/oauth2/callback/oidc" {
		t.Fatalf("redirect_uri=%q", query.Get("redirect_uri"))
	}
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		t.Fatalf("query=%s", query.Encode())
	}
	if query.Get("state") == "" {
		t.Fatalf("state missing: %s", query.Encode())
	}
}

func TestGenericOAuthCallbackRedirectsToStoredCallbackURL(t *testing.T) {
	oauthServer, tokenRequestSeen := newGenericOAuthCallbackServer(t, "oidc-account", "OIDC User", "OIDC@EXAMPLE.COM", `{"access_token":"access-token","refresh_token":"refresh-token","scope":"openid email","expires_in":3600}`)
	defer oauthServer.Close()

	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         oauthServer.URL + "/token",
				UserInfoURL:      oauthServer.URL + "/userinfo",
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", body.URL)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	if location := callback.Header().Get("Location"); location != "https://app.example.com/dashboard" {
		t.Fatalf("Location=%q", location)
	}
	if !*tokenRequestSeen {
		t.Fatal("expected token request")
	}
	user, err := a.Store().FindUserByEmail(context.Background(), "oidc@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if user.Name != "OIDC User" || !user.EmailVerified {
		t.Fatalf("user=%+v", user)
	}
	account, err := a.Store().FindAccountByProviderAndAccountID(context.Background(), "oidc", "oidc-account")
	if err != nil {
		t.Fatal(err)
	}
	if account.UserID != user.ID || account.AccessToken != "access-token" || account.RefreshToken != "refresh-token" || account.Scope != "openid,email" {
		t.Fatalf("account=%+v", account)
	}
	if len(callback.Result().Cookies()) == 0 {
		t.Fatal("expected session cookie")
	}
}

func TestGenericOAuthCallbackAcceptsFormPost(t *testing.T) {
	oauthServer, tokenRequestSeen := newGenericOAuthCallbackServer(t, "form-post-account", "Form Post User", "generic-oauth-form-post@example.com", `{"access_token":"access-token","refresh_token":"refresh-token","scope":"openid email","expires_in":3600}`)
	defer oauthServer.Close()

	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         oauthServer.URL + "/token",
				UserInfoURL:      oauthServer.URL + "/userinfo",
				ResponseMode:     "form_post",
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", body.URL)
	}
	if responseMode := parsed.Query().Get("response_mode"); responseMode != "form_post" {
		t.Fatalf("response_mode=%q", responseMode)
	}

	callback := postForm(t, a, "/oauth2/callback/oidc", url.Values{
		"code":  {"code"},
		"state": {state},
	})
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	if location := callback.Header().Get("Location"); location != "https://app.example.com/dashboard" {
		t.Fatalf("Location=%q", location)
	}
	if !*tokenRequestSeen {
		t.Fatal("expected token endpoint request")
	}
	user, err := a.Store().FindUserByEmail(context.Background(), "generic-oauth-form-post@example.com")
	if err != nil {
		t.Fatal(err)
	}
	account, err := a.Store().FindAccountByProviderAndAccountID(context.Background(), "oidc", "form-post-account")
	if err != nil {
		t.Fatal(err)
	}
	if account.UserID != user.ID || account.AccessToken != "access-token" {
		t.Fatalf("account=%+v user=%+v", account, user)
	}
}

func TestGenericOAuthCallbackUsesIDTokenUserInfo(t *testing.T) {
	idToken := genericOAuthTestIDToken(map[string]any{
		"sub":            "id-token-account",
		"email":          "ID-TOKEN@EXAMPLE.COM",
		"name":           "ID Token User",
		"email_verified": true,
		"picture":        "https://idp.example.com/id-token.png",
	})
	tokenResponse, err := json.Marshal(map[string]string{
		"access_token": "access-token",
		"id_token":     idToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(tokenResponse)
		case "/userinfo":
			t.Fatal("userinfo endpoint should not be called when id_token is present")
		default:
			http.NotFound(w, r)
		}
	}))
	defer oauthServer.Close()

	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         oauthServer.URL + "/token",
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", body.URL)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	user, err := a.Store().FindUserByEmail(context.Background(), "id-token@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if user.Name != "ID Token User" || !user.EmailVerified {
		t.Fatalf("user=%+v", user)
	}
	account, err := a.Store().FindAccountByProviderAndAccountID(context.Background(), "oidc", "id-token-account")
	if err != nil {
		t.Fatal(err)
	}
	if account.UserID != user.ID || account.IDToken != idToken {
		t.Fatalf("account=%+v user=%+v", account, user)
	}
}

func TestGenericOAuthCallbackOverridesUserInfoOnSignIn(t *testing.T) {
	profileName := "Initial Name"
	profileEmailVerified := false
	profileImage := "https://idp.example.com/initial.png"
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         "https://idp.example.com/oauth/token",
				OverrideUserInfo: true,
				GetToken: func(_ context.Context, _ plugins.GenericOAuthGetTokenParams) (*provider.OAuthTokens, error) {
					return &provider.OAuthTokens{AccessToken: "access-token"}, nil
				},
				GetUserInfo: func(_ context.Context, _ provider.OAuthTokens) (*provider.UserInfo, error) {
					return &provider.UserInfo{
						User: provider.OAuthUser{
							ID:            "override-account",
							Name:          profileName,
							Email:         "override-user@example.com",
							Image:         &profileImage,
							EmailVerified: profileEmailVerified,
						},
					}, nil
				},
			},
		},
	}))

	first := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard"}`)
	if first.Code != http.StatusOK {
		t.Fatalf("status %d body %s", first.Code, first.Body.String())
	}
	var firstBody struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstBody); err != nil {
		t.Fatal(err)
	}
	firstURL, err := url.Parse(firstBody.URL)
	if err != nil {
		t.Fatal(err)
	}
	firstState := firstURL.Query().Get("state")
	if firstState == "" {
		t.Fatalf("state missing: %s", firstBody.URL)
	}
	firstCallback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(firstState))
	if firstCallback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", firstCallback.Code, firstCallback.Body.String())
	}

	profileName = "Updated Name"
	profileEmailVerified = true
	profileImage = "https://idp.example.com/updated.png"
	second := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard"}`)
	if second.Code != http.StatusOK {
		t.Fatalf("status %d body %s", second.Code, second.Body.String())
	}
	var secondBody struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &secondBody); err != nil {
		t.Fatal(err)
	}
	secondURL, err := url.Parse(secondBody.URL)
	if err != nil {
		t.Fatal(err)
	}
	secondState := secondURL.Query().Get("state")
	if secondState == "" {
		t.Fatalf("state missing: %s", secondBody.URL)
	}
	secondCallback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(secondState))
	if secondCallback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", secondCallback.Code, secondCallback.Body.String())
	}

	user, err := a.Store().FindUserByEmail(context.Background(), "override-user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if user.Name != "Updated Name" || !user.EmailVerified || user.Image == nil || *user.Image != "https://idp.example.com/updated.png" {
		t.Fatalf("user=%+v", user)
	}
}

func TestGenericOAuthCallbackLinksAccount(t *testing.T) {
	oauthServer, tokenRequestSeen := newGenericOAuthCallbackServer(t, "link-account", "Link User", "generic-oauth-link-callback@example.com", `{"access_token":"access-token","refresh_token":"refresh-token","scope":"openid email","expires_in":3600}`)
	defer oauthServer.Close()

	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         oauthServer.URL + "/token",
				UserInfoURL:      oauthServer.URL + "/userinfo",
			},
		},
	}))

	signUp := post(t, a, "/sign-up/email", `{"name":"Link User","email":"generic-oauth-link-callback@example.com","password":"password123"}`)
	if signUp.Code != http.StatusOK {
		t.Fatalf("status %d body %s", signUp.Code, signUp.Body.String())
	}
	user, err := a.Store().FindUserByEmail(context.Background(), "generic-oauth-link-callback@example.com")
	if err != nil {
		t.Fatal(err)
	}
	link := postWithCookies(t, a, "/oauth2/link", `{"providerId":"oidc","callbackURL":"https://app.example.com/settings"}`, signUp.Result().Cookies())
	if link.Code != http.StatusOK {
		t.Fatalf("status %d body %s", link.Code, link.Body.String())
	}
	var linkBody struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(link.Body.Bytes(), &linkBody); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(linkBody.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", linkBody.URL)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	if location := callback.Header().Get("Location"); location != "https://app.example.com/settings" {
		t.Fatalf("Location=%q", location)
	}
	if !*tokenRequestSeen {
		t.Fatal("expected token request")
	}
	account, err := a.Store().FindAccountByProviderAndAccountID(context.Background(), "oidc", "link-account")
	if err != nil {
		t.Fatal(err)
	}
	if account.UserID != user.ID || account.AccessToken != "access-token" {
		t.Fatalf("account=%+v user=%+v", account, user)
	}
}

func TestGenericOAuthCallbackAppliesAccessTokenExpiresInFallback(t *testing.T) {
	oauthServer, _ := newGenericOAuthCallbackServer(t, "expires-account", "Expires User", "generic-oauth-expires@example.com", `{"access_token":"access-token","refresh_token":"refresh-token","scope":"openid email"}`)
	defer oauthServer.Close()

	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:           "oidc",
				ClientID:             "client",
				ClientSecret:         "secret",
				AuthorizationURL:     "https://idp.example.com/oauth/authorize",
				TokenURL:             oauthServer.URL + "/token",
				UserInfoURL:          oauthServer.URL + "/userinfo",
				AccessTokenExpiresIn: 3600,
			},
		},
	}))

	beforeCallback := time.Now()
	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", body.URL)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	account, err := a.Store().FindAccountByProviderAndAccountID(context.Background(), "oidc", "expires-account")
	if err != nil {
		t.Fatal(err)
	}
	if account.AccessTokenExpiresAt == nil {
		t.Fatalf("access token expiry missing: %+v", account)
	}
	minExpiresAt := beforeCallback.Add(3590 * time.Second)
	maxExpiresAt := beforeCallback.Add(3610 * time.Second)
	if account.AccessTokenExpiresAt.Before(minExpiresAt) || account.AccessTokenExpiresAt.After(maxExpiresAt) {
		t.Fatalf("access token expiry=%s, want between %s and %s", account.AccessTokenExpiresAt.Format(time.RFC3339), minExpiresAt.Format(time.RFC3339), maxExpiresAt.Format(time.RFC3339))
	}
}

func TestGenericOAuthGetAccessTokenRefreshesExpiredToken(t *testing.T) {
	expiredAt := time.Now().Add(-time.Minute)
	refreshSeen := false
	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "refresh-token" {
			http.Error(w, "refresh form", http.StatusBadRequest)
			return
		}
		refreshSeen = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access-token","expires_in":3600,"scope":"openid profile","id_token":"new-id-token"}`))
	}))
	defer oauthServer.Close()

	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         oauthServer.URL + "/token",
				GetToken: func(_ context.Context, _ plugins.GenericOAuthGetTokenParams) (*provider.OAuthTokens, error) {
					return &provider.OAuthTokens{
						AccessToken:          "old-access-token",
						RefreshToken:         "refresh-token",
						AccessTokenExpiresAt: &expiredAt,
						Scopes:               []string{"openid", "email"},
					}, nil
				},
				GetUserInfo: func(_ context.Context, _ provider.OAuthTokens) (*provider.UserInfo, error) {
					return &provider.UserInfo{
						User: provider.OAuthUser{
							ID:            "refresh-account",
							Name:          "Refresh User",
							Email:         "generic-oauth-refresh@example.com",
							EmailVerified: true,
						},
					}, nil
				},
			},
		},
	}))

	callback := completeGenericOAuthSignIn(t, a, "oidc")
	token := postWithCookies(t, a, "/get-access-token", `{"providerId":"oidc"}`, callback.Result().Cookies())
	if token.Code != http.StatusOK {
		t.Fatalf("status %d body %s", token.Code, token.Body.String())
	}
	var tokenBody struct {
		AccessToken string   `json:"accessToken"`
		IDToken     string   `json:"idToken"`
		Scopes      []string `json:"scopes"`
	}
	if err := json.Unmarshal(token.Body.Bytes(), &tokenBody); err != nil {
		t.Fatal(err)
	}
	if !refreshSeen {
		t.Fatal("expected refresh token endpoint call")
	}
	if tokenBody.AccessToken != "new-access-token" || tokenBody.IDToken != "new-id-token" {
		t.Fatalf("token=%+v", tokenBody)
	}
	if len(tokenBody.Scopes) != 2 || tokenBody.Scopes[0] != "openid" || tokenBody.Scopes[1] != "profile" {
		t.Fatalf("scopes=%v", tokenBody.Scopes)
	}
	account, err := a.Store().FindAccountByProviderAndAccountID(context.Background(), "oidc", "refresh-account")
	if err != nil {
		t.Fatal(err)
	}
	if account.AccessToken != "new-access-token" || account.RefreshToken != "refresh-token" || account.IDToken != "new-id-token" || account.Scope != "openid,profile" {
		t.Fatalf("account=%+v", account)
	}
	if account.AccessTokenExpiresAt == nil || !account.AccessTokenExpiresAt.After(time.Now()) {
		t.Fatalf("access token expiry=%v", account.AccessTokenExpiresAt)
	}
}

func TestGenericOAuthRefreshTokenEndpoint(t *testing.T) {
	expiredAt := time.Now().Add(-time.Minute)
	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "refresh-token" {
			http.Error(w, "refresh form", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"manual-access-token","expires_in":3600,"scope":"email"}`))
	}))
	defer oauthServer.Close()

	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         oauthServer.URL + "/token",
				GetToken: func(_ context.Context, _ plugins.GenericOAuthGetTokenParams) (*provider.OAuthTokens, error) {
					return &provider.OAuthTokens{
						AccessToken:          "old-access-token",
						RefreshToken:         "refresh-token",
						AccessTokenExpiresAt: &expiredAt,
						Scopes:               []string{"openid"},
					}, nil
				},
				GetUserInfo: func(_ context.Context, _ provider.OAuthTokens) (*provider.UserInfo, error) {
					return &provider.UserInfo{
						User: provider.OAuthUser{
							ID:            "manual-refresh-account",
							Name:          "Manual Refresh User",
							Email:         "generic-oauth-manual-refresh@example.com",
							EmailVerified: true,
						},
					}, nil
				},
			},
		},
	}))

	callback := completeGenericOAuthSignIn(t, a, "oidc")
	refresh := postWithCookies(t, a, "/refresh-token", `{"providerId":"oidc"}`, callback.Result().Cookies())
	if refresh.Code != http.StatusOK {
		t.Fatalf("status %d body %s", refresh.Code, refresh.Body.String())
	}
	var refreshBody struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		Scope        string `json:"scope"`
		ProviderID   string `json:"providerId"`
		AccountID    string `json:"accountId"`
	}
	if err := json.Unmarshal(refresh.Body.Bytes(), &refreshBody); err != nil {
		t.Fatal(err)
	}
	if refreshBody.AccessToken != "manual-access-token" || refreshBody.RefreshToken != "refresh-token" || refreshBody.Scope != "email" {
		t.Fatalf("refresh=%+v", refreshBody)
	}
	if refreshBody.ProviderID != "oidc" || refreshBody.AccountID != "manual-refresh-account" {
		t.Fatalf("refresh=%+v", refreshBody)
	}
}

func TestGenericOAuthCallbackSendsAuthorizationHeaders(t *testing.T) {
	tokenHeaderSeen := false
	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if r.Header.Get("X-Custom-Header") != "test-value" {
				http.Error(w, "custom header", http.StatusBadRequest)
				return
			}
			tokenHeaderSeen = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access-token"}`))
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"header-account","name":"Header User","email":"generic-oauth-header@example.com","email_verified":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer oauthServer.Close()

	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         oauthServer.URL + "/token",
				UserInfoURL:      oauthServer.URL + "/userinfo",
				AuthorizationHeaders: map[string]string{
					"X-Custom-Header": "test-value",
				},
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", body.URL)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	if !tokenHeaderSeen {
		t.Fatal("expected custom token header")
	}
}

func TestGenericOAuthCallbackSendsTokenURLParams(t *testing.T) {
	tokenParamsSeen := false
	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "form", http.StatusBadRequest)
				return
			}
			if r.Form.Get("audience") != "api" || r.Form.Get("redirect_uri") != "https://provider.example.com/callback" {
				http.Error(w, "token params", http.StatusBadRequest)
				return
			}
			tokenParamsSeen = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access-token"}`))
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"params-account","name":"Params User","email":"generic-oauth-params@example.com","email_verified":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer oauthServer.Close()

	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         oauthServer.URL + "/token",
				UserInfoURL:      oauthServer.URL + "/userinfo",
				TokenURLParams: map[string]string{
					"audience":     "api",
					"redirect_uri": "https://provider.example.com/callback",
				},
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", body.URL)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	if !tokenParamsSeen {
		t.Fatal("expected token URL params")
	}
}

func TestGenericOAuthCallbackSupportsBasicAuthentication(t *testing.T) {
	basicAuthSeen := false
	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "form", http.StatusBadRequest)
				return
			}
			expectedAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("client:secret"))
			if r.Header.Get("Authorization") != expectedAuthorization {
				http.Error(w, "authorization", http.StatusUnauthorized)
				return
			}
			if r.Form.Get("client_id") != "" || r.Form.Get("client_secret") != "" {
				http.Error(w, "body credentials", http.StatusBadRequest)
				return
			}
			basicAuthSeen = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access-token"}`))
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"basic-account","name":"Basic User","email":"generic-oauth-basic@example.com","email_verified":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer oauthServer.Close()

	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         oauthServer.URL + "/token",
				UserInfoURL:      oauthServer.URL + "/userinfo",
				Authentication:   provider.OAuthClientAuthenticationBasic,
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", body.URL)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	if !basicAuthSeen {
		t.Fatal("expected basic auth token request")
	}
}

func TestGenericOAuthCallbackUsesCustomGetUserInfo(t *testing.T) {
	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"custom-access-token"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer oauthServer.Close()

	var receivedTokens provider.OAuthTokens
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         oauthServer.URL + "/token",
				GetUserInfo: func(_ context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error) {
					receivedTokens = tokens
					return &provider.UserInfo{
						User: provider.OAuthUser{
							ID:            "custom-account",
							Name:          "Custom User",
							Email:         "CUSTOM-USER@EXAMPLE.COM",
							EmailVerified: true,
						},
					}, nil
				},
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", body.URL)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	if receivedTokens.AccessToken != "custom-access-token" {
		t.Fatalf("tokens=%+v", receivedTokens)
	}
	user, err := a.Store().FindUserByEmail(context.Background(), "custom-user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	account, err := a.Store().FindAccountByProviderAndAccountID(context.Background(), "oidc", "custom-account")
	if err != nil {
		t.Fatal(err)
	}
	if account.UserID != user.ID || account.AccessToken != "custom-access-token" {
		t.Fatalf("account=%+v user=%+v", account, user)
	}
}

func TestGenericOAuthCallbackUsesCustomGetToken(t *testing.T) {
	tokenEndpointHit := false
	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenEndpointHit = true
			http.Error(w, "unexpected token endpoint", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer oauthServer.Close()

	var receivedParams plugins.GenericOAuthGetTokenParams
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:           "oidc",
				ClientID:             "client",
				ClientSecret:         "secret",
				AuthorizationURL:     "https://idp.example.com/oauth/authorize",
				TokenURL:             oauthServer.URL + "/token",
				UserInfoURL:          "https://idp.example.com/oauth/userinfo",
				PKCE:                 true,
				AccessTokenExpiresIn: 3600,
				GetToken: func(_ context.Context, params plugins.GenericOAuthGetTokenParams) (*provider.OAuthTokens, error) {
					receivedParams = params
					return &provider.OAuthTokens{
						AccessToken:  "custom-access-token",
						RefreshToken: "custom-refresh-token",
					}, nil
				},
				GetUserInfo: func(_ context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error) {
					if tokens.AccessToken != "custom-access-token" {
						t.Fatalf("tokens=%+v", tokens)
					}
					return &provider.UserInfo{
						User: provider.OAuthUser{
							ID:            "custom-token-account",
							Name:          "Custom Token User",
							Email:         "custom-token@example.com",
							EmailVerified: true,
						},
					}, nil
				},
			},
		},
	}))

	beforeCallback := time.Now()
	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	state := query.Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", body.URL)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	if tokenEndpointHit {
		t.Fatal("standard token endpoint should not be called")
	}
	if receivedParams.Code != "code" || receivedParams.RedirectURI != "http://localhost:8080/api/auth/oauth2/callback/oidc" || receivedParams.CodeVerifier == "" {
		t.Fatalf("params=%+v", receivedParams)
	}
	account, err := a.Store().FindAccountByProviderAndAccountID(context.Background(), "oidc", "custom-token-account")
	if err != nil {
		t.Fatal(err)
	}
	if account.AccessToken != "custom-access-token" || account.RefreshToken != "custom-refresh-token" {
		t.Fatalf("account=%+v", account)
	}
	if account.AccessTokenExpiresAt == nil {
		t.Fatalf("access token expiry missing: %+v", account)
	}
	if account.AccessTokenExpiresAt.Before(beforeCallback.Add(3590*time.Second)) || account.AccessTokenExpiresAt.After(beforeCallback.Add(3610*time.Second)) {
		t.Fatalf("access token expiry=%s", account.AccessTokenExpiresAt.Format(time.RFC3339))
	}
}

func TestGenericOAuthCallbackRedirectsNewUsersToNewUserCallbackURL(t *testing.T) {
	oauthServer, _ := newGenericOAuthCallbackServer(t, "new-user-account", "New User", "generic-oauth-new-user@example.com", `{"access_token":"access-token"}`)
	defer oauthServer.Close()

	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         oauthServer.URL + "/token",
				UserInfoURL:      oauthServer.URL + "/userinfo",
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard","newUserCallbackURL":"https://app.example.com/welcome"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", body.URL)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	if location := callback.Header().Get("Location"); location != "https://app.example.com/welcome" {
		t.Fatalf("Location=%q", location)
	}
}

func TestGenericOAuthCallbackUsesStoredErrorCallbackURL(t *testing.T) {
	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			http.Error(w, "token failed", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer oauthServer.Close()

	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         oauthServer.URL + "/token",
				UserInfoURL:      "https://idp.example.com/oauth/userinfo",
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard","errorCallbackURL":"https://app.example.com/oauth-error?source=generic"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", body.URL)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	location := callback.Header().Get("Location")
	if location != "https://app.example.com/oauth-error?error=oauth_code_verification_failed&source=generic" {
		t.Fatalf("Location=%q", location)
	}
}

func TestGenericOAuthCallbackRedirectsProfileValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		userInfo *provider.UserInfo
		want     string
	}{
		{
			name: "missing user info",
			want: "user_info_is_missing",
		},
		{
			name: "missing account id",
			userInfo: &provider.UserInfo{
				User: provider.OAuthUser{
					Name:          "Missing ID",
					Email:         "missing-id@example.com",
					EmailVerified: true,
				},
			},
			want: "id_is_missing",
		},
		{
			name: "missing name",
			userInfo: &provider.UserInfo{
				User: provider.OAuthUser{
					ID:            "missing-name",
					Email:         "missing-name@example.com",
					EmailVerified: true,
				},
			},
			want: "name_is_missing",
		},
		{
			name: "missing email",
			userInfo: &provider.UserInfo{
				User: provider.OAuthUser{
					ID:            "missing-email",
					Name:          "Missing Email",
					EmailVerified: true,
				},
			},
			want: "email_is_missing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
				Providers: []plugins.GenericOAuthProviderConfig{
					{
						ProviderID:       "oidc",
						ClientID:         "client",
						ClientSecret:     "secret",
						AuthorizationURL: "https://idp.example.com/oauth/authorize",
						TokenURL:         "https://idp.example.com/oauth/token",
						GetToken: func(_ context.Context, _ plugins.GenericOAuthGetTokenParams) (*provider.OAuthTokens, error) {
							return &provider.OAuthTokens{AccessToken: "access-token"}, nil
						},
						GetUserInfo: func(_ context.Context, _ provider.OAuthTokens) (*provider.UserInfo, error) {
							return tt.userInfo, nil
						},
					},
				},
			}))

			w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard","errorCallbackURL":"https://app.example.com/oauth-error"}`)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d body %s", w.Code, w.Body.String())
			}
			var body struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			parsed, err := url.Parse(body.URL)
			if err != nil {
				t.Fatal(err)
			}
			state := parsed.Query().Get("state")
			if state == "" {
				t.Fatalf("state missing: %s", body.URL)
			}

			callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
			if callback.Code != http.StatusFound {
				t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
			}
			location := callback.Header().Get("Location")
			want := "https://app.example.com/oauth-error?error=" + tt.want
			if location != want {
				t.Fatalf("Location=%q want %q", location, want)
			}
		})
	}
}

func TestGenericOAuthCallbackRequestSignUpOverridesDisableImplicitSignUp(t *testing.T) {
	var accountID string
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:            "oidc",
				ClientID:              "client",
				ClientSecret:          "secret",
				AuthorizationURL:      "https://idp.example.com/oauth/authorize",
				TokenURL:              "https://idp.example.com/oauth/token",
				DisableImplicitSignUp: true,
				GetToken: func(_ context.Context, _ plugins.GenericOAuthGetTokenParams) (*provider.OAuthTokens, error) {
					return &provider.OAuthTokens{AccessToken: "access-token"}, nil
				},
				GetUserInfo: func(_ context.Context, _ provider.OAuthTokens) (*provider.UserInfo, error) {
					return &provider.UserInfo{
						User: provider.OAuthUser{
							ID:            accountID,
							Name:          "Request SignUp User",
							Email:         "generic-oauth-request-signup@example.com",
							EmailVerified: true,
						},
					}, nil
				},
			},
		},
	}))

	accountID = "blocked-account"
	blocked := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard","errorCallbackURL":"https://app.example.com/oauth-error"}`)
	if blocked.Code != http.StatusOK {
		t.Fatalf("status %d body %s", blocked.Code, blocked.Body.String())
	}
	var blockedBody struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(blocked.Body.Bytes(), &blockedBody); err != nil {
		t.Fatal(err)
	}
	blockedURL, err := url.Parse(blockedBody.URL)
	if err != nil {
		t.Fatal(err)
	}
	blockedState := blockedURL.Query().Get("state")
	if blockedState == "" {
		t.Fatalf("state missing: %s", blockedBody.URL)
	}
	blockedCallback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(blockedState))
	if blockedCallback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", blockedCallback.Code, blockedCallback.Body.String())
	}
	if location := blockedCallback.Header().Get("Location"); location != "https://app.example.com/oauth-error?error=signup_disabled" {
		t.Fatalf("Location=%q", location)
	}

	accountID = "allowed-account"
	allowed := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard","requestSignUp":true}`)
	if allowed.Code != http.StatusOK {
		t.Fatalf("status %d body %s", allowed.Code, allowed.Body.String())
	}
	var allowedBody struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(allowed.Body.Bytes(), &allowedBody); err != nil {
		t.Fatal(err)
	}
	allowedURL, err := url.Parse(allowedBody.URL)
	if err != nil {
		t.Fatal(err)
	}
	allowedState := allowedURL.Query().Get("state")
	if allowedState == "" {
		t.Fatalf("state missing: %s", allowedBody.URL)
	}
	allowedCallback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(allowedState))
	if allowedCallback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", allowedCallback.Code, allowedCallback.Body.String())
	}
	if location := allowedCallback.Header().Get("Location"); location != "https://app.example.com/dashboard" {
		t.Fatalf("Location=%q", location)
	}
	if _, err := a.Store().FindAccountByProviderAndAccountID(context.Background(), "oidc", "allowed-account"); err != nil {
		t.Fatal(err)
	}
}

func TestGenericOAuthLinkCallbackUsesStoredErrorCallbackURL(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         "https://idp.example.com/oauth/token",
				GetToken: func(_ context.Context, _ plugins.GenericOAuthGetTokenParams) (*provider.OAuthTokens, error) {
					return &provider.OAuthTokens{AccessToken: "access-token"}, nil
				},
				GetUserInfo: func(_ context.Context, _ provider.OAuthTokens) (*provider.UserInfo, error) {
					return &provider.UserInfo{
						User: provider.OAuthUser{
							ID:            "link-error-account",
							Name:          "Different Email",
							Email:         "different@example.com",
							EmailVerified: true,
						},
					}, nil
				},
			},
		},
	}))

	signUp := post(t, a, "/sign-up/email", `{"name":"Link Error","email":"generic-oauth-link-error@example.com","password":"password123"}`)
	if signUp.Code != http.StatusOK {
		t.Fatalf("status %d body %s", signUp.Code, signUp.Body.String())
	}
	link := postWithCookies(t, a, "/oauth2/link", `{"providerId":"oidc","callbackURL":"https://app.example.com/settings","errorCallbackURL":"https://app.example.com/link-error?source=generic"}`, signUp.Result().Cookies())
	if link.Code != http.StatusOK {
		t.Fatalf("status %d body %s", link.Code, link.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(link.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", body.URL)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	location := callback.Header().Get("Location")
	if location != "https://app.example.com/link-error?error=email_doesn%27t_match&source=generic" {
		t.Fatalf("Location=%q", location)
	}
}

func TestGenericOAuthCallbackMapsProfileToUser(t *testing.T) {
	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access-token"}`))
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer access-token" {
				http.Error(w, "authorization", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"username":"derived-id-user","email":"derived-id@example.com","name":"Derived Id User","email_verified":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer oauthServer.Close()

	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         oauthServer.URL + "/token",
				UserInfoURL:      oauthServer.URL + "/userinfo",
				MapProfileToUser: func(_ context.Context, profile map[string]any) (provider.OAuthUserMapping, error) {
					id, _ := profile["username"].(string)
					emailVerified, _ := profile["email_verified"].(bool)
					return provider.OAuthUserMapping{
						ID:            &id,
						EmailVerified: &emailVerified,
					}, nil
				},
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing: %s", body.URL)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state="+url.QueryEscape(state))
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	user, err := a.Store().FindUserByEmail(context.Background(), "derived-id@example.com")
	if err != nil {
		t.Fatal(err)
	}
	account, err := a.Store().FindAccountByProviderAndAccountID(context.Background(), "oidc", "derived-id-user")
	if err != nil {
		t.Fatal(err)
	}
	if account.UserID != user.ID || user.Name != "Derived Id User" || !user.EmailVerified {
		t.Fatalf("account=%+v user=%+v", account, user)
	}
}

func TestGenericOAuthCallbackRedirectsProviderErrors(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         "https://idp.example.com/oauth/token",
			},
		},
	}))

	callback := get(t, a, "/oauth2/callback/oidc?error=access_denied&error_description=Denied")
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	location := callback.Header().Get("Location")
	if location != "http://localhost:8080/api/auth/error?error=access_denied&error_description=Denied" {
		t.Fatalf("Location=%q", location)
	}
}

func TestGenericOAuthCallbackRedirectsMissingCode(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         "https://idp.example.com/oauth/token",
			},
		},
	}))

	callback := get(t, a, "/oauth2/callback/oidc?state=state")
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	location := callback.Header().Get("Location")
	if location != "http://localhost:8080/api/auth/error?error=oAuth_code_missing" {
		t.Fatalf("Location=%q", location)
	}
}

func TestGenericOAuthSignInUsesDiscoveryURL(t *testing.T) {
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Discovery") != "secret" {
			t.Fatalf("X-Discovery=%q", r.Header.Get("X-Discovery"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_endpoint":"https://discovery.example.com/oauth/authorize?tenant=workspace","token_endpoint":"https://discovery.example.com/oauth/token"}`))
	}))
	defer discoveryServer.Close()
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID: "oidc", ClientID: "client", ClientSecret: "secret",
				DiscoveryURL: discoveryServer.URL,
				DiscoveryHeaders: map[string]string{
					"X-Discovery": "secret",
				},
				Scopes: []string{"openid"},
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","disableRedirect":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "https" || parsed.Host != "discovery.example.com" || parsed.Path != "/oauth/authorize" {
		t.Fatalf("url=%s", body.URL)
	}
	query := parsed.Query()
	if query.Get("tenant") != "workspace" || query.Get("client_id") != "client" || query.Get("scope") != "openid" {
		t.Fatalf("query=%s", query.Encode())
	}
}

func TestGenericOAuthSignInRejectsIncompleteConfig(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID: "oidc", ClientID: "client", ClientSecret: "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
			},
		},
	}))

	w := post(t, a, "/sign-in/oauth2", `{"providerId":"oidc","callbackURL":"https://app.example.com/dashboard"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestGenericOAuthCallbackRejectsProviderMismatch(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID:       "oidc",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         "https://idp.example.com/oauth/token",
				UserInfoURL:      "https://idp.example.com/oauth/userinfo",
			},
			{
				ProviderID:       "other",
				ClientID:         "client",
				ClientSecret:     "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         "https://idp.example.com/oauth/token",
				UserInfoURL:      "https://idp.example.com/oauth/userinfo",
			},
		},
	}))
	if err := a.CreateVerification(context.Background(), constants.VerificationOAuth2State+"state", "oidc|https://app.example.com/dashboard", time.Minute); err != nil {
		t.Fatal(err)
	}

	callback := get(t, a, "/oauth2/callback/other?code=code&state=state")
	if callback.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
}

func TestGenericOAuthCallbackRejectsIssuerMismatch(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID: "oidc", ClientID: "client", ClientSecret: "secret",
				AuthorizationURL: "https://idp.example.com/oauth/authorize",
				TokenURL:         "https://idp.example.com/oauth/token",
				UserInfoURL:      "https://idp.example.com/oauth/userinfo",
				Issuer:           "https://issuer.example.com",
			},
		},
	}))
	if err := a.CreateVerification(context.Background(), constants.VerificationOAuth2State+"state", "oidc|https://app.example.com/dashboard", time.Minute); err != nil {
		t.Fatal(err)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state=state&iss=https%3A%2F%2Fother.example.com")
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	if location := callback.Header().Get("Location"); location != "http://localhost:8080/api/auth/error?error=issuer_mismatch" {
		t.Fatalf("Location=%q", location)
	}
}

func TestGenericOAuthCallbackRequiresIssuerWhenConfigured(t *testing.T) {
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID: "oidc", ClientID: "client", ClientSecret: "secret",
				AuthorizationURL:        "https://idp.example.com/oauth/authorize",
				TokenURL:                "https://idp.example.com/oauth/token",
				UserInfoURL:             "https://idp.example.com/oauth/userinfo",
				Issuer:                  "https://issuer.example.com",
				RequireIssuerValidation: true,
			},
		},
	}))
	if err := a.CreateVerification(context.Background(), constants.VerificationOAuth2State+"state", "oidc|https://app.example.com/dashboard", time.Minute); err != nil {
		t.Fatal(err)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state=state")
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	if location := callback.Header().Get("Location"); location != "http://localhost:8080/api/auth/error?error=issuer_missing" {
		t.Fatalf("Location=%q", location)
	}
}

func TestGenericOAuthCallbackUsesDiscoveryIssuer(t *testing.T) {
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_endpoint":"https://idp.example.com/oauth/authorize","token_endpoint":"https://idp.example.com/oauth/token","issuer":"https://issuer.example.com"}`))
	}))
	defer discoveryServer.Close()
	a := newTestAuth(t, plugins.GenericOAuth(plugins.GenericOAuthOptions{
		Providers: []plugins.GenericOAuthProviderConfig{
			{
				ProviderID: "oidc", ClientID: "client", ClientSecret: "secret",
				DiscoveryURL: discoveryServer.URL,
			},
		},
	}))
	if err := a.CreateVerification(context.Background(), constants.VerificationOAuth2State+"state", "oidc|https://app.example.com/dashboard", time.Minute); err != nil {
		t.Fatal(err)
	}

	callback := get(t, a, "/oauth2/callback/oidc?code=code&state=state&iss=https%3A%2F%2Fother.example.com")
	if callback.Code != http.StatusFound {
		t.Fatalf("status %d body %s", callback.Code, callback.Body.String())
	}
	if location := callback.Header().Get("Location"); location != "http://localhost:8080/api/auth/error?error=issuer_mismatch" {
		t.Fatalf("Location=%q", location)
	}
}
