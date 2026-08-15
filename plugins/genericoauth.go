package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/internal/jwt"
	oauth2pkg "github.com/patrickkabwe/betterauth-go/internal/oauth2"
	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

// GenericOAuthGetUserInfo fetches user info from custom provider token data.
type GenericOAuthGetUserInfo func(ctx context.Context, tokens provider.OAuthTokens) (*provider.UserInfo, error)

// GenericOAuthGetToken exchanges an authorization code for provider tokens.
type GenericOAuthGetToken func(ctx context.Context, params GenericOAuthGetTokenParams) (*provider.OAuthTokens, error)

// GenericOAuthGetTokenParams contains the authorization-code exchange inputs.
type GenericOAuthGetTokenParams struct {
	Code         string
	RedirectURI  string
	CodeVerifier string
}

// GenericOAuthMapProfileToUser maps a provider profile into Better Auth user fields.
type GenericOAuthMapProfileToUser func(ctx context.Context, profile map[string]any) (provider.OAuthUserMapping, error)

// GenericOAuthProviderConfig configures a custom OAuth2/OIDC provider.
type GenericOAuthProviderConfig struct {
	ProviderID              string
	ClientID                string
	ClientSecret            string
	DiscoveryURL            string
	DiscoveryHeaders        map[string]string
	Issuer                  string
	RequireIssuerValidation bool
	AuthorizationURL        string
	TokenURL                string
	UserInfoURL             string
	RedirectURI             string
	Scopes                  []string
	ResponseType            string
	ResponseMode            string
	PKCE                    bool
	Prompt                  string
	AccessType              string
	AccessTokenExpiresIn    int
	DisableImplicitSignUp   bool
	DisableSignUp           bool
	OverrideUserInfo        bool
	AuthorizationHeaders    map[string]string
	AuthorizationURLParams  map[string]string
	TokenURLParams          map[string]string
	Authentication          provider.OAuthClientAuthentication
	GetToken                GenericOAuthGetToken
	GetUserInfo             GenericOAuthGetUserInfo
	MapProfileToUser        GenericOAuthMapProfileToUser
}

// GenericOAuthOptions configures the generic OAuth plugin.
type GenericOAuthOptions struct {
	Providers []GenericOAuthProviderConfig
}

// GenericOAuth adds custom OIDC/OAuth2 providers.
func GenericOAuth(opts GenericOAuthOptions) auth.Plugin {
	providers := make(map[string]GenericOAuthProviderConfig)
	for _, p := range opts.Providers {
		providers[p.ProviderID] = p
	}
	callbackHandler := func(c *auth.Context) {
		handleGenericOAuthCallback(c, providers)
	}
	return basePlugin{
		id: constants.PluginGenericOAuth,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/sign-in/oauth2", func(c *auth.Context) {
				var body struct {
					ProviderID         string   `json:"providerId"`
					CallbackURL        string   `json:"callbackURL"`
					NewUserCallbackURL string   `json:"newUserCallbackURL"`
					ErrorCallbackURL   string   `json:"errorCallbackURL"`
					DisableRedirect    bool     `json:"disableRedirect"`
					Scopes             []string `json:"scopes"`
					RequestSignUp      bool     `json:"requestSignUp"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				p, ok := providers[body.ProviderID]
				if !ok {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeProviderNotFound))
					return
				}
				authorizationURL, err := genericOAuthSignInAuthorizationURL(c, p)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOAuthError))
					return
				}
				state, codeVerifier, err := createGenericOAuthState(c, genericOAuthStateInput{
					ProviderID:    body.ProviderID,
					CallbackURL:   body.CallbackURL,
					NewUserURL:    body.NewUserCallbackURL,
					ErrorURL:      body.ErrorCallbackURL,
					RequestSignUp: body.RequestSignUp,
					UsePKCE:       p.PKCE,
				})
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				q := genericOAuthAuthorizationValues(c, p, state, genericOAuthSignInScopes(body.Scopes, p.Scopes), codeVerifier)
				redirectURL := provider.BuildAuthURL(authorizationURL, q)
				c.WriteJSON(http.StatusOK, map[string]any{"url": redirectURL, "redirect": !body.DisableRedirect})
			}),
			rt(http.MethodGet, "/oauth2/callback/{providerId}", callbackHandler),
			rt(http.MethodPost, "/oauth2/callback/{providerId}", callbackHandler),
			rt(http.MethodPost, "/oauth2/link", func(c *auth.Context) {
				var body struct {
					ProviderID       string   `json:"providerId"`
					CallbackURL      string   `json:"callbackURL"`
					Scopes           []string `json:"scopes"`
					ErrorCallbackURL string   `json:"errorCallbackURL"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				p, ok := providers[body.ProviderID]
				if !ok {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeProviderNotFound))
					return
				}
				authorizationURL, err := genericOAuthLinkAuthorizationURL(c, p)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOAuthError))
					return
				}
				state, codeVerifier, err := createGenericOAuthState(c, genericOAuthStateInput{
					ProviderID:  body.ProviderID,
					CallbackURL: body.CallbackURL,
					ErrorURL:    body.ErrorCallbackURL,
					LinkUserID:  user.ID,
					LinkEmail:   user.Email,
					UsePKCE:     p.PKCE,
				})
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				q := genericOAuthAuthorizationValues(c, p, state, genericOAuthLinkScopes(body.Scopes, p.Scopes), codeVerifier)
				redirectURL := provider.BuildAuthURL(authorizationURL, q)
				c.WriteJSON(http.StatusOK, map[string]any{"url": redirectURL, "redirect": true})
			}),
		},
		hooks: &auth.PluginHooks{
			Before: []func(*auth.Context) bool{
				func(c *auth.Context) bool {
					return handleGenericOAuthTokenRoutes(c, providers)
				},
			},
		},
	}
}

func handleGenericOAuthCallback(c *auth.Context, providers map[string]GenericOAuthProviderConfig) {
	providerID := c.Vars["providerId"]
	values, err := genericOAuthCallbackValues(c)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
		return
	}
	if errorCode := values.Get("error"); errorCode != "" {
		redirectGenericOAuthError(c, genericOAuthDefaultErrorURL(c), errorCode, values.Get("error_description"))
		return
	}
	code := values.Get("code")
	if code == "" {
		redirectGenericOAuthError(c, genericOAuthDefaultErrorURL(c), "oAuth_code_missing", "")
		return
	}
	state := values.Get("state")
	if state == "" {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOAuthError))
		return
	}
	p, ok := providers[providerID]
	if !ok {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeProviderNotFound))
		return
	}
	v, err := c.Auth.ConsumeVerification(c.R.Context(), constants.VerificationOAuth2State+state)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidState))
		return
	}
	stateData, ok := parseGenericOAuthStateValue(v.Value)
	if !ok || stateData.ProviderID != providerID {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidState))
		return
	}
	callbackURL := stateData.CallbackURL
	if callbackURL == "" {
		callbackURL = c.Auth.BaseURL()
	}
	errorURL := genericOAuthCallbackErrorURL(c, stateData)
	if issuerError := genericOAuthIssuerError(c, p, values); issuerError != "" {
		redirectGenericOAuthError(c, errorURL, issuerError, "")
		return
	}
	tokens, err := genericOAuthExchangeAuthorizationCode(c, p, code, stateData.CodeVerifier)
	if err != nil {
		redirectGenericOAuthError(c, errorURL, "oauth_code_verification_failed", "")
		return
	}
	userInfo, err := genericOAuthUserInfo(c, p, tokens)
	if err != nil {
		redirectGenericOAuthError(c, errorURL, "unable_to_get_user_info", "")
		return
	}
	if stateData.LinkUserID != "" {
		handleGenericOAuthLinkCallback(c, stateData, userInfo, tokens)
		return
	}
	user, isRegister, err := genericOAuthSignInUser(c, p, stateData, userInfo, tokens)
	if err != nil {
		redirectGenericOAuthError(c, errorURL, strings.ReplaceAll(err.Error(), " ", "_"), "")
		return
	}
	if _, err := c.Auth.NewSession(c, user.ID, true); err != nil {
		redirectGenericOAuthError(c, errorURL, "unable_to_create_session", "")
		return
	}
	if isRegister && stateData.NewUserURL != "" {
		callbackURL = stateData.NewUserURL
	}
	c.Redirect(callbackURL)
}

func genericOAuthCallbackValues(c *auth.Context) (url.Values, error) {
	if c.R.Method != http.MethodPost {
		return c.R.URL.Query(), nil
	}
	if err := c.R.ParseForm(); err != nil {
		return nil, err
	}
	values := url.Values{}
	for key, list := range c.R.Form {
		copied := make([]string, len(list))
		copy(copied, list)
		values[key] = copied
	}
	return values, nil
}

type genericOAuthTokenRequest struct {
	ProviderID string `json:"providerId"`
	AccountID  string `json:"accountId,omitempty"`
}

func handleGenericOAuthTokenRoutes(c *auth.Context, providers map[string]GenericOAuthProviderConfig) bool {
	if c.R.Method != http.MethodPost {
		return true
	}
	path := strings.TrimSuffix(c.R.URL.Path, "/")
	if path == "" {
		path = "/"
	}
	if path != "/get-access-token" && path != "/refresh-token" {
		return true
	}
	body, err := parseGenericOAuthTokenRequest(c)
	if err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidEmail, constants.MsgInvalidRequestBody))
		return false
	}
	p, ok := providers[body.ProviderID]
	if !ok {
		return true
	}
	if path == "/get-access-token" {
		handleGenericOAuthGetAccessToken(c, p, body)
		return false
	}
	handleGenericOAuthRefreshToken(c, p, body)
	return false
}

func parseGenericOAuthTokenRequest(c *auth.Context) (genericOAuthTokenRequest, error) {
	originalBody := c.R.Body
	raw, err := io.ReadAll(io.LimitReader(c.R.Body, 1<<20))
	_ = originalBody.Close()
	if err != nil {
		return genericOAuthTokenRequest{}, err
	}
	c.R.Body = io.NopCloser(bytes.NewReader(raw))
	if len(raw) == 0 {
		return genericOAuthTokenRequest{}, nil
	}
	var body genericOAuthTokenRequest
	if strings.HasPrefix(strings.ToLower(c.R.Header.Get(constants.HeaderContentType)), "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(string(raw))
		if err != nil {
			return genericOAuthTokenRequest{}, err
		}
		body.ProviderID = values.Get("providerId")
		body.AccountID = values.Get("accountId")
		return body, nil
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return genericOAuthTokenRequest{}, err
	}
	return body, nil
}

func handleGenericOAuthGetAccessToken(c *auth.Context, p GenericOAuthProviderConfig, body genericOAuthTokenRequest) {
	sess, _, ok := c.RequireSession()
	if !ok {
		return
	}
	account, ok := genericOAuthAccountForUser(c, sess.UserID, body.ProviderID, body.AccountID)
	if !ok {
		return
	}
	if shouldRefreshGenericOAuthAccessToken(account) {
		tokens, err := refreshGenericOAuthAccessToken(c, p, account.RefreshToken)
		if err != nil {
			c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeFailedToGetAccessToken, constants.MsgFailedValidAccessToken))
			return
		}
		if err := updateGenericOAuthAccount(c, account.ID, tokens); err != nil {
			c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeFailedToGetAccessToken, constants.MsgFailedValidAccessToken))
			return
		}
		applyGenericOAuthTokensToAccount(account, tokens)
	}
	c.WriteJSON(http.StatusOK, types.AccessTokenResponse{
		AccessToken:          account.AccessToken,
		AccessTokenExpiresAt: account.AccessTokenExpiresAt,
		IDToken:              account.IDToken,
		Scopes:               splitGenericOAuthScopes(account.Scope),
	})
}

func handleGenericOAuthRefreshToken(c *auth.Context, p GenericOAuthProviderConfig, body genericOAuthTokenRequest) {
	sess, _, ok := c.RequireSession()
	if !ok {
		return
	}
	account, ok := genericOAuthAccountForUser(c, sess.UserID, body.ProviderID, body.AccountID)
	if !ok {
		return
	}
	if account.RefreshToken == "" {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeRefreshTokenNotFound))
		return
	}
	tokens, err := refreshGenericOAuthAccessToken(c, p, account.RefreshToken)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeFailedToRefreshAccessToken))
		return
	}
	refreshToken := tokens.RefreshToken
	if refreshToken == "" {
		refreshToken = account.RefreshToken
	}
	refreshExpires := tokens.RefreshTokenExpiresAt
	if refreshExpires == nil {
		refreshExpires = account.RefreshTokenExpiresAt
	}
	scope := account.Scope
	if len(tokens.Scopes) > 0 {
		scope = strings.Join(tokens.Scopes, ",")
	}
	idToken := tokens.IDToken
	if idToken == "" {
		idToken = account.IDToken
	}
	update := store.AccountUpdate{
		AccessToken:           &tokens.AccessToken,
		RefreshToken:          &refreshToken,
		AccessTokenExpiresAt:  tokens.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: refreshExpires,
		IDToken:               &idToken,
		Scope:                 &scope,
	}
	if _, err := c.Auth.Store().UpdateAccount(c.R.Context(), account.ID, update); err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeFailedToRefreshAccessToken))
		return
	}
	c.WriteJSON(http.StatusOK, types.RefreshTokenResponse{
		AccessToken:           tokens.AccessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  tokens.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: refreshExpires,
		Scope:                 scope,
		IDToken:               idToken,
		ProviderID:            account.ProviderID,
		AccountID:             account.AccountID,
	})
}

func genericOAuthAccountForUser(c *auth.Context, userID string, providerID string, accountID string) (*types.Account, bool) {
	accounts, err := c.Auth.Store().ListAccountsByUserID(c.R.Context(), userID)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return nil, false
	}
	for i := range accounts {
		account := &accounts[i]
		if account.ProviderID != providerID {
			continue
		}
		if accountID == "" || account.AccountID == accountID {
			return account, true
		}
	}
	c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeAccountNotFound))
	return nil, false
}

func shouldRefreshGenericOAuthAccessToken(account *types.Account) bool {
	return account.RefreshToken != "" && account.AccessTokenExpiresAt != nil && account.AccessTokenExpiresAt.Sub(time.Now()) < 5*time.Second
}

func refreshGenericOAuthAccessToken(c *auth.Context, p GenericOAuthProviderConfig, refreshToken string) (*provider.OAuthTokens, error) {
	tokenURL, err := genericOAuthTokenEndpoint(c, p)
	if err != nil {
		return nil, err
	}
	tokens, err := provider.RefreshAccessTokenWithOptions(c.R.Context(), provider.RefreshAccessTokenOpts{
		TokenURL:       tokenURL,
		ClientID:       p.ClientID,
		ClientSecret:   p.ClientSecret,
		RefreshToken:   refreshToken,
		Authentication: p.Authentication,
	})
	if err != nil {
		return nil, err
	}
	if tokens == nil || tokens.AccessToken == "" {
		return nil, errors.New("access token missing")
	}
	return genericOAuthApplyAccessTokenExpiresIn(p, tokens), nil
}

func applyGenericOAuthTokensToAccount(account *types.Account, tokens *provider.OAuthTokens) {
	account.AccessToken = tokens.AccessToken
	account.AccessTokenExpiresAt = tokens.AccessTokenExpiresAt
	if tokens.RefreshToken != "" {
		account.RefreshToken = tokens.RefreshToken
	}
	if tokens.RefreshTokenExpiresAt != nil {
		account.RefreshTokenExpiresAt = tokens.RefreshTokenExpiresAt
	}
	if tokens.IDToken != "" {
		account.IDToken = tokens.IDToken
	}
	if len(tokens.Scopes) > 0 {
		account.Scope = strings.Join(tokens.Scopes, ",")
	}
}

func splitGenericOAuthScopes(scope string) []string {
	if scope == "" {
		return []string{}
	}
	return strings.Split(scope, ",")
}

func genericOAuthSignInAuthorizationURL(c *auth.Context, p GenericOAuthProviderConfig) (string, error) {
	authorizationURL := p.AuthorizationURL
	tokenURL := p.TokenURL
	if p.DiscoveryURL != "" {
		discovery, err := genericOAuthDiscovery(c, p)
		if err != nil {
			return "", err
		}
		if discovery.AuthorizationEndpoint != "" {
			authorizationURL = discovery.AuthorizationEndpoint
		}
		if discovery.TokenEndpoint != "" {
			tokenURL = discovery.TokenEndpoint
		}
	}
	if authorizationURL == "" || tokenURL == "" {
		return "", fmt.Errorf("invalid generic oauth configuration for provider %q: authorizationURL=%q tokenURL=%q", p.ProviderID, authorizationURL, tokenURL)
	}
	return authorizationURL, nil
}

func genericOAuthLinkAuthorizationURL(c *auth.Context, p GenericOAuthProviderConfig) (string, error) {
	authorizationURL := p.AuthorizationURL
	if p.DiscoveryURL != "" {
		discovery, err := genericOAuthDiscovery(c, p)
		if err != nil {
			return "", err
		}
		if discovery.AuthorizationEndpoint != "" {
			authorizationURL = discovery.AuthorizationEndpoint
		}
	}
	if authorizationURL == "" {
		return "", fmt.Errorf("invalid generic oauth configuration for provider %q: authorizationURL=%q", p.ProviderID, authorizationURL)
	}
	return authorizationURL, nil
}

type genericOAuthDiscoveryDocument struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	Issuer                string `json:"issuer"`
}

func genericOAuthDiscovery(c *auth.Context, p GenericOAuthProviderConfig) (*genericOAuthDiscoveryDocument, error) {
	req, err := http.NewRequestWithContext(c.R.Context(), http.MethodGet, p.DiscoveryURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(constants.HeaderAccept, constants.MIMEJSON)
	for key, value := range p.DiscoveryHeaders {
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("generic oauth discovery failed for provider %q at %q with status %d: %s", p.ProviderID, p.DiscoveryURL, resp.StatusCode, string(body))
	}
	var discovery genericOAuthDiscoveryDocument
	if err := json.Unmarshal(body, &discovery); err != nil {
		return nil, err
	}
	return &discovery, nil
}

func genericOAuthIssuerError(c *auth.Context, p GenericOAuthProviderConfig, values url.Values) string {
	expectedIssuer, err := genericOAuthExpectedIssuer(c, p)
	if err != nil || expectedIssuer == "" {
		if err == nil && !p.RequireIssuerValidation {
			return ""
		}
		return "issuer_missing"
	}
	issuer := values.Get("iss")
	if issuer == "" {
		if p.RequireIssuerValidation {
			return "issuer_missing"
		}
		return ""
	}
	if issuer != expectedIssuer {
		return "issuer_mismatch"
	}
	return ""
}

func genericOAuthExpectedIssuer(c *auth.Context, p GenericOAuthProviderConfig) (string, error) {
	if p.Issuer != "" {
		return p.Issuer, nil
	}
	if p.DiscoveryURL == "" {
		return "", nil
	}
	discovery, err := genericOAuthDiscovery(c, p)
	if err != nil {
		return "", err
	}
	return discovery.Issuer, nil
}

func parseGenericOAuthStateValue(value string) (genericOAuthStatePayload, bool) {
	var payload genericOAuthStatePayload
	if err := json.Unmarshal([]byte(value), &payload); err == nil && payload.ProviderID != "" {
		return payload, true
	}
	providerID, callbackURL, ok := strings.Cut(value, "|")
	if !ok || providerID == "" {
		return genericOAuthStatePayload{}, false
	}
	return genericOAuthStatePayload{ProviderID: providerID, CallbackURL: callbackURL}, true
}

type genericOAuthStateInput struct {
	ProviderID    string
	CallbackURL   string
	NewUserURL    string
	ErrorURL      string
	LinkUserID    string
	LinkEmail     string
	RequestSignUp bool
	UsePKCE       bool
}

type genericOAuthStatePayload struct {
	ProviderID    string `json:"providerId"`
	CallbackURL   string `json:"callbackURL"`
	NewUserURL    string `json:"newUserURL,omitempty"`
	ErrorURL      string `json:"errorURL,omitempty"`
	CodeVerifier  string `json:"codeVerifier,omitempty"`
	LinkUserID    string `json:"linkUserId,omitempty"`
	LinkEmail     string `json:"linkEmail,omitempty"`
	RequestSignUp bool   `json:"requestSignUp,omitempty"`
}

func createGenericOAuthState(c *auth.Context, input genericOAuthStateInput) (string, string, error) {
	codeVerifier := ""
	var err error
	if input.UsePKCE {
		codeVerifier, err = oauth2pkg.GenerateCodeVerifier()
		if err != nil {
			return "", "", err
		}
	}
	state, err := id.Generate(32)
	if err != nil {
		return "", "", err
	}
	payload := genericOAuthStatePayload{
		ProviderID:    input.ProviderID,
		CallbackURL:   input.CallbackURL,
		NewUserURL:    input.NewUserURL,
		ErrorURL:      input.ErrorURL,
		CodeVerifier:  codeVerifier,
		LinkUserID:    input.LinkUserID,
		LinkEmail:     input.LinkEmail,
		RequestSignUp: input.RequestSignUp,
	}
	value, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}
	if err := c.Auth.CreateVerification(c.R.Context(), constants.VerificationOAuth2State+state, string(value), 10*time.Minute); err != nil {
		return "", "", err
	}
	return state, codeVerifier, nil
}

func genericOAuthExchangeAuthorizationCode(c *auth.Context, p GenericOAuthProviderConfig, code string, codeVerifier string) (*provider.OAuthTokens, error) {
	redirectURI := genericOAuthRedirectURI(c, p)
	if p.GetToken != nil {
		tokens, err := p.GetToken(c.R.Context(), GenericOAuthGetTokenParams{
			Code:         code,
			RedirectURI:  redirectURI,
			CodeVerifier: codeVerifier,
		})
		if err != nil {
			return nil, err
		}
		if tokens == nil {
			return nil, errors.New("tokens are missing")
		}
		return genericOAuthApplyAccessTokenExpiresIn(p, tokens), nil
	}
	tokenURL, err := genericOAuthTokenEndpoint(c, p)
	if err != nil {
		return nil, err
	}
	data, err := provider.ExchangeAuthorizationCode(c.R.Context(), provider.CodeExchangeOpts{
		TokenURL:       tokenURL,
		ClientID:       p.ClientID,
		ClientSecret:   p.ClientSecret,
		Code:           code,
		RedirectURI:    redirectURI,
		CodeVerifier:   codeVerifier,
		Authentication: p.Authentication,
		Headers:        p.AuthorizationHeaders,
		ExtraParams:    p.TokenURLParams,
		ExtraOverwrite: true,
	})
	if err != nil {
		return nil, err
	}
	tokens := provider.TokensFromMap(data)
	return genericOAuthApplyAccessTokenExpiresIn(p, tokens), nil
}

func genericOAuthApplyAccessTokenExpiresIn(p GenericOAuthProviderConfig, tokens *provider.OAuthTokens) *provider.OAuthTokens {
	if tokens.AccessTokenExpiresAt == nil && p.AccessTokenExpiresIn > 0 {
		expiresAt := time.Now().Add(time.Duration(p.AccessTokenExpiresIn) * time.Second)
		tokens.AccessTokenExpiresAt = &expiresAt
	}
	return tokens
}

func genericOAuthTokenEndpoint(c *auth.Context, p GenericOAuthProviderConfig) (string, error) {
	tokenURL := p.TokenURL
	if p.DiscoveryURL != "" {
		discovery, err := genericOAuthDiscovery(c, p)
		if err != nil {
			return "", err
		}
		if discovery.TokenEndpoint != "" {
			tokenURL = discovery.TokenEndpoint
		}
	}
	if tokenURL == "" {
		return "", fmt.Errorf("invalid generic oauth configuration for provider %q: tokenURL=%q", p.ProviderID, tokenURL)
	}
	return tokenURL, nil
}

func genericOAuthUserInfoEndpoint(c *auth.Context, p GenericOAuthProviderConfig) (string, error) {
	userInfoURL := p.UserInfoURL
	if p.DiscoveryURL != "" {
		discovery, err := genericOAuthDiscovery(c, p)
		if err != nil {
			return "", err
		}
		if discovery.UserInfoEndpoint != "" {
			userInfoURL = discovery.UserInfoEndpoint
		}
	}
	if userInfoURL == "" {
		return "", fmt.Errorf("invalid generic oauth configuration for provider %q: userInfoURL=%q", p.ProviderID, userInfoURL)
	}
	return userInfoURL, nil
}

func genericOAuthUserInfo(c *auth.Context, p GenericOAuthProviderConfig, tokens *provider.OAuthTokens) (provider.OAuthUser, error) {
	if tokens == nil || tokens.AccessToken == "" {
		return provider.OAuthUser{}, errors.New("access token missing")
	}
	if p.GetUserInfo != nil {
		info, err := p.GetUserInfo(c.R.Context(), *tokens)
		if err != nil {
			return provider.OAuthUser{}, err
		}
		if info == nil {
			return provider.OAuthUser{}, errors.New("user info is missing")
		}
		return genericOAuthMappedUser(c, p, info.User, genericOAuthProfileFromUserInfo(info))
	}
	if tokens.IDToken != "" {
		claims, err := jwt.DecodePayload(tokens.IDToken)
		if err != nil {
			return provider.OAuthUser{}, err
		}
		user, err := genericOAuthUserFromMap(c, p, claims)
		if err == nil {
			return user, nil
		}
	}
	userInfoURL, err := genericOAuthUserInfoEndpoint(c, p)
	if err != nil {
		return provider.OAuthUser{}, err
	}
	req, err := http.NewRequestWithContext(c.R.Context(), http.MethodGet, userInfoURL, nil)
	if err != nil {
		return provider.OAuthUser{}, err
	}
	req.Header.Set(constants.HeaderAccept, constants.MIMEJSON)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return provider.OAuthUser{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return provider.OAuthUser{}, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return provider.OAuthUser{}, fmt.Errorf("generic oauth userinfo failed for provider %q at %q with status %d: %s", p.ProviderID, userInfoURL, resp.StatusCode, string(body))
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return provider.OAuthUser{}, err
	}
	return genericOAuthUserFromMap(c, p, data)
}

func genericOAuthUserFromMap(c *auth.Context, p GenericOAuthProviderConfig, data map[string]any) (provider.OAuthUser, error) {
	accountID := firstGenericOAuthString(data, "id", "sub")
	name := firstGenericOAuthString(data, "name")
	imageValue := firstGenericOAuthString(data, "image", "picture", "avatar_url")
	var image *string
	if imageValue != "" {
		image = &imageValue
	}
	emailVerified, _ := data["email_verified"].(bool)
	return genericOAuthMappedUser(c, p, provider.OAuthUser{
		ID: accountID, Name: name, Email: firstGenericOAuthString(data, "email"), Image: image, EmailVerified: emailVerified,
	}, data)
}

func genericOAuthMappedUser(c *auth.Context, p GenericOAuthProviderConfig, user provider.OAuthUser, profile map[string]any) (provider.OAuthUser, error) {
	if p.MapProfileToUser != nil {
		mapping, err := p.MapProfileToUser(c.R.Context(), cloneGenericOAuthProfile(profile))
		if err != nil {
			return provider.OAuthUser{}, err
		}
		user = provider.ApplyOAuthUserMapping(user, mapping)
	}
	return normalizeGenericOAuthUser(user)
}

func genericOAuthProfileFromUserInfo(info *provider.UserInfo) map[string]any {
	profile := cloneGenericOAuthProfile(info.Data)
	if _, ok := profile["id"]; !ok && info.User.ID != "" {
		profile["id"] = info.User.ID
	}
	if _, ok := profile["name"]; !ok && info.User.Name != "" {
		profile["name"] = info.User.Name
	}
	if _, ok := profile["email"]; !ok && info.User.Email != "" {
		profile["email"] = info.User.Email
	}
	if _, ok := profile["email_verified"]; !ok {
		profile["email_verified"] = info.User.EmailVerified
	}
	if _, ok := profile["image"]; !ok && info.User.Image != nil {
		profile["image"] = *info.User.Image
	}
	return profile
}

func cloneGenericOAuthProfile(profile map[string]any) map[string]any {
	out := make(map[string]any, len(profile))
	for key, value := range profile {
		out[key] = value
	}
	return out
}

func normalizeGenericOAuthUser(user provider.OAuthUser) (provider.OAuthUser, error) {
	if user.ID == "" {
		return provider.OAuthUser{}, errors.New("id is missing")
	}
	if user.Name == "" {
		return provider.OAuthUser{}, errors.New("name is missing")
	}
	user.Email = auth.NormalizeEmail(user.Email)
	if user.Email == "" {
		return provider.OAuthUser{}, errors.New("email is missing")
	}
	return user, nil
}

func firstGenericOAuthString(data map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := data[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			if typed != "" {
				return typed
			}
		case float64:
			return strconv.FormatFloat(typed, 'f', -1, 64)
		case bool:
			return strconv.FormatBool(typed)
		}
	}
	return ""
}

func genericOAuthSignInUser(c *auth.Context, p GenericOAuthProviderConfig, stateData genericOAuthStatePayload, userInfo provider.OAuthUser, tokens *provider.OAuthTokens) (*types.User, bool, error) {
	account, err := c.Auth.Store().FindAccountByProviderAndAccountID(c.R.Context(), p.ProviderID, userInfo.ID)
	if err == nil {
		if err := updateGenericOAuthAccount(c, account.ID, tokens); err != nil {
			return nil, false, err
		}
		user, err := c.Auth.Store().FindUserByID(c.R.Context(), account.UserID)
		if err != nil {
			return nil, false, err
		}
		if p.OverrideUserInfo {
			updated, err := overrideGenericOAuthUserInfo(c, user, userInfo)
			return updated, false, err
		}
		return user, false, nil
	}
	if !errors.Is(err, berrors.ErrNotFound) {
		return nil, false, err
	}
	existing, err := c.Auth.Store().FindUserByEmail(c.R.Context(), userInfo.Email)
	if err == nil && existing != nil {
		return nil, false, errors.New("account not linked")
	}
	if err != nil && !errors.Is(err, berrors.ErrNotFound) {
		return nil, false, err
	}
	if p.DisableSignUp || p.DisableImplicitSignUp && !stateData.RequestSignUp {
		return nil, false, errors.New("signup disabled")
	}
	user, err := createGenericOAuthUser(c, userInfo)
	if err != nil {
		return nil, false, err
	}
	if err := createGenericOAuthAccount(c, p.ProviderID, user.ID, userInfo.ID, tokens); err != nil {
		return nil, false, err
	}
	return user, true, nil
}

func createGenericOAuthUser(c *auth.Context, userInfo provider.OAuthUser) (*types.User, error) {
	now := time.Now()
	userID, err := id.Generate(32)
	if err != nil {
		return nil, err
	}
	user := &types.User{
		ID: userID, Name: userInfo.Name, Email: userInfo.Email, EmailVerified: userInfo.EmailVerified,
		Image: userInfo.Image, CreatedAt: now, UpdatedAt: now,
	}
	if err := c.Auth.Store().CreateUser(c.R.Context(), user); err != nil {
		return nil, err
	}
	return user, nil
}

func overrideGenericOAuthUserInfo(c *auth.Context, user *types.User, userInfo provider.OAuthUser) (*types.User, error) {
	email := auth.NormalizeEmail(userInfo.Email)
	emailVerified := userInfo.EmailVerified
	if strings.EqualFold(email, user.Email) {
		emailVerified = user.EmailVerified || userInfo.EmailVerified
	}
	update := store.UserUpdate{
		Name:          &userInfo.Name,
		Email:         &email,
		EmailVerified: &emailVerified,
	}
	if userInfo.Image != nil {
		update.Image = &userInfo.Image
	}
	return c.Auth.Store().UpdateUser(c.R.Context(), user.ID, update)
}

func createGenericOAuthAccount(c *auth.Context, providerID string, userID string, accountID string, tokens *provider.OAuthTokens) error {
	now := time.Now()
	idValue, err := id.Generate(32)
	if err != nil {
		return err
	}
	return c.Auth.Store().CreateAccount(c.R.Context(), &types.Account{
		ID: idValue, AccountID: accountID, ProviderID: providerID, UserID: userID,
		AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken,
		AccessTokenExpiresAt: tokens.AccessTokenExpiresAt, RefreshTokenExpiresAt: tokens.RefreshTokenExpiresAt,
		IDToken: tokens.IDToken, Scope: strings.Join(tokens.Scopes, ","), CreatedAt: now, UpdatedAt: now,
	})
}

func updateGenericOAuthAccount(c *auth.Context, accountID string, tokens *provider.OAuthTokens) error {
	update := store.AccountUpdate{
		AccessTokenExpiresAt:  tokens.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: tokens.RefreshTokenExpiresAt,
	}
	hasUpdate := tokens.AccessTokenExpiresAt != nil || tokens.RefreshTokenExpiresAt != nil
	if tokens.AccessToken != "" {
		update.AccessToken = &tokens.AccessToken
		hasUpdate = true
	}
	if tokens.RefreshToken != "" {
		update.RefreshToken = &tokens.RefreshToken
		hasUpdate = true
	}
	if tokens.IDToken != "" {
		update.IDToken = &tokens.IDToken
		hasUpdate = true
	}
	if len(tokens.Scopes) > 0 {
		scope := strings.Join(tokens.Scopes, ",")
		update.Scope = &scope
		hasUpdate = true
	}
	if !hasUpdate {
		return nil
	}
	_, err := c.Auth.Store().UpdateAccount(c.R.Context(), accountID, update)
	return err
}

func handleGenericOAuthLinkCallback(c *auth.Context, stateData genericOAuthStatePayload, userInfo provider.OAuthUser, tokens *provider.OAuthTokens) {
	errorURL := genericOAuthCallbackErrorURL(c, stateData)
	if !strings.EqualFold(stateData.LinkEmail, userInfo.Email) {
		redirectGenericOAuthError(c, errorURL, "email_doesn't_match", "")
		return
	}
	existing, err := c.Auth.Store().FindAccountByProviderAndAccountID(c.R.Context(), stateData.ProviderID, userInfo.ID)
	if err == nil {
		if existing.UserID != stateData.LinkUserID {
			redirectGenericOAuthError(c, errorURL, "account_already_linked_to_different_user", "")
			return
		}
		if err := updateGenericOAuthAccount(c, existing.ID, tokens); err != nil {
			redirectGenericOAuthError(c, errorURL, "unable_to_link_account", "")
			return
		}
		c.Redirect(stateData.CallbackURL)
		return
	}
	if !errors.Is(err, berrors.ErrNotFound) {
		redirectGenericOAuthError(c, errorURL, "unable_to_link_account", "")
		return
	}
	if err := createGenericOAuthAccount(c, stateData.ProviderID, stateData.LinkUserID, userInfo.ID, tokens); err != nil {
		redirectGenericOAuthError(c, errorURL, "unable_to_link_account", "")
		return
	}
	c.Redirect(stateData.CallbackURL)
}

func genericOAuthDefaultErrorURL(c *auth.Context) string {
	return c.Auth.BaseURL() + c.Auth.BasePath() + "/error"
}

func genericOAuthCallbackErrorURL(c *auth.Context, stateData genericOAuthStatePayload) string {
	if stateData.ErrorURL != "" {
		return stateData.ErrorURL
	}
	return genericOAuthDefaultErrorURL(c)
}

func redirectGenericOAuthError(c *auth.Context, errorURL string, code string, description string) {
	target := appendGenericOAuthQuery(errorURL, "error", code)
	if description != "" {
		target = appendGenericOAuthQuery(target, "error_description", description)
	}
	c.Redirect(target)
}

func appendGenericOAuthQuery(rawURL string, key string, value string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		separator := "?"
		if strings.Contains(rawURL, "?") {
			separator = "&"
		}
		return rawURL + separator + url.QueryEscape(key) + "=" + url.QueryEscape(value)
	}
	query := parsed.Query()
	query.Set(key, value)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func genericOAuthAuthorizationValues(c *auth.Context, p GenericOAuthProviderConfig, state string, scopes []string, codeVerifier string) url.Values {
	responseType := p.ResponseType
	if responseType == "" {
		responseType = "code"
	}
	q := url.Values{
		"client_id":     {p.ClientID},
		"response_type": {responseType},
		"redirect_uri":  {genericOAuthRedirectURI(c, p)},
		"scope":         {joinScopes(scopes)},
		"state":         {state},
	}
	if p.Prompt != "" {
		q.Set("prompt", p.Prompt)
	}
	if p.AccessType != "" {
		q.Set("access_type", p.AccessType)
	}
	if p.ResponseMode != "" {
		q.Set("response_mode", p.ResponseMode)
	}
	if codeVerifier != "" {
		q.Set("code_challenge_method", "S256")
		q.Set("code_challenge", oauth2pkg.CodeChallengeS256(codeVerifier))
	}
	for key, value := range p.AuthorizationURLParams {
		q.Set(key, value)
	}
	return q
}

func genericOAuthRedirectURI(c *auth.Context, p GenericOAuthProviderConfig) string {
	if p.RedirectURI != "" {
		return p.RedirectURI
	}
	return c.Auth.BaseURL() + c.Auth.BasePath() + "/oauth2/callback/" + p.ProviderID
}

func genericOAuthSignInScopes(requestScopes []string, configuredScopes []string) []string {
	if len(requestScopes) == 0 {
		return configuredScopes
	}
	scopes := make([]string, 0, len(requestScopes)+len(configuredScopes))
	scopes = append(scopes, requestScopes...)
	scopes = append(scopes, configuredScopes...)
	return scopes
}

func genericOAuthLinkScopes(requestScopes []string, configuredScopes []string) []string {
	if len(requestScopes) == 0 {
		return configuredScopes
	}
	return requestScopes
}

func joinScopes(scopes []string) string {
	if len(scopes) == 0 {
		return "openid email profile"
	}
	out := ""
	for i, s := range scopes {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}
