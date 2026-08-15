package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	constants "github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/types"
)

type signInSocialBody struct {
	Provider           string                 `json:"provider"`
	CallbackURL        string                 `json:"callbackURL,omitempty"`
	NewUserCallbackURL string                 `json:"newUserCallbackURL,omitempty"`
	ErrorCallbackURL   string                 `json:"errorCallbackURL,omitempty"`
	DisableRedirect    *bool                  `json:"disableRedirect,omitempty"`
	IDToken            *linkSocialIDTokenBody `json:"idToken,omitempty"`
	Scopes             []string               `json:"scopes,omitempty"`
	RequestSignUp      *bool                  `json:"requestSignUp,omitempty"`
	LoginHint          string                 `json:"loginHint,omitempty"`
	AdditionalData     map[string]any         `json:"additionalData,omitempty"`
}

func handleSignInSocial(c *Context) {
	var body signInSocialBody
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidEmail, constants.MsgInvalidRequestBody))
		return
	}
	if body.Provider == "" {
		c.WriteError(apierror.WithCode(http.StatusNotFound, apierror.CodeProviderNotFound))
		return
	}

	p, ok := c.Auth.socialProvider(body.Provider)
	if !ok {
		c.WriteError(apierror.WithCode(http.StatusNotFound, apierror.CodeProviderNotFound))
		return
	}

	if body.IDToken != nil && body.IDToken.Token != "" {
		handleSocialIDTokenSignIn(c, p, body)
		return
	}

	oauthP, ok := p.(provider.OAuthProvider)
	if !ok {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeOAuthNotImplemented, constants.MsgOAuthNotImplementedProvider))
		return
	}

	requestSignUp := body.RequestSignUp != nil && *body.RequestSignUp
	state, codeVerifier, err := c.Auth.generateOAuthState(c, oauthStateInput{
		CallbackURL: body.CallbackURL, ErrorCallbackURL: body.ErrorCallbackURL,
		NewUserCallbackURL: body.NewUserCallbackURL, RequestSignUp: requestSignUp,
		AdditionalData: body.AdditionalData,
	})
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}

	redirectURI := c.Auth.cfg.baseURL + c.Auth.cfg.basePath + "/callback/" + oauthP.ID()
	authURL, err := oauthP.CreateAuthorizationURL(c.R.Context(), provider.AuthorizationURLOpts{
		State: state, CodeVerifier: codeVerifier, RedirectURI: redirectURI, Scopes: body.Scopes, LoginHint: body.LoginHint,
	})
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}

	disableRedirect := body.DisableRedirect != nil && *body.DisableRedirect
	if !disableRedirect {
		c.W.Header().Set("Location", authURL)
	}
	c.WriteJSON(http.StatusOK, types.SocialSignInResponse{URL: authURL, Redirect: !disableRedirect})
}

func handleSocialIDTokenSignIn(c *Context, p provider.SocialProvider, body signInSocialBody) {
	linker, ok := p.(provider.IDTokenLinker)
	if !ok {
		c.WriteError(apierror.New(http.StatusNotFound, apierror.CodeIDTokenNotSupported, constants.MsgIDTokenNotSupportedDetail))
		return
	}
	nonce := ""
	if body.IDToken != nil {
		nonce = body.IDToken.Nonce
	}
	valid, err := linker.VerifyIDToken(c.R.Context(), body.IDToken.Token, nonce)
	if err != nil || !valid {
		c.WriteError(apierror.WithCode(http.StatusUnauthorized, apierror.CodeInvalidToken))
		return
	}
	tokens := provider.OAuthTokens{
		AccessToken: body.IDToken.AccessToken, RefreshToken: body.IDToken.RefreshToken,
		IDToken: body.IDToken.Token, Scopes: body.IDToken.Scopes, User: body.IDToken.User,
	}
	info, err := p.GetUserInfo(c.R.Context(), tokens)
	if err != nil || info == nil {
		c.WriteError(apierror.WithCode(http.StatusUnauthorized, apierror.CodeFailedToGetUserInfo))
		return
	}
	if info.User.Email == "" {
		c.WriteError(apierror.WithCode(http.StatusUnauthorized, apierror.CodeUserEmailNotFound))
		return
	}
	account := oauthAccountInput{
		ProviderID:  p.ID(),
		AccountID:   info.User.ID,
		AccessToken: tokens.AccessToken,
	}
	requestSignUp := body.RequestSignUp != nil && *body.RequestSignUp
	result, err := c.Auth.handleOAuthUserInfo(c, info.User, account, oauthUserOptions{
		DisableSignUp: c.Auth.socialSignUpDisabled(p, requestSignUp),
		CallbackURL:   body.CallbackURL,
	})
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	if result.Error != "" {
		c.WriteError(apierror.New(http.StatusUnauthorized, apierror.CodeOAuthLinkError, result.Error))
		return
	}
	c.WriteJSON(http.StatusOK, types.SocialSignInResponse{
		Redirect: false, Token: result.Session.Token, User: toUserResponse(result.User),
	})
}

func handleOAuthCallback(c *Context) {
	providerID := c.Vars["provider"]
	defaultErrorURL := c.Auth.cfg.baseURL + c.Auth.cfg.basePath + "/error"

	if c.R.Method == http.MethodPost {
		redirectOAuthPostCallback(c, providerID)
		return
	}

	p, ok := c.Auth.socialProvider(providerID)
	if !ok {
		redirectOAuthError(c, defaultErrorURL, "oauth_provider_not_found")
		return
	}
	oauthP, ok := p.(provider.OAuthProvider)
	if !ok {
		redirectOAuthError(c, defaultErrorURL, "oauth_provider_not_found")
		return
	}

	q := c.R.URL.Query()
	code := q.Get("code")
	state := q.Get("state")

	var stateData *oauthStatePayload
	if state != "" {
		parsed, err := c.Auth.parseOAuthState(c, state)
		if err != nil {
			redirectOAuthError(c, defaultErrorURL, "state_mismatch")
			return
		}
		stateData = parsed
	}

	errorURL := defaultErrorURL
	if stateData != nil && stateData.ErrorURL != "" {
		errorURL = stateData.ErrorURL
	}
	if errParam := q.Get("error"); errParam != "" {
		redirectOAuthErrorWithDescription(c, errorURL, errParam, q.Get("error_description"))
		return
	}
	if code == "" || state == "" {
		redirectOAuthError(c, errorURL, "no_code")
		return
	}
	if stateData.CallbackURL == "" {
		redirectOAuthError(c, errorURL, "no_callback_url")
		return
	}

	redirectURI := c.Auth.cfg.baseURL + c.Auth.cfg.basePath + "/callback/" + providerID
	tokens, err := oauthP.ValidateAuthorizationCode(c.R.Context(), code, stateData.CodeVerifier, redirectURI)
	if err != nil {
		redirectOAuthError(c, errorURL, "invalid_code")
		return
	}
	if userData := parseOAuthCallbackUser(q.Get("user")); userData != nil {
		tokens.User = userData
	}

	info, err := p.GetUserInfo(c.R.Context(), *tokens)
	if err != nil || info == nil || info.User.ID == "" {
		redirectOAuthError(c, errorURL, "unable_to_get_user_info")
		return
	}
	if info.User.Email == "" {
		redirectOAuthError(c, errorURL, "email_not_found")
		return
	}

	accountInput := oauthAccountFromTokens(providerID, info.User.ID, tokens)

	if stateData.Link != nil {
		handleOAuthLinkCallback(c, stateData, info.User, accountInput)
		return
	}

	result, err := c.Auth.handleOAuthUserInfo(c, info.User, accountInput, oauthUserOptions{
		DisableSignUp:    c.Auth.socialSignUpDisabled(p, stateData.RequestSignUp),
		CallbackURL:      stateData.CallbackURL,
		OverrideUserInfo: c.Auth.shouldOverrideUserInfoOnSignIn(p),
	})
	if err != nil {
		redirectOAuthError(c, errorURL, "internal_server_error")
		return
	}
	if result.Error != "" {
		redirectOAuthError(c, errorURL, strings.ReplaceAll(result.Error, " ", "_"))
		return
	}

	redirectTo := stateData.CallbackURL
	if result.IsRegister && stateData.NewUserURL != "" {
		redirectTo = stateData.NewUserURL
	}
	c.Redirect(redirectTo)
}

func handleOAuthLinkCallback(c *Context, stateData *oauthStatePayload, userInfo provider.OAuthUser, account oauthAccountInput) {
	errorURL := stateData.ErrorURL
	if errorURL == "" {
		errorURL = c.Auth.cfg.baseURL + c.Auth.cfg.basePath + "/error"
	}

	if !c.Auth.linkingAllowed(account.ProviderID, userInfo.EmailVerified) {
		redirectOAuthError(c, errorURL, "unable_to_link_account")
		return
	}
	if !strings.EqualFold(userInfo.Email, stateData.Link.Email) && !c.Auth.cfg.account.allowDifferentEmails {
		redirectOAuthError(c, errorURL, "email_doesn't_match")
		return
	}

	existing, err := c.Auth.cfg.store.FindAccountByProviderAndAccountID(c.R.Context(), account.ProviderID, account.AccountID)
	if err == nil {
		if existing.UserID != stateData.Link.UserID {
			redirectOAuthError(c, errorURL, "account_already_linked_to_different_user")
			return
		}
		if err := c.Auth.updateOAuthAccountTokens(c, existing.ID, account); err != nil {
			redirectOAuthError(c, errorURL, "unable_to_link_account")
			return
		}
		c.Auth.applyUserInfoOnLink(c, stateData.Link.UserID, userInfo)
		c.Redirect(stateData.CallbackURL)
		return
	}
	if !errors.Is(err, berrors.ErrNotFound) {
		redirectOAuthError(c, errorURL, "unable_to_link_account")
		return
	}

	if err := c.Auth.saveOAuthAccount(c, stateData.Link.UserID, account); err != nil {
		redirectOAuthError(c, errorURL, "unable_to_link_account")
		return
	}
	c.Auth.applyUserInfoOnLink(c, stateData.Link.UserID, userInfo)
	c.Redirect(stateData.CallbackURL)
}

func redirectOAuthPostCallback(c *Context, providerID string) {
	params := url.Values{}
	var body map[string]any
	if err := c.ParseJSON(&body); err == nil {
		for key, value := range body {
			if value == nil {
				continue
			}
			if raw, ok := value.(json.RawMessage); ok {
				params.Set(key, strings.Trim(string(raw), `"`))
				continue
			}
			params.Set(key, stringFromOAuthCallbackValue(value))
		}
	}
	for key, values := range c.R.URL.Query() {
		for _, value := range values {
			params.Set(key, value)
		}
	}
	target := c.Auth.cfg.baseURL + c.Auth.cfg.basePath + "/callback/" + providerID
	if encoded := params.Encode(); encoded != "" {
		target += "?" + encoded
	}
	c.Redirect(target)
}

func parseOAuthCallbackUser(raw string) map[string]any {
	if raw == "" {
		return nil
	}
	var user map[string]any
	if err := json.Unmarshal([]byte(raw), &user); err != nil {
		return nil
	}
	return user
}

func stringFromOAuthCallbackValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return string(data)
	}
}

func redirectOAuthError(c *Context, errorURL, code string) {
	redirectOAuthErrorWithDescription(c, errorURL, code, "")
}

func redirectOAuthErrorWithDescription(c *Context, errorURL, code, description string) {
	if errorURL == "" {
		errorURL = c.Auth.cfg.baseURL + c.Auth.cfg.basePath + "/error"
	}
	target := appendQuery(errorURL, "error", code)
	if description != "" {
		target = appendQuery(target, "error_description", description)
	}
	c.Redirect(target)
}
