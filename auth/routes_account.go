package auth

import (
	constants "github.com/patrickkabwe/betterauth-go/constants"
	"net/http"
	"strings"

	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

func handleListAccounts(c *Context) {
	sess, _, ok := c.RequireSession()
	if !ok {
		return
	}

	accounts, err := c.Auth.cfg.store.ListAccountsByUserID(c.R.Context(), sess.UserID)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}

	resp := make([]types.AccountResponse, 0, len(accounts))
	for _, a := range accounts {
		resp = append(resp, toAccountResponse(a))
	}
	c.WriteJSON(http.StatusOK, resp)
}

type linkSocialIDTokenBody struct {
	Token        string   `json:"token"`
	Nonce        string   `json:"nonce,omitempty"`
	AccessToken  string   `json:"accessToken,omitempty"`
	RefreshToken string   `json:"refreshToken,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

type linkSocialBody struct {
	Provider         string                 `json:"provider"`
	CallbackURL      string                 `json:"callbackURL,omitempty"`
	IDToken          *linkSocialIDTokenBody `json:"idToken,omitempty"`
	Scopes           []string               `json:"scopes,omitempty"`
	ErrorCallbackURL string                 `json:"errorCallbackURL,omitempty"`
	DisableRedirect  *bool                  `json:"disableRedirect,omitempty"`
	AdditionalData   map[string]any         `json:"additionalData,omitempty"`
}

func handleLinkSocial(c *Context) {
	sess, user, ok := c.RequireSession()
	if !ok {
		return
	}

	var body linkSocialBody
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidEmail, constants.MsgInvalidRequestBody))
		return
	}
	if body.Provider == "" {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeProviderNotFound))
		return
	}

	p, ok := c.Auth.socialProvider(body.Provider)
	if !ok {
		c.WriteError(apierror.WithCode(http.StatusNotFound, apierror.CodeProviderNotFound))
		return
	}

	if body.IDToken != nil && body.IDToken.Token != "" {
		if linkErr := c.Auth.linkWithIDToken(c, sess, user, p, body); linkErr != nil {
			c.WriteError(linkErr)
			return
		}
		c.WriteJSON(http.StatusOK, types.LinkSocialResponse{URL: "", Redirect: false, Status: true})
		return
	}

	callback := body.CallbackURL
	if callback == "" {
		callback = "/"
	}
	state, codeVerifier, err := c.Auth.generateOAuthState(c, oauthStateInput{
		CallbackURL: callback, ErrorCallbackURL: body.ErrorCallbackURL,
		Link:           &oauthLinkState{UserID: sess.UserID, Email: user.Email},
		AdditionalData: body.AdditionalData,
	})
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}

	authURL, err := p.CreateAuthorizationURL(c.R.Context(), provider.AuthorizationURLOpts{
		State: state, CodeVerifier: codeVerifier,
		RedirectURI: c.Auth.cfg.baseURL + c.Auth.cfg.basePath + "/callback/" + p.ID(),
		Scopes:      body.Scopes,
	})
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}

	disableRedirect := body.DisableRedirect != nil && *body.DisableRedirect
	if !disableRedirect {
		c.W.Header().Set("Location", authURL)
	}
	c.WriteJSON(http.StatusOK, types.LinkSocialResponse{
		URL:      authURL,
		Redirect: !disableRedirect,
	})
}

type unlinkAccountBody struct {
	ProviderID string `json:"providerId"`
	AccountID  string `json:"accountId"`
}

func handleUnlinkAccount(c *Context) {
	sess, _, ok := c.requireFreshSession(SessionOpts{})
	if !ok {
		return
	}

	var body unlinkAccountBody
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidEmail, constants.MsgInvalidRequestBody))
		return
	}

	accounts, err := c.Auth.cfg.store.ListAccountsByUserID(c.R.Context(), sess.UserID)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}

	if len(accounts) == 1 && !c.Auth.cfg.account.allowUnlinkingAll {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeFailedToUnlinkLastAccount, constants.MsgCannotUnlinkLastAccount))
		return
	}

	var target *types.Account
	for i := range accounts {
		a := &accounts[i]
		if a.ProviderID == body.ProviderID && (body.AccountID == "" || a.AccountID == body.AccountID) {
			target = a
			break
		}
	}
	if target == nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeAccountNotFound))
		return
	}

	if err := c.Auth.cfg.store.DeleteAccount(c.R.Context(), target.ID); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	c.WriteJSON(http.StatusOK, types.StatusResponse{Status: true})
}

type accessTokenBody struct {
	ProviderID string `json:"providerId"`
	AccountID  string `json:"accountId,omitempty"`
	UserID     string `json:"userId,omitempty"`
}

func handleGetAccessToken(c *Context) {
	var body accessTokenBody
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidEmail, constants.MsgInvalidRequestBody))
		return
	}
	if body.ProviderID == "" {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeProviderNotSupported, constants.MsgProviderIsNotSupported))
		return
	}

	userID, err := c.Auth.resolveAccountUserID(c, body.UserID)
	if err != nil {
		c.WriteError(err)
		return
	}

	tokens, err := c.Auth.getValidAccessToken(c, userID, body.ProviderID, body.AccountID, nil)
	if err != nil {
		c.WriteError(err)
		return
	}
	c.WriteJSON(http.StatusOK, types.AccessTokenResponse{
		AccessToken:          tokens.AccessToken,
		AccessTokenExpiresAt: tokens.AccessTokenExpiresAt,
		IDToken:              tokens.IDToken,
		Scopes:               tokens.Scopes,
	})
}

func handleRefreshToken(c *Context) {
	var body accessTokenBody
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidEmail, constants.MsgInvalidRequestBody))
		return
	}
	if body.ProviderID == "" {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeProviderNotSupported, constants.MsgProviderIsNotSupported))
		return
	}

	userID, apiErr := c.Auth.resolveAccountUserID(c, body.UserID)
	if apiErr != nil {
		c.WriteError(apiErr)
		return
	}

	p, ok := c.Auth.socialProvider(body.ProviderID)
	if !ok {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeProviderNotSupported, constants.MsgProviderIsNotSupported))
		return
	}
	refresher, ok := p.(provider.TokenRefresher)
	if !ok {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeTokenRefreshNotSupported, constants.MsgProviderNoTokenRefresh))
		return
	}

	accounts, err := c.Auth.cfg.store.ListAccountsByUserID(c.R.Context(), userID)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	account := findUserAccount(accounts, body.ProviderID, body.AccountID)
	if account == nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeAccountNotFound))
		return
	}
	if account.RefreshToken == "" {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeRefreshTokenNotFound))
		return
	}

	newTokens, err := refresher.RefreshAccessToken(c.R.Context(), account.RefreshToken)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeFailedToRefreshAccessToken))
		return
	}

	refreshToken := newTokens.RefreshToken
	if refreshToken == "" {
		refreshToken = account.RefreshToken
	}
	refreshExpires := newTokens.RefreshTokenExpiresAt
	if refreshExpires == nil {
		refreshExpires = account.RefreshTokenExpiresAt
	}
	scope := account.Scope
	if len(newTokens.Scopes) > 0 {
		scope = strings.Join(newTokens.Scopes, ",")
	}
	idToken := newTokens.IDToken
	if idToken == "" {
		idToken = account.IDToken
	}

	update := store.AccountUpdate{
		AccessToken:           &newTokens.AccessToken,
		RefreshToken:          &refreshToken,
		AccessTokenExpiresAt:  newTokens.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: refreshExpires,
		IDToken:               &idToken,
		Scope:                 &scope,
	}
	if _, err := c.Auth.cfg.store.UpdateAccount(c.R.Context(), account.ID, update); err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeFailedToRefreshAccessToken))
		return
	}

	c.WriteJSON(http.StatusOK, types.RefreshTokenResponse{
		AccessToken:           newTokens.AccessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  newTokens.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: refreshExpires,
		Scope:                 scope,
		IDToken:               idToken,
		ProviderID:            account.ProviderID,
		AccountID:             account.AccountID,
	})
}

func handleAccountInfo(c *Context) {
	accountID := c.R.URL.Query().Get("accountId")
	providerID := c.R.URL.Query().Get("providerId")
	userIDParam := c.R.URL.Query().Get("userId")

	userID, apiErr := c.Auth.resolveAccountUserID(c, userIDParam)
	if apiErr != nil {
		c.WriteError(apiErr)
		return
	}

	var account *types.Account
	if accountID != "" {
		accounts, err := c.Auth.cfg.store.ListAccountsByUserID(c.R.Context(), userID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		var matches []types.Account
		for _, a := range accounts {
			if a.AccountID == accountID && (providerID == "" || a.ProviderID == providerID) {
				matches = append(matches, a)
			}
		}
		if len(matches) > 1 {
			c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeAmbiguousAccount, constants.MsgAmbiguousAccountDetail))
			return
		}
		if len(matches) == 1 {
			account = &matches[0]
		}
	}

	if account == nil || account.UserID != userID {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeAccountNotFound))
		return
	}

	p, ok := c.Auth.socialProvider(account.ProviderID)
	if !ok {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeProviderNotConfigured, constants.MsgProviderNotConfiguredAcct))
		return
	}

	tokens, apiErr := c.Auth.getValidAccessToken(c, userID, account.ProviderID, account.AccountID, account)
	if apiErr != nil {
		c.WriteError(apiErr)
		return
	}
	if tokens.AccessToken == "" {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeAccessTokenNotFound))
		return
	}

	info, err := p.GetUserInfo(c.R.Context(), provider.OAuthTokens{
		AccessToken:          tokens.AccessToken,
		AccessTokenExpiresAt: tokens.AccessTokenExpiresAt,
		IDToken:              tokens.IDToken,
		Scopes:               tokens.Scopes,
	})
	if err != nil || info == nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeFailedToGetUserInfo))
		return
	}

	data := info.Data
	if data == nil {
		data = map[string]any{}
	}
	c.WriteJSON(http.StatusOK, types.AccountInfoResponse{
		User: types.OAuthUserInfo{
			ID:            info.User.ID,
			Name:          info.User.Name,
			Email:         info.User.Email,
			Image:         info.User.Image,
			EmailVerified: info.User.EmailVerified,
		},
		Data: data,
	})
}
