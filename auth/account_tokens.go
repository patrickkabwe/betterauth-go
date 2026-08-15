package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

func (a *Auth) socialProvider(providerID string) (provider.SocialProvider, bool) {
	if a.cfg.socialProviders == nil {
		return nil, false
	}
	p, ok := a.cfg.socialProviders[providerID]
	return p, ok
}

func (a *Auth) resolveAccountUserID(c *Context, userID string) (string, *apierror.Error) {
	sess, user, err := c.GetSession()
	if err != nil || user == nil {
		if c.R != nil {
			return "", apierror.WithCode(http.StatusUnauthorized, apierror.CodeUnauthorized)
		}
		if userID == "" {
			return "", apierror.New(http.StatusBadRequest, apierror.CodeUserIDOrSessionRequired, constants.MsgUserIDOrSessionRequired)
		}
		return userID, nil
	}
	_ = sess
	if userID != "" && userID != user.ID {
		return user.ID, nil
	}
	return user.ID, nil
}

func findUserAccount(accounts []types.Account, providerID, accountID string) *types.Account {
	for i := range accounts {
		a := &accounts[i]
		if a.ProviderID != providerID {
			continue
		}
		if accountID == "" || a.AccountID == accountID {
			return a
		}
	}
	return nil
}

type validAccessToken struct {
	AccessToken          string
	AccessTokenExpiresAt *time.Time
	IDToken              string
	Scopes               []string
}

func (a *Auth) getValidAccessToken(c *Context, userID, providerID, accountID string, account *types.Account) (*validAccessToken, *apierror.Error) {
	p, ok := a.socialProvider(providerID)
	if !ok {
		return nil, apierror.New(http.StatusBadRequest, apierror.CodeProviderNotSupported, constants.MsgProviderIsNotSupported)
	}

	if account == nil {
		accounts, err := a.cfg.store.ListAccountsByUserID(c.R.Context(), userID)
		if err != nil {
			return nil, apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError)
		}
		account = findUserAccount(accounts, providerID, accountID)
	}
	if account == nil {
		return nil, apierror.WithCode(http.StatusBadRequest, apierror.CodeAccountNotFound)
	}

	accessToken := account.AccessToken
	accessTokenExpiresAt := account.AccessTokenExpiresAt
	idToken := account.IDToken

	expired := accessTokenExpiresAt != nil && accessTokenExpiresAt.Sub(time.Now()) < 5*time.Second
	refresher, canRefresh := p.(provider.TokenRefresher)
	if account.RefreshToken != "" && expired && canRefresh {
		newTokens, err := refresher.RefreshAccessToken(c.R.Context(), account.RefreshToken)
		if err != nil {
			return nil, apierror.New(http.StatusBadRequest, apierror.CodeFailedToGetAccessToken, constants.MsgFailedValidAccessToken)
		}
		update := store.AccountUpdate{
			AccessToken:          &newTokens.AccessToken,
			AccessTokenExpiresAt: newTokens.AccessTokenExpiresAt,
		}
		if newTokens.RefreshToken != "" {
			update.RefreshToken = &newTokens.RefreshToken
		}
		if newTokens.RefreshTokenExpiresAt != nil {
			update.RefreshTokenExpiresAt = newTokens.RefreshTokenExpiresAt
		}
		if newTokens.IDToken != "" {
			update.IDToken = &newTokens.IDToken
		}
		updated, err := a.cfg.store.UpdateAccount(c.R.Context(), account.ID, update)
		if err != nil {
			return nil, apierror.New(http.StatusBadRequest, apierror.CodeFailedToGetAccessToken, constants.MsgFailedValidAccessToken)
		}
		account = updated
		accessToken = newTokens.AccessToken
		accessTokenExpiresAt = newTokens.AccessTokenExpiresAt
		if newTokens.IDToken != "" {
			idToken = newTokens.IDToken
		}
	}

	scopes := []string{}
	if account.Scope != "" {
		scopes = strings.Split(account.Scope, ",")
	}

	return &validAccessToken{
		AccessToken:          accessToken,
		AccessTokenExpiresAt: accessTokenExpiresAt,
		IDToken:              idToken,
		Scopes:               scopes,
	}, nil
}
