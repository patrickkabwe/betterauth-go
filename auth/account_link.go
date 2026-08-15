package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

func (a *Auth) linkingAllowed(providerID string, emailVerified bool) bool {
	if !a.cfg.account.linkingEnabled {
		return false
	}
	if a.cfg.account.trustedProviders[providerID] {
		return true
	}
	return emailVerified
}

func (a *Auth) applyUserInfoOnLink(c *Context, userID string, info provider.OAuthUser) {
	if !a.cfg.account.updateUserInfoOnLink {
		return
	}
	update := store.UserUpdate{}
	if info.Name != "" {
		update.Name = &info.Name
	}
	if info.Image != nil {
		update.Image = &info.Image
	}
	if update.Name == nil && update.Image == nil {
		return
	}
	_, _ = a.cfg.store.UpdateUser(c.R.Context(), userID, update)
}

func (a *Auth) createLinkedAccount(c *Context, userID string, p provider.SocialProvider, accountID string, tokens provider.OAuthTokens, idToken string) error {
	now := time.Now()
	accID, err := id.Generate(32)
	if err != nil {
		return err
	}
	scope := strings.Join(tokens.Scopes, ",")
	account := &types.Account{
		ID:                    accID,
		AccountID:             accountID,
		ProviderID:            p.ID(),
		UserID:                userID,
		AccessToken:           tokens.AccessToken,
		RefreshToken:          tokens.RefreshToken,
		AccessTokenExpiresAt:  tokens.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: tokens.RefreshTokenExpiresAt,
		IDToken:               idToken,
		Scope:                 scope,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	return a.cfg.store.CreateAccount(c.R.Context(), account)
}

func (a *Auth) linkWithIDToken(c *Context, sess *types.Session, user *types.User, p provider.SocialProvider, body linkSocialBody) *apierror.Error {
	linker, ok := p.(provider.IDTokenLinker)
	if !ok {
		return apierror.New(http.StatusNotFound, apierror.CodeIDTokenNotSupported, constants.MsgIDTokenNotSupportedDetail)
	}
	nonce := ""
	if body.IDToken != nil {
		nonce = body.IDToken.Nonce
	}
	valid, err := linker.VerifyIDToken(c.R.Context(), body.IDToken.Token, nonce)
	if err != nil || !valid {
		return apierror.WithCode(http.StatusUnauthorized, apierror.CodeInvalidToken)
	}

	tokens := provider.OAuthTokens{}
	if body.IDToken != nil {
		tokens = provider.OAuthTokens{
			AccessToken:  body.IDToken.AccessToken,
			RefreshToken: body.IDToken.RefreshToken,
			IDToken:      body.IDToken.Token,
			Scopes:       body.IDToken.Scopes,
		}
	}
	info, err := p.GetUserInfo(c.R.Context(), tokens)
	if err != nil || info == nil {
		return apierror.WithCode(http.StatusUnauthorized, apierror.CodeFailedToGetUserInfo)
	}
	if info.User.Email == "" {
		return apierror.WithCode(http.StatusUnauthorized, apierror.CodeUserEmailNotFound)
	}

	providerAccountID := info.User.ID
	accounts, err := a.cfg.store.ListAccountsByUserID(c.R.Context(), sess.UserID)
	if err != nil {
		return apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError)
	}
	for _, acc := range accounts {
		if acc.ProviderID == p.ID() && acc.AccountID == providerAccountID {
			return nil
		}
	}

	if !a.linkingAllowed(p.ID(), info.User.EmailVerified) {
		return apierror.New(http.StatusUnauthorized, apierror.CodeLinkingNotAllowed, constants.MsgLinkingNotAllowedDetail)
	}
	if strings.ToLower(info.User.Email) != strings.ToLower(user.Email) && !a.cfg.account.allowDifferentEmails {
		return apierror.New(http.StatusUnauthorized, apierror.CodeLinkingDifferentEmails, constants.MsgLinkingDifferentEmailsDetail)
	}

	if err := a.createLinkedAccount(c, sess.UserID, p, providerAccountID, tokens, body.IDToken.Token); err != nil {
		return apierror.New(http.StatusExpectationFailed, apierror.CodeLinkingFailed, constants.MsgLinkingFailedDetail)
	}
	a.applyUserInfoOnLink(c, sess.UserID, info.User)
	return nil
}
