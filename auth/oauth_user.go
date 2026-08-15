package auth

import (
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

type oauthAccountInput struct {
	ProviderID            string
	AccountID             string
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	IDToken               string
	Scope                 string
}

type oauthUserResult struct {
	User       *types.User
	Session    *types.Session
	IsRegister bool
	Error      string
}

func (a *Auth) handleOAuthUserInfo(c *Context, userInfo provider.OAuthUser, account oauthAccountInput, disableSignUp bool) (*oauthUserResult, error) {
	email := strings.ToLower(strings.TrimSpace(userInfo.Email))
	if email == "" {
		return &oauthUserResult{Error: "email not found"}, nil
	}

	existing, err := a.cfg.store.FindUserByEmail(c.R.Context(), email)
	isRegister := err != nil

	if !isRegister {
		return a.linkOAuthToExistingUser(c, existing, userInfo, account)
	}

	if disableSignUp {
		return &oauthUserResult{Error: "signup disabled"}, nil
	}
	return a.createOAuthUser(c, userInfo, account, email)
}

func (a *Auth) socialSignUpDisabled(p provider.SocialProvider, requestSignUp bool) bool {
	policy, ok := p.(provider.SignUpPolicyProvider)
	if !ok {
		return false
	}
	if policy.DisableSignUp() {
		return true
	}
	return policy.DisableImplicitSignUp() && !requestSignUp
}

func (a *Auth) linkOAuthToExistingUser(c *Context, user *types.User, userInfo provider.OAuthUser, account oauthAccountInput) (*oauthUserResult, error) {
	accounts, err := a.cfg.store.ListAccountsByUserID(c.R.Context(), user.ID)
	if err != nil {
		return nil, err
	}

	var linked *types.Account
	for i := range accounts {
		if accounts[i].ProviderID == account.ProviderID && accounts[i].AccountID == account.AccountID {
			linked = &accounts[i]
			break
		}
	}

	if linked == nil {
		if !a.canImplicitLink(account.ProviderID, user, userInfo) {
			return &oauthUserResult{Error: "account not linked"}, nil
		}
		if err := a.saveOAuthAccount(c, user.ID, account); err != nil {
			return &oauthUserResult{Error: "unable to link account"}, nil
		}
		a.applyUserInfoOnLink(c, user.ID, userInfo)
	} else {
		_ = a.updateOAuthAccountTokens(c, linked.ID, account)
	}

	if userInfo.EmailVerified && !user.EmailVerified && strings.EqualFold(userInfo.Email, user.Email) {
		verified := true
		user, _ = a.cfg.store.UpdateUser(c.R.Context(), user.ID, store.UserUpdate{EmailVerified: &verified})
	}

	sess, err := a.createSession(c, user.ID, true)
	if err != nil {
		return &oauthUserResult{Error: "unable to create session"}, nil
	}
	return &oauthUserResult{User: user, Session: sess, IsRegister: false}, nil
}

func (a *Auth) canImplicitLink(providerID string, user *types.User, userInfo provider.OAuthUser) bool {
	if !a.cfg.account.linkingEnabled {
		return false
	}
	if a.cfg.account.trustedProviders[providerID] {
		return true
	}
	if !userInfo.EmailVerified {
		return false
	}
	if !user.EmailVerified {
		return false
	}
	return true
}

func (a *Auth) createOAuthUser(c *Context, userInfo provider.OAuthUser, account oauthAccountInput, email string) (*oauthUserResult, error) {
	now := time.Now()
	userID, err := id.Generate(32)
	if err != nil {
		return nil, err
	}
	user := &types.User{
		ID: userID, Name: userInfo.Name, Email: email,
		EmailVerified: userInfo.EmailVerified, Image: userInfo.Image,
		CreatedAt: now, UpdatedAt: now,
		Additional: applyDefaultAdditionalFields(nil, a.cfg.user.additionalFields),
	}
	if err := a.cfg.store.CreateUser(c.R.Context(), user); err != nil {
		return &oauthUserResult{Error: "unable to create user"}, nil
	}
	if err := a.saveOAuthAccount(c, userID, account); err != nil {
		return &oauthUserResult{Error: "unable to create user"}, nil
	}
	sess, err := a.createSession(c, userID, true)
	if err != nil {
		return &oauthUserResult{Error: "unable to create session"}, nil
	}
	return &oauthUserResult{User: user, Session: sess, IsRegister: true}, nil
}

func (a *Auth) saveOAuthAccount(c *Context, userID string, account oauthAccountInput) error {
	now := time.Now()
	accID, err := id.Generate(32)
	if err != nil {
		return err
	}
	return a.cfg.store.CreateAccount(c.R.Context(), &types.Account{
		ID: accID, AccountID: account.AccountID, ProviderID: account.ProviderID, UserID: userID,
		AccessToken: account.AccessToken, RefreshToken: account.RefreshToken,
		AccessTokenExpiresAt: account.AccessTokenExpiresAt, RefreshTokenExpiresAt: account.RefreshTokenExpiresAt,
		IDToken: account.IDToken, Scope: account.Scope, CreatedAt: now, UpdatedAt: now,
	})
}

func (a *Auth) updateOAuthAccountTokens(c *Context, accountID string, account oauthAccountInput) error {
	update := store.AccountUpdate{
		AccessTokenExpiresAt: account.AccessTokenExpiresAt, RefreshTokenExpiresAt: account.RefreshTokenExpiresAt,
	}
	hasUpdate := account.AccessTokenExpiresAt != nil || account.RefreshTokenExpiresAt != nil
	if account.AccessToken != "" {
		update.AccessToken = &account.AccessToken
		hasUpdate = true
	}
	if account.RefreshToken != "" {
		update.RefreshToken = &account.RefreshToken
		hasUpdate = true
	}
	if account.IDToken != "" {
		update.IDToken = &account.IDToken
		hasUpdate = true
	}
	if account.Scope != "" {
		update.Scope = &account.Scope
		hasUpdate = true
	}
	if !hasUpdate {
		return nil
	}
	_, err := a.cfg.store.UpdateAccount(c.R.Context(), accountID, update)
	return err
}

func oauthAccountFromTokens(providerID, accountID string, tokens *provider.OAuthTokens) oauthAccountInput {
	scope := strings.Join(tokens.Scopes, ",")
	return oauthAccountInput{
		ProviderID: providerID, AccountID: accountID,
		AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken,
		AccessTokenExpiresAt: tokens.AccessTokenExpiresAt, RefreshTokenExpiresAt: tokens.RefreshTokenExpiresAt,
		IDToken: tokens.IDToken, Scope: scope,
	}
}
