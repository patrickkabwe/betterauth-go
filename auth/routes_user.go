package auth

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/cookie"
	"github.com/patrickkabwe/betterauth-go/internal/crypto"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

func handleUpdateUser(c *Context) {
	sess, user, ok := c.RequireSession()
	if !ok {
		return
	}

	var body map[string]json.RawMessage
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeBodyMustBeAnObject))
		return
	}
	if _, hasEmail := body["email"]; hasEmail {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeEmailCanNotBeUpdated))
		return
	}
	phoneAdditional, phoneErr := c.Auth.phoneNumberAdditionalFromRaw(body)
	if phoneErr != nil {
		c.WriteError(phoneErr)
		return
	}

	update, _, fieldErr := mergeUserUpdateFromBody(body, c.Auth.cfg.user.additionalFields)
	if fieldErr != nil {
		c.WriteError(fieldErr)
		return
	}
	update.Additional = mergeAdditionalUpdate(update.Additional, phoneAdditional)
	update.Additional, fieldErr = runUserAdditionalProcessors(c, "update", user.ID, update.Additional)
	if fieldErr != nil {
		c.WriteError(fieldErr)
		return
	}
	if update.Name == nil && update.Image == nil && len(update.Additional) == 0 {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeBodyMustBeAnObject, constants.MsgNoFieldsToUpdate))
		return
	}

	updated, err := c.Auth.cfg.store.UpdateUser(c.R.Context(), user.ID, update)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	c.Auth.syncUserSession(c, sess, updated)
	c.WriteJSON(http.StatusOK, types.UpdateUserResponse{Status: true})
}

func (a *Auth) phoneNumberAdditionalFromRaw(raw map[string]json.RawMessage) (map[string]any, *apierror.Error) {
	if !a.phoneNumberPluginEnabled() {
		return nil, nil
	}
	value, ok := raw[constants.FieldPhoneNumber]
	if !ok {
		return nil, nil
	}
	if string(value) != "null" {
		return nil, apierror.New(http.StatusBadRequest, "PHONE_NUMBER_CANNOT_BE_UPDATED", "Phone number cannot be updated")
	}
	return map[string]any{
		constants.FieldPhoneNumber:   nil,
		constants.FieldPhoneVerified: false,
	}, nil
}

func (a *Auth) phoneNumberPluginEnabled() bool {
	for _, plugin := range a.cfg.plugins {
		if plugin.ID() == constants.PluginPhoneNumber {
			return true
		}
	}
	return false
}

func mergeAdditionalUpdate(base map[string]any, extra map[string]any) map[string]any {
	if len(extra) == 0 {
		return base
	}
	out := make(map[string]any, len(base)+len(extra))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range extra {
		out[key] = value
	}
	return out
}

type changePasswordBody struct {
	CurrentPassword     string `json:"currentPassword"`
	NewPassword         string `json:"newPassword"`
	RevokeOtherSessions *bool  `json:"revokeOtherSessions"`
}

func handleChangePassword(c *Context) {
	sess, user, ok := c.requireSessionWithOpts(SessionOpts{DisableCookieCache: true})
	if !ok {
		return
	}

	var body changePasswordBody
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidPassword, constants.MsgInvalidRequestBody))
		return
	}
	if len(body.NewPassword) < c.Auth.cfg.minPassword {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodePasswordTooShort))
		return
	}
	if len(body.NewPassword) > c.Auth.cfg.maxPassword {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodePasswordTooLong))
		return
	}
	if err := c.Auth.ValidatePasswords(body.NewPassword); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidPassword, err.Error()))
		return
	}

	account, err := c.Auth.cfg.store.FindAccountByUserAndProvider(c.R.Context(), user.ID, constants.ProviderCredential)
	if err != nil || account.Password == "" {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeCredentialAccountNotFound))
		return
	}
	valid, err := c.Auth.cfg.hasher.Verify(account.Password, body.CurrentPassword)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	if !valid {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeInvalidPassword))
		return
	}

	hash, err := c.Auth.cfg.hasher.Hash(body.NewPassword)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	if err := c.Auth.cfg.store.UpdateAccountPassword(c.R.Context(), user.ID, constants.ProviderCredential, hash); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}

	var newToken *string
	if body.RevokeOtherSessions != nil && *body.RevokeOtherSessions {
		if err := c.Auth.cfg.store.DeleteAllSessionsByUserID(c.R.Context(), user.ID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		newSess, err := c.Auth.createSession(c, user.ID, !cookie.IsDontRememberAny(c.R, c.Auth.cfg.cookie, c.Auth.cfg.secrets))
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeFailedToCreateSession))
			return
		}
		newToken = &newSess.Token
		_ = sess
	} else {
		c.Auth.syncUserSession(c, sess, user)
	}

	c.WriteJSON(http.StatusOK, types.ChangePasswordResponse{
		Token: newToken,
		User:  toUserResponse(user),
	})
}

type changeEmailBody struct {
	NewEmail    string `json:"newEmail"`
	CallbackURL string `json:"callbackURL"`
}

func handleChangeEmail(c *Context) {
	_, user, ok := c.requireSessionWithOpts(SessionOpts{DisableCookieCache: true})
	if !ok {
		return
	}
	if !c.Auth.cfg.user.changeEmailEnabled {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeChangeEmailDisabled))
		return
	}

	var body changeEmailBody
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidEmail, constants.MsgInvalidRequestBody))
		return
	}

	newEmail := strings.ToLower(strings.TrimSpace(body.NewEmail))
	if !crypto.ValidateEmail(newEmail) {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeInvalidEmail))
		return
	}
	if newEmail == user.Email {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeEmailIsTheSame))
		return
	}

	canUpdateWithoutVerification := !user.EmailVerified && c.Auth.cfg.user.updateEmailWithoutVerify
	canSendVerification := c.Auth.cfg.emailVerification.sendVerificationEmail != nil
	canSendConfirmation := canSendVerification && user.EmailVerified && c.Auth.cfg.user.sendChangeEmailConfirmation != nil
	if !canUpdateWithoutVerification && !canSendConfirmation && !canSendVerification {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeVerificationEmailNotEnabled))
		return
	}

	callback := body.CallbackURL
	if callback == "" {
		callback = "/"
	}

	if _, err := c.Auth.cfg.store.FindUserByEmail(c.R.Context(), newEmail); err == nil {
		_, _ = createEmailVerificationToken(c, user.Email, map[string]any{"updateTo": newEmail})
		c.WriteJSON(http.StatusOK, types.StatusResponse{Status: true})
		return
	}

	if canUpdateWithoutVerification {
		updated, err := c.Auth.cfg.store.UpdateUser(c.R.Context(), user.ID, store.UserUpdate{Email: &newEmail})
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		if canSendVerification {
			if err := sendVerificationEmailToUser(c, updated, callback); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
				return
			}
		}
		c.WriteJSON(http.StatusOK, types.StatusResponse{Status: true})
		return
	}

	requestType := "change-email-verification"
	sendFn := c.Auth.cfg.emailVerification.sendVerificationEmail
	if canSendConfirmation {
		requestType = "change-email-confirmation"
		sendFn = func(ctx context.Context, data types.VerificationEmailData) error {
			return c.Auth.cfg.user.sendChangeEmailConfirmation(ctx, types.ChangeEmailData{
				User: data.User, NewEmail: newEmail, URL: data.URL, Token: data.Token,
			})
		}
	}

	token, err := createEmailVerificationToken(c, user.Email, map[string]any{
		"updateTo": newEmail, "requestType": requestType,
	})
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	verifyURL := c.Auth.cfg.baseURL + c.Auth.cfg.basePath + "/verify-email?token=" + url.QueryEscape(token) + "&callbackURL=" + url.QueryEscape(callback)
	targetUser := types.CloneUser(user)
	targetUser.Email = newEmail
	if err := sendFn(c.R.Context(), types.VerificationEmailData{User: targetUser, URL: verifyURL, Token: token}); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	c.WriteJSON(http.StatusOK, types.StatusResponse{Status: true})
}

type setPasswordBody struct {
	NewPassword string `json:"newPassword"`
}

func handleSetPassword(c *Context) {
	_, user, ok := c.requireSessionWithOpts(SessionOpts{DisableCookieCache: true})
	if !ok {
		return
	}

	var body setPasswordBody
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidPassword, constants.MsgInvalidRequestBody))
		return
	}
	if len(body.NewPassword) < c.Auth.cfg.minPassword {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodePasswordTooShort))
		return
	}
	if len(body.NewPassword) > c.Auth.cfg.maxPassword {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodePasswordTooLong))
		return
	}

	account, err := c.Auth.cfg.store.FindAccountByUserAndProvider(c.R.Context(), user.ID, constants.ProviderCredential)
	if err == nil && account.Password != "" {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodePasswordAlreadySet))
		return
	}

	hash, err := c.Auth.cfg.hasher.Hash(body.NewPassword)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	now := time.Now()
	if err == nil && account != nil {
		if err := c.Auth.cfg.store.UpdateAccountPassword(c.R.Context(), user.ID, constants.ProviderCredential, hash); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
	} else {
		accID, err := id.Generate(32)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		if err := c.Auth.cfg.store.CreateAccount(c.R.Context(), &types.Account{
			ID: accID, AccountID: user.ID, ProviderID: constants.ProviderCredential,
			UserID: user.ID, Password: hash, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
	}
	c.WriteJSON(http.StatusOK, types.StatusResponse{Status: true})
}

var errInvalidDeleteToken = errors.New("invalid delete token")

type deleteUserBody struct {
	Password    string `json:"password"`
	Token       string `json:"token"`
	CallbackURL string `json:"callbackURL"`
}

func handleDeleteUser(c *Context) {
	sess, user, ok := c.requireSessionWithOpts(SessionOpts{DisableCookieCache: true})
	if !ok {
		return
	}
	if !c.Auth.cfg.user.deleteUserEnabled {
		c.WriteError(apierror.WithCode(http.StatusNotFound, apierror.CodeDeleteUserDisabled))
		return
	}

	var body deleteUserBody
	_ = c.ParseJSON(&body)

	switch {
	case body.Password != "":
		account, err := c.Auth.cfg.store.FindAccountByUserAndProvider(c.R.Context(), user.ID, constants.ProviderCredential)
		if err != nil || account.Password == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeCredentialAccountNotFound))
			return
		}
		valid, err := c.Auth.cfg.hasher.Verify(account.Password, body.Password)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		if !valid {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeInvalidPassword))
			return
		}
	case body.Token != "":
		if err := c.Auth.completeDeleteWithToken(c, body.Token, user.ID); err != nil {
			writeDeleteTokenError(c, err)
			return
		}
		cookieDelete(c)
		c.WriteJSON(http.StatusOK, types.DeleteUserResponse{Success: true, Message: "User deleted"})
		return
	case c.Auth.cfg.user.sendDeleteAccount != nil:
		token, err := id.Generate(32)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		now := time.Now()
		vID, err := id.Generate(32)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		identifier := "delete-account:" + token
		if err := c.Auth.cfg.store.CreateVerification(c.R.Context(), &types.Verification{
			ID: vID, Identifier: identifier, Value: user.ID,
			ExpiresAt: now.Add(c.Auth.cfg.user.deleteTokenExpires),
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		callback := body.CallbackURL
		if callback == "" {
			callback = "/"
		}
		deleteURL := c.Auth.cfg.baseURL + c.Auth.cfg.basePath + "/delete-user/callback?token=" + url.QueryEscape(token) + "&callbackURL=" + url.QueryEscape(callback)
		if err := c.Auth.cfg.user.sendDeleteAccount(c.R.Context(), *user, deleteURL, token); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, types.DeleteUserResponse{Success: true, Message: "Verification email sent"})
		return
	default:
		if !c.Auth.isSessionFresh(sess) {
			c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeSessionExpired, constants.MsgTokenExpired))
			return
		}
	}

	if err := c.Auth.runBeforeDelete(c, user); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	if err := c.Auth.cfg.store.DeleteUser(c.R.Context(), user.ID); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	if err := c.Auth.cfg.store.DeleteAllSessionsByUserID(c.R.Context(), user.ID); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	cookieDelete(c)
	if err := c.Auth.runAfterDelete(c, user); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	c.WriteJSON(http.StatusOK, types.DeleteUserResponse{Success: true, Message: "User deleted"})
}

func handleDeleteUserCallback(c *Context) {
	if !c.Auth.cfg.user.deleteUserEnabled {
		c.WriteError(apierror.WithCode(http.StatusNotFound, apierror.CodeDeleteUserDisabled))
		return
	}

	token := c.R.URL.Query().Get("token")
	callbackURL := c.R.URL.Query().Get("callbackURL")
	identifier := "delete-account:" + token

	v, err := c.Auth.cfg.store.FindVerificationByIdentifier(c.R.Context(), identifier)
	if err != nil || time.Now().After(v.ExpiresAt) {
		if callbackURL != "" {
			c.Redirect(appendQuery(callbackURL, "error", apierror.CodeInvalidToken))
			return
		}
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeInvalidToken))
		return
	}

	sess, sessionUser, ok := c.requireSessionWithOpts(SessionOpts{DisableCookieCache: true})
	if !ok {
		return
	}
	if sessionUser.ID != v.Value {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeInvalidToken))
		return
	}
	_ = sess

	user, err := c.Auth.cfg.store.FindUserByID(c.R.Context(), v.Value)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeUserNotFound))
		return
	}

	if err := c.Auth.runBeforeDelete(c, user); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	if err := c.Auth.cfg.store.DeleteUser(c.R.Context(), user.ID); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	if err := c.Auth.cfg.store.DeleteAllSessionsByUserID(c.R.Context(), user.ID); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	if err := c.Auth.cfg.store.DeleteVerificationByIdentifier(c.R.Context(), identifier); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	cookieDelete(c)
	if err := c.Auth.runAfterDelete(c, user); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}

	if callbackURL != "" {
		c.Redirect(callbackURL)
		return
	}
	c.WriteJSON(http.StatusOK, types.DeleteUserResponse{Success: true, Message: "User deleted"})
}

func (a *Auth) completeDeleteWithToken(c *Context, token, userID string) error {
	identifier := "delete-account:" + token
	v, err := a.cfg.store.FindVerificationByIdentifier(c.R.Context(), identifier)
	if err != nil {
		if errors.Is(err, berrors.ErrNotFound) {
			return errInvalidDeleteToken
		}
		return err
	}
	if time.Now().After(v.ExpiresAt) || v.Value != userID {
		return errInvalidDeleteToken
	}
	user, err := a.cfg.store.FindUserByID(c.R.Context(), userID)
	if err != nil {
		return err
	}
	if err := a.runBeforeDelete(c, user); err != nil {
		return err
	}
	if err := a.cfg.store.DeleteUser(c.R.Context(), userID); err != nil {
		return err
	}
	if err := a.cfg.store.DeleteAllSessionsByUserID(c.R.Context(), userID); err != nil {
		return err
	}
	if err := a.cfg.store.DeleteVerificationByIdentifier(c.R.Context(), identifier); err != nil {
		return err
	}
	if err := a.runAfterDelete(c, user); err != nil {
		return err
	}
	return nil
}

func writeDeleteTokenError(c *Context, err error) {
	if errors.Is(err, errInvalidDeleteToken) {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeInvalidToken))
		return
	}
	c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
}

func (a *Auth) runBeforeDelete(c *Context, user *types.User) error {
	if a.cfg.user.beforeDelete == nil {
		return nil
	}
	return a.cfg.user.beforeDelete(c.R.Context(), *user)
}

func (a *Auth) runAfterDelete(c *Context, user *types.User) error {
	if a.cfg.user.afterDelete == nil {
		return nil
	}
	return a.cfg.user.afterDelete(c.R.Context(), *user)
}

func (a *Auth) syncUserSession(c *Context, sess *types.Session, user *types.User) {
	a.setSessionCache(c, sess, user)
}
