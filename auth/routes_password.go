package auth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/types"
)

type requestPasswordResetBody struct {
	Email      string `json:"email"`
	RedirectTo string `json:"redirectTo"`
}

func handleRequestPasswordReset(c *Context) {
	if c.Auth.cfg.emailPassword.sendResetPassword == nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeResetPasswordDisabled))
		return
	}

	var body requestPasswordResetBody
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidEmail, constants.MsgInvalidRequestBody))
		return
	}

	msg := constants.MsgResetPasswordIfExists
	email := strings.ToLower(strings.TrimSpace(body.Email))
	user, err := c.Auth.cfg.store.FindUserByEmail(c.R.Context(), email)
	if err != nil {
		_, _ = id.Generate(24)
		_, _ = c.Auth.cfg.store.FindVerificationByIdentifier(c.R.Context(), "dummy")
		c.WriteJSON(http.StatusOK, types.MessageStatusResponse{Status: true, Message: msg})
		return
	}

	token, err := id.Generate(24)
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
	identifier := constants.VerificationResetPassword + token
	if err := c.Auth.cfg.store.CreateVerification(c.R.Context(), &types.Verification{
		ID: vID, Identifier: identifier, Value: user.ID,
		ExpiresAt: now.Add(c.Auth.cfg.emailPassword.resetPasswordTokenExpires),
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}

	callback := ""
	if body.RedirectTo != "" {
		callback = url.QueryEscape(body.RedirectTo)
	}
	resetURL := c.Auth.cfg.baseURL + c.Auth.cfg.basePath + "/reset-password/" + token + "?callbackURL=" + callback
	if err := c.Auth.cfg.emailPassword.sendResetPassword(c.R.Context(), types.ResetPasswordEmailData{
		User: *user, URL: resetURL, Token: token,
	}); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}

	c.WriteJSON(http.StatusOK, types.MessageStatusResponse{Status: true, Message: msg})
}

func handleResetPasswordCallback(c *Context) {
	token := c.Vars["token"]
	callbackURL := c.R.URL.Query().Get("callbackURL")
	if token == "" || callbackURL == "" {
		c.Redirect(appendQuery(c.Auth.cfg.baseURL+c.Auth.cfg.basePath+"/error", "error", "INVALID_TOKEN"))
		return
	}
	identifier := constants.VerificationResetPassword + token

	v, err := c.Auth.cfg.store.FindVerificationByIdentifier(c.R.Context(), identifier)
	if err != nil || time.Now().After(v.ExpiresAt) {
		c.Redirect(appendQuery(callbackURL, "error", "INVALID_TOKEN"))
		return
	}

	c.Redirect(appendQuery(callbackURL, "token", token))
}

type resetPasswordBody struct {
	NewPassword string `json:"newPassword"`
	Token       string `json:"token"`
}

func handleResetPassword(c *Context) {
	var body resetPasswordBody
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidToken, constants.MsgInvalidRequestBody))
		return
	}

	token := body.Token
	if token == "" {
		token = c.R.URL.Query().Get("token")
	}
	if token == "" {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeInvalidToken))
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

	identifier := constants.VerificationResetPassword + token
	v, err := c.Auth.cfg.store.FindVerificationByIdentifier(c.R.Context(), identifier)
	if err != nil || time.Now().After(v.ExpiresAt) {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeInvalidToken))
		return
	}
	if err := c.Auth.cfg.store.DeleteVerificationByIdentifier(c.R.Context(), identifier); err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeInvalidToken))
		return
	}

	hash, err := c.Auth.cfg.hasher.Hash(body.NewPassword)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}

	_, err = c.Auth.cfg.store.FindAccountByUserAndProvider(c.R.Context(), v.Value, constants.ProviderCredential)
	if err != nil {
		if !errors.Is(err, berrors.ErrNotFound) {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		now := time.Now()
		accID, err := id.Generate(32)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
		if err := c.Auth.cfg.store.CreateAccount(c.R.Context(), &types.Account{
			ID: accID, AccountID: v.Value, ProviderID: constants.ProviderCredential,
			UserID: v.Value, Password: hash, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
	} else {
		if err := c.Auth.cfg.store.UpdateAccountPassword(c.R.Context(), v.Value, constants.ProviderCredential, hash); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
	}

	if c.Auth.cfg.emailPassword.revokeSessionsOnPasswordReset {
		if err := c.Auth.cfg.store.DeleteAllSessionsByUserID(c.R.Context(), v.Value); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
	}

	c.WriteJSON(http.StatusOK, types.StatusResponse{Status: true})
}

type verifyPasswordBody struct {
	Password string `json:"password"`
}

func handleVerifyPassword(c *Context) {
	_, user, ok := c.requireSessionWithOpts(SessionOpts{DisableCookieCache: true})
	if !ok {
		return
	}

	var body verifyPasswordBody
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidPassword, constants.MsgInvalidRequestBody))
		return
	}

	account, err := c.Auth.cfg.store.FindAccountByUserAndProvider(c.R.Context(), user.ID, constants.ProviderCredential)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeInvalidPassword))
		return
	}

	valid, err := c.Auth.cfg.hasher.Verify(account.Password, body.Password)
	if err != nil || !valid {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeInvalidPassword))
		return
	}

	c.WriteJSON(http.StatusOK, types.VerifyPasswordResponse{Status: true})
}

func appendQuery(rawURL, key, value string) string { //nolint:unparam // shared helper
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL + "?" + key + "=" + url.QueryEscape(value)
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}
