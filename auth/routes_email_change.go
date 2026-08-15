package auth

import (
	"net/http"
	"net/url"

	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

func handleVerifyEmailChange(c *Context, payload map[string]any, callbackURL string) bool {
	updateTo, _ := payload["updateTo"].(string)
	if updateTo == "" {
		return false
	}
	requestType, _ := payload["requestType"].(string)

	email, err := jwtEmailFromPayload(payload)
	if err != nil {
		redirectVerifyError(c, callbackURL, apierror.CodeInvalidToken)
		return true
	}

	user, err := c.Auth.cfg.store.FindUserByEmail(c.R.Context(), email)
	if err != nil {
		redirectVerifyError(c, callbackURL, apierror.CodeUserNotFound)
		return true
	}

	sess, sessionUser, _ := c.GetSession()
	if sess != nil && sessionUser != nil && sessionUser.Email != email {
		redirectVerifyError(c, callbackURL, apierror.CodeInvalidUser)
		return true
	}

	switch requestType {
	case "change-email-confirmation":
		newToken, err := createEmailVerificationToken(c, email, map[string]any{
			"updateTo": updateTo, "requestType": "change-email-verification",
		})
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return true
		}
		cb := callbackURL
		if cb == "" {
			cb = "/"
		}
		verifyURL := c.Auth.cfg.baseURL + c.Auth.cfg.basePath + "/verify-email?token=" + url.QueryEscape(newToken) + "&callbackURL=" + url.QueryEscape(cb)
		if c.Auth.cfg.emailVerification.sendVerificationEmail != nil {
			target := types.CloneUser(user)
			target.Email = updateTo
			if err := c.Auth.cfg.emailVerification.sendVerificationEmail(c.R.Context(), types.VerificationEmailData{
				User: target, URL: verifyURL, Token: newToken,
			}); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
				return true
			}
		}
		if callbackURL != "" {
			c.Redirect(callbackURL)
			return true
		}
		c.WriteJSON(http.StatusOK, types.StatusResponse{Status: true})
		return true

	case "change-email-verification":
		if sess == nil {
			sess, err = c.Auth.createSession(c, user.ID, true)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeFailedToCreateSession))
				return true
			}
		}
		verified := true
		newEmail := updateTo
		updated, err := c.Auth.cfg.store.UpdateUser(c.R.Context(), user.ID, store.UserUpdate{
			Email: &newEmail, EmailVerified: &verified,
		})
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return true
		}
		c.Auth.syncUserSession(c, sess, updated)
		if callbackURL != "" {
			c.Redirect(callbackURL)
			return true
		}
		responseUser := toUserResponse(updated)
		c.WriteJSON(http.StatusOK, types.VerifyEmailResponse{Status: true, User: &responseUser})
		return true

	default:
		if sess == nil {
			sess, err = c.Auth.createSession(c, user.ID, true)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeFailedToCreateSession))
				return true
			}
		}
		newEmail := updateTo
		verified := false
		updated, err := c.Auth.cfg.store.UpdateUser(c.R.Context(), user.ID, store.UserUpdate{
			Email: &newEmail, EmailVerified: &verified,
		})
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return true
		}
		if c.Auth.cfg.emailVerification.sendVerificationEmail != nil {
			if err := sendVerificationEmailToUser(c, updated, callbackURL); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
				return true
			}
		}
		c.Auth.syncUserSession(c, sess, updated)
		if callbackURL != "" {
			c.Redirect(callbackURL)
			return true
		}
		responseUser := toUserResponse(updated)
		c.WriteJSON(http.StatusOK, types.VerifyEmailResponse{Status: true, User: &responseUser})
		return true
	}
}

func jwtEmailFromPayload(payload map[string]any) (string, error) {
	email, ok := payload["email"].(string)
	if !ok || email == "" {
		return "", berrors.ErrMissingEmailClaim
	}
	return email, nil
}
