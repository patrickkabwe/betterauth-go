package auth

import (
	constants "github.com/patrickkabwe/betterauth-go/constants"
	"net/http"
	"net/url"
	"strings"

	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/jwt"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

type sendVerificationEmailBody struct {
	Email       string `json:"email"`
	CallbackURL string `json:"callbackURL"`
}

func handleSendVerificationEmail(c *Context) {
	if c.Auth.cfg.emailVerification.sendVerificationEmail == nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, apierror.CodeVerificationEmailNotEnabled))
		return
	}

	var body sendVerificationEmailBody
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidEmail, constants.MsgInvalidRequestBody))
		return
	}

	email := strings.ToLower(strings.TrimSpace(body.Email))
	user, err := c.Auth.cfg.store.FindUserByEmail(c.R.Context(), email)
	if err != nil {
		c.WriteJSON(http.StatusOK, types.StatusResponse{Status: true})
		return
	}

	if err := sendVerificationEmailToUser(c, user, body.CallbackURL); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	c.WriteJSON(http.StatusOK, types.StatusResponse{Status: true})
}

func sendVerificationEmailToUser(c *Context, user *types.User, callbackURL string) error {
	token, err := createEmailVerificationToken(c, user.Email, nil)
	if err != nil {
		return err
	}
	if callbackURL == "" {
		callbackURL = "/"
	}
	verifyURL := c.Auth.cfg.baseURL + c.Auth.cfg.basePath + "/verify-email?token=" + url.QueryEscape(token) + "&callbackURL=" + url.QueryEscape(callbackURL)
	return c.Auth.cfg.emailVerification.sendVerificationEmail(c.R.Context(), types.VerificationEmailData{
		User:  *user,
		URL:   verifyURL,
		Token: token,
	})
}

func createEmailVerificationToken(c *Context, email string, extra map[string]any) (string, error) {
	claims := map[string]any{"email": strings.ToLower(email)}
	for k, v := range extra {
		claims[k] = v
	}
	return jwt.SignHS256(c.Auth.cfg.secret, claims, c.Auth.cfg.emailVerification.expiresIn)
}

func handleVerifyEmail(c *Context) {
	token := c.R.URL.Query().Get("token")
	callbackURL := c.R.URL.Query().Get("callbackURL")

	payload, err := jwt.VerifyHS256Any(token, c.Auth.cfg.secrets)
	if err != nil {
		redirectVerifyError(c, callbackURL, verifyErrorCode(err))
		return
	}

	if handleVerifyEmailChange(c, payload, callbackURL) {
		return
	}

	email, err := jwt.EmailClaim(payload)
	if err != nil {
		redirectVerifyError(c, callbackURL, apierror.CodeInvalidToken)
		return
	}

	user, err := c.Auth.cfg.store.FindUserByEmail(c.R.Context(), email)
	if err != nil {
		redirectVerifyError(c, callbackURL, apierror.CodeUserNotFound)
		return
	}

	verified := true
	updated, err := c.Auth.cfg.store.UpdateUser(c.R.Context(), user.ID, store.UserUpdate{EmailVerified: &verified})
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}

	if callbackURL != "" {
		c.Redirect(callbackURL)
		return
	}

	c.WriteJSON(http.StatusOK, types.VerifyEmailResponse{Status: true, User: toUserResponse(updated)})
}

func verifyErrorCode(err error) string {
	if err == jwt.ErrExpired {
		return apierror.CodeTokenExpired
	}
	return apierror.CodeInvalidToken
}

func redirectVerifyError(c *Context, callbackURL, code string) {
	if callbackURL != "" {
		sep := "?"
		if strings.Contains(callbackURL, "?") {
			sep = "&"
		}
		c.Redirect(callbackURL + sep + "error=" + code)
		return
	}
	c.WriteError(apierror.New(http.StatusUnauthorized, code, code))
}
