package plugins

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/store"
)

// EmailOTPOptions configures email OTP flows.
type EmailOTPOptions struct {
	SendOTP   func(ctx context.Context, email, otp, typ string) error
	ExpiresIn time.Duration
	OTPLength int
}

func (o EmailOTPOptions) length() int {
	if o.OTPLength == 0 {
		return 6
	}
	return o.OTPLength
}

func (o EmailOTPOptions) expires() time.Duration {
	if o.ExpiresIn == 0 {
		return 5 * time.Minute
	}
	return o.ExpiresIn
}

// EmailOTP adds email one-time password authentication.
func EmailOTP(opts EmailOTPOptions) auth.Plugin {
	return basePlugin{
		id: constants.PluginEmailOTP,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/email-otp/send-verification-otp", sendOTPHandler(opts, constants.EmailOTPTypeVerification)),
			rt(http.MethodPost, "/email-otp/check-verification-otp", checkOTPHandler(opts, constants.EmailOTPTypeVerification)),
			rt(http.MethodPost, "/email-otp/verify-email", verifyEmailOTPHandler(opts)),
			rt(http.MethodPost, "/sign-in/email-otp", signInEmailOTPHandler(opts)),
			rt(http.MethodPost, "/email-otp/request-password-reset", sendOTPHandler(opts, constants.EmailOTPTypeForgetPassword)),
			rt(http.MethodPost, "/forget-password/email-otp", sendOTPHandler(opts, constants.EmailOTPTypeForgetPassword)),
			rt(http.MethodPost, "/email-otp/reset-password", resetPasswordOTPHandler(opts)),
			rt(http.MethodPost, "/email-otp/request-email-change", sendOTPHandler(opts, constants.EmailOTPTypeEmailChange)),
			rt(http.MethodPost, "/email-otp/change-email", changeEmailOTPHandler(opts)),
		},
	}
}

func otpIdentifier(typ, email string) string {
	return fmt.Sprintf("%s%s:%s", constants.VerificationEmailOTP, typ, auth.NormalizeEmail(email))
}

func sendOTPHandler(opts EmailOTPOptions, typ string) func(*auth.Context) {
	return func(c *auth.Context) {
		if opts.SendOTP == nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeEmailOTPDisabled))
			return
		}
		var body struct {
			Email string `json:"email"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Email == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidEmail))
			return
		}
		raw, _ := id.Generate(opts.length())
		otp := raw[:opts.length()]
		_ = c.Auth.CreateVerification(c.R.Context(), otpIdentifier(typ, body.Email), otp, opts.expires())
		_ = opts.SendOTP(c.R.Context(), body.Email, otp, typ)
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func checkOTPHandler(opts EmailOTPOptions, typ string) func(*auth.Context) {
	return func(c *auth.Context) {
		var body struct {
			Email string `json:"email"`
			OTP   string `json:"otp"`
			Type  string `json:"type"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		otpType := typ
		if body.Type != "" {
			if !validEmailOTPCheckType(body.Type) {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
				return
			}
			otpType = body.Type
		}
		ok := verifyStoredOTP(c, otpType, body.Email, body.OTP, false)
		c.WriteJSON(http.StatusOK, map[string]bool{"success": ok})
	}
}

func validEmailOTPCheckType(typ string) bool {
	switch typ {
	case constants.EmailOTPTypeVerification, constants.EmailOTPTypeForgetPassword, constants.EmailOTPTypeEmailChange:
		return true
	}
	return false
}

func verifyStoredOTP(c *auth.Context, typ, email, otp string, consume bool) bool {
	identifier := otpIdentifier(typ, email)
	v, err := c.Auth.Store().FindVerificationByIdentifier(c.R.Context(), identifier)
	if err != nil || time.Now().After(v.ExpiresAt) || v.Value != otp {
		return false
	}
	if consume {
		_ = c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), identifier)
	}
	return true
}

func verifyEmailOTPHandler(_ EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		var body struct {
			Email string `json:"email"`
			OTP   string `json:"otp"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		if !verifyStoredOTP(c, constants.EmailOTPTypeVerification, body.Email, body.OTP, true) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		user, err := c.Auth.Store().FindUserByEmail(c.R.Context(), auth.NormalizeEmail(body.Email))
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeUserNotFound))
			return
		}
		verified := true
		user, _ = c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{EmailVerified: &verified})
		c.WriteJSON(http.StatusOK, map[string]any{"user": user})
	}
}

func signInEmailOTPHandler(_ EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		var body struct {
			Email      string `json:"email"`
			OTP        string `json:"otp"`
			RememberMe *bool  `json:"rememberMe"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		if !verifyStoredOTP(c, constants.EmailOTPTypeVerification, body.Email, body.OTP, true) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		user, err := c.Auth.Store().FindUserByEmail(c.R.Context(), auth.NormalizeEmail(body.Email))
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeUserNotFound))
			return
		}
		remember := true
		if body.RememberMe != nil {
			remember = *body.RememberMe
		}
		sess, err := c.Auth.NewSession(c, user.ID, remember)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeFailedToCreateSession))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]any{"token": sess.Token, "user": user})
	}
}

func resetPasswordOTPHandler(_ EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		var body struct {
			Email       string `json:"email"`
			OTP         string `json:"otp"`
			NewPassword string `json:"newPassword"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		if !verifyStoredOTP(c, constants.EmailOTPTypeForgetPassword, body.Email, body.OTP, true) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		user, err := c.Auth.Store().FindUserByEmail(c.R.Context(), auth.NormalizeEmail(body.Email))
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeUserNotFound))
			return
		}
		if err := c.Auth.ValidatePasswords(body.NewPassword); err != nil {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidPassword, err.Error()))
			return
		}
		hash, err := c.Auth.HashPassword(body.NewPassword)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		_ = c.Auth.Store().UpdateAccountPassword(c.R.Context(), user.ID, constants.ProviderCredential, hash)
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func changeEmailOTPHandler(_ EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		_, user, ok := c.RequireSession()
		if !ok {
			return
		}
		var body struct {
			Email string `json:"email"`
			OTP   string `json:"otp"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		if !verifyStoredOTP(c, constants.EmailOTPTypeEmailChange, body.Email, body.OTP, true) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		email := auth.NormalizeEmail(body.Email)
		user, _ = c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{Email: &email})
		c.WriteJSON(http.StatusOK, map[string]any{"user": user})
	}
}
