package plugins

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

// EmailOTPOptions configures email OTP flows.
type EmailOTPOptions struct {
	SendOTP         func(ctx context.Context, email, otp, typ string) error
	ExpiresIn       time.Duration
	OTPLength       int
	DisableSignUp   bool
	AllowedAttempts int
}

const (
	codeEmailOTPExpired         = "OTP_EXPIRED"
	codeEmailOTPTooManyAttempts = "TOO_MANY_ATTEMPTS"
)

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

func (o EmailOTPOptions) allowedAttempts() int {
	if o.AllowedAttempts == 0 {
		return 3
	}
	return o.AllowedAttempts
}

// EmailOTP adds email one-time password authentication.
func EmailOTP(opts EmailOTPOptions) auth.Plugin {
	return basePlugin{
		id: constants.PluginEmailOTP,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/email-otp/send-verification-otp", sendVerificationOTPHandler(opts)),
			rt(http.MethodPost, "/email-otp/check-verification-otp", checkOTPHandler(opts, constants.EmailOTPTypeVerification)),
			rt(http.MethodPost, "/email-otp/verify-email", verifyEmailOTPHandler(opts)),
			rt(http.MethodPost, "/sign-in/email-otp", signInEmailOTPHandler(opts)),
			rt(http.MethodPost, "/email-otp/request-password-reset", requestPasswordResetEmailOTPHandler(opts)),
			rt(http.MethodPost, "/forget-password/email-otp", requestPasswordResetEmailOTPHandler(opts)),
			rt(http.MethodPost, "/email-otp/reset-password", resetPasswordOTPHandler(opts)),
			rt(http.MethodPost, "/email-otp/request-email-change", sendOTPHandler(opts, constants.EmailOTPTypeEmailChange)),
			rt(http.MethodPost, "/email-otp/change-email", changeEmailOTPHandler(opts)),
		},
	}
}

func sendVerificationOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		var body struct {
			Email string `json:"email"`
			Type  string `json:"type"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Email == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidEmail))
			return
		}
		if body.Type == constants.EmailOTPTypeEmailChange {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		if !validEmailOTPType(body.Type) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		sendOTP(c, opts, auth.NormalizeEmail(body.Email), body.Type)
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
		sendOTP(c, opts, auth.NormalizeEmail(body.Email), typ)
	}
}

func sendOTP(c *auth.Context, opts EmailOTPOptions, email, typ string) {
	if opts.SendOTP == nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeEmailOTPDisabled))
		return
	}
	raw, _ := id.Generate(opts.length())
	otp := raw[:opts.length()]
	_ = c.Auth.CreateVerification(c.R.Context(), otpIdentifier(typ, email), otp+":0", opts.expires())
	_ = opts.SendOTP(c.R.Context(), email, otp, typ)
	c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
}

func requestPasswordResetEmailOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		var body struct {
			Email string `json:"email"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Email == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidEmail))
			return
		}
		email := auth.NormalizeEmail(body.Email)
		_, err := c.Auth.Store().FindUserByEmail(c.R.Context(), email)
		if errors.Is(err, berrors.ErrNotFound) {
			err = c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), otpIdentifier(constants.EmailOTPTypeForgetPassword, email))
			if err != nil && !errors.Is(err, berrors.ErrNotFound) {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
			c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			return
		}
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		sendOTP(c, opts, email, constants.EmailOTPTypeForgetPassword)
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
		if !verifyStoredOTP(c, opts, otpType, body.Email, body.OTP, false) {
			return
		}
		if _, err := c.Auth.Store().FindUserByEmail(c.R.Context(), auth.NormalizeEmail(body.Email)); err != nil {
			if errors.Is(err, berrors.ErrNotFound) {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeUserNotFound))
				return
			}
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func validEmailOTPCheckType(typ string) bool {
	return validEmailOTPType(typ)
}

func validEmailOTPType(typ string) bool {
	switch typ {
	case constants.EmailOTPTypeVerification, constants.EmailOTPTypeSignIn, constants.EmailOTPTypeForgetPassword, constants.EmailOTPTypeEmailChange:
		return true
	}
	return false
}

func verifyStoredOTP(c *auth.Context, opts EmailOTPOptions, typ, email, otp string, consume bool) bool {
	identifier := otpIdentifier(typ, email)
	if consume {
		return consumeStoredEmailOTP(c, opts, identifier, otp)
	}
	v, err := c.Auth.Store().FindVerificationByIdentifier(c.R.Context(), identifier)
	if errors.Is(err, berrors.ErrNotFound) {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
		return false
	}
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	if time.Now().After(v.ExpiresAt) {
		_ = c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), identifier)
		c.WriteError(apierror.New(http.StatusBadRequest, codeEmailOTPExpired, "OTP expired"))
		return false
	}
	storedOTP, attempts := splitEmailOTPValue(v.Value)
	if attempts >= opts.allowedAttempts() {
		_ = c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), identifier)
		c.WriteError(apierror.New(http.StatusForbidden, codeEmailOTPTooManyAttempts, "Too many attempts"))
		return false
	}
	if storedOTP != otp {
		if !saveEmailOTPAttempts(c, v, attempts+1) {
			return false
		}
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
		return false
	}
	return true
}

func consumeStoredEmailOTP(c *auth.Context, opts EmailOTPOptions, identifier string, otp string) bool {
	existing, err := c.Auth.Store().FindVerificationByIdentifier(c.R.Context(), identifier)
	if err == nil && time.Now().After(existing.ExpiresAt) {
		_ = c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), identifier)
		c.WriteError(apierror.New(http.StatusBadRequest, codeEmailOTPExpired, "OTP expired"))
		return false
	}
	if err != nil && !errors.Is(err, berrors.ErrNotFound) {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	v, err := c.Auth.ConsumeVerification(c.R.Context(), identifier)
	if errors.Is(err, berrors.ErrNotFound) {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
		return false
	}
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	storedOTP, attempts := splitEmailOTPValue(v.Value)
	if attempts >= opts.allowedAttempts() {
		c.WriteError(apierror.New(http.StatusForbidden, codeEmailOTPTooManyAttempts, "Too many attempts"))
		return false
	}
	if storedOTP != otp {
		if !saveEmailOTPAttempts(c, v, attempts+1) {
			return false
		}
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
		return false
	}
	return true
}

func splitEmailOTPValue(value string) (string, int) {
	idx := strings.LastIndex(value, ":")
	if idx < 0 {
		return value, 0
	}
	attempts, err := strconv.Atoi(value[idx+1:])
	if err != nil {
		return value, 0
	}
	return value[:idx], attempts
}

func saveEmailOTPAttempts(c *auth.Context, verification *types.Verification, attempts int) bool {
	otp, _ := splitEmailOTPValue(verification.Value)
	now := time.Now()
	err := c.Auth.Store().CreateVerification(c.R.Context(), &types.Verification{
		ID: verification.ID, Identifier: verification.Identifier, Value: otp + ":" + strconv.Itoa(attempts),
		ExpiresAt: verification.ExpiresAt, CreatedAt: verification.CreatedAt, UpdatedAt: now,
	})
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	return true
}

func verifyEmailOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		var body struct {
			Email string `json:"email"`
			OTP   string `json:"otp"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		if !verifyStoredOTP(c, opts, constants.EmailOTPTypeVerification, body.Email, body.OTP, true) {
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

func signInEmailOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		var body struct {
			Email      string  `json:"email"`
			OTP        string  `json:"otp"`
			Name       string  `json:"name"`
			Image      *string `json:"image"`
			RememberMe *bool   `json:"rememberMe"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		if !verifyStoredOTP(c, opts, constants.EmailOTPTypeSignIn, body.Email, body.OTP, true) {
			return
		}
		email := auth.NormalizeEmail(body.Email)
		user, err := c.Auth.Store().FindUserByEmail(c.R.Context(), email)
		if errors.Is(err, berrors.ErrNotFound) {
			if opts.DisableSignUp {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
				return
			}
			user, err = c.Auth.CreateUser(c.R.Context(), body.Name, email, body.Image, nil)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusUnprocessableEntity, constants.CodeFailedToCreateUser))
				return
			}
			verified := true
			user, err = c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{EmailVerified: &verified})
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
		} else if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		} else if !user.EmailVerified {
			verified := true
			user, err = c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{EmailVerified: &verified})
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
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

func resetPasswordOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
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
		if !verifyStoredOTP(c, opts, constants.EmailOTPTypeForgetPassword, body.Email, body.OTP, true) {
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

func changeEmailOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
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
		if !verifyStoredOTP(c, opts, constants.EmailOTPTypeEmailChange, body.Email, body.OTP, true) {
			return
		}
		email := auth.NormalizeEmail(body.Email)
		user, _ = c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{Email: &email})
		c.WriteJSON(http.StatusOK, map[string]any{"user": user})
	}
}
