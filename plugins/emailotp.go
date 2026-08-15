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
	internalcrypto "github.com/patrickkabwe/betterauth-go/internal/crypto"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

// EmailOTPOptions configures email OTP flows.
type EmailOTPOptions struct {
	SendOTP         func(ctx context.Context, email, otp, typ string) error
	GenerateOTP     EmailOTPGenerateOTP
	ExpiresIn       time.Duration
	OTPLength       int
	DisableSignUp   bool
	AllowedAttempts int
	ChangeEmail     EmailOTPChangeEmailOptions
	ResendStrategy  EmailOTPResendStrategy
	StoreOTP        EmailOTPStoreOTP
	HashOTP         EmailOTPHashOTP
	EncryptOTP      EmailOTPEncryptOTP
	DecryptOTP      EmailOTPDecryptOTP
}

// EmailOTPGenerateOTP generates an OTP for an email OTP flow.
type EmailOTPGenerateOTP func(ctx context.Context, email, typ string) (string, error)

// EmailOTPHashOTP hashes an OTP for storage and verification.
type EmailOTPHashOTP func(ctx context.Context, otp string) (string, error)

// EmailOTPEncryptOTP encrypts a recoverable OTP before storage.
type EmailOTPEncryptOTP func(ctx context.Context, otp string) (string, error)

// EmailOTPDecryptOTP decrypts a recoverable stored OTP.
type EmailOTPDecryptOTP func(ctx context.Context, storedOTP string) (string, error)

// EmailOTPStoreOTP controls how OTP values are persisted.
type EmailOTPStoreOTP string

// EmailOTPChangeEmailOptions configures the change-email OTP flow.
type EmailOTPChangeEmailOptions struct {
	Enabled            bool
	VerifyCurrentEmail bool
}

// EmailOTPResendStrategy controls OTP behavior when a valid code already exists.
type EmailOTPResendStrategy string

const (
	codeEmailOTPExpired         = "OTP_EXPIRED"
	codeEmailOTPTooManyAttempts = "TOO_MANY_ATTEMPTS"

	EmailOTPResendStrategyReuse EmailOTPResendStrategy = "reuse"

	EmailOTPStoreOTPHashed EmailOTPStoreOTP = "hashed"
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
			srt(http.MethodPost, "/email-otp/create-verification-otp", createVerificationOTPHandler(opts)),
			srt(http.MethodGet, "/email-otp/get-verification-otp", getVerificationOTPHandler(opts)),
			rt(http.MethodPost, "/email-otp/check-verification-otp", checkOTPHandler(opts, constants.EmailOTPTypeVerification)),
			rt(http.MethodPost, "/email-otp/verify-email", verifyEmailOTPHandler(opts)),
			rt(http.MethodPost, "/sign-in/email-otp", signInEmailOTPHandler(opts)),
			rt(http.MethodPost, "/email-otp/request-password-reset", requestPasswordResetEmailOTPHandler(opts)),
			rt(http.MethodPost, "/forget-password/email-otp", requestPasswordResetEmailOTPHandler(opts)),
			rt(http.MethodPost, "/email-otp/reset-password", resetPasswordOTPHandler(opts)),
			rt(http.MethodPost, "/email-otp/request-email-change", requestEmailChangeOTPHandler(opts)),
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
		if opts.SendOTP == nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeEmailOTPDisabled))
			return
		}
		email := auth.NormalizeEmail(body.Email)
		if !validateEmailOTPAddress(c, email) {
			return
		}
		_, err := c.Auth.Store().FindUserByEmail(c.R.Context(), email)
		if errors.Is(err, berrors.ErrNotFound) {
			if body.Type != constants.EmailOTPTypeSignIn || opts.DisableSignUp {
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
				return
			}
		} else if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		sendOTP(c, opts, email, body.Type)
	}
}

func otpIdentifier(typ, email string) string {
	return fmt.Sprintf("%s%s:%s", constants.VerificationEmailOTP, typ, auth.NormalizeEmail(email))
}

func validateEmailOTPAddress(c *auth.Context, email string) bool {
	if !internalcrypto.ValidateEmail(auth.NormalizeEmail(email)) {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidEmail))
		return false
	}
	return true
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
	otp, ok := createEmailOTP(c, opts, email, typ, otpIdentifier(typ, email))
	if !ok {
		return
	}
	if err := opts.SendOTP(c.R.Context(), email, otp, typ); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return
	}
	c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
}

func createEmailOTP(c *auth.Context, opts EmailOTPOptions, email, typ, identifier string) (string, bool) {
	if opts.ResendStrategy == EmailOTPResendStrategyReuse {
		otp, reused, ok := reuseEmailOTP(c, opts, identifier)
		if !ok {
			return "", false
		}
		if reused {
			return otp, true
		}
	}
	return storeGeneratedEmailOTP(c, opts, email, typ, identifier)
}

func storeGeneratedEmailOTP(c *auth.Context, opts EmailOTPOptions, email, typ, identifier string) (string, bool) {
	otp, err := generateEmailOTP(c.R.Context(), opts, email, typ)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return "", false
	}
	storedOTP, ok := storeEmailOTPValue(c, opts, otp)
	if !ok {
		return "", false
	}
	if err := c.Auth.CreateVerification(c.R.Context(), identifier, storedOTP+":0", opts.expires()); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return "", false
	}
	return otp, true
}

func storeEmailOTPValue(c *auth.Context, opts EmailOTPOptions, otp string) (string, bool) {
	if opts.HashOTP != nil {
		hash, err := opts.HashOTP(c.R.Context(), otp)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return "", false
		}
		return hash, true
	}
	if opts.EncryptOTP != nil || opts.DecryptOTP != nil {
		if opts.EncryptOTP == nil || opts.DecryptOTP == nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return "", false
		}
		encryptedOTP, err := opts.EncryptOTP(c.R.Context(), otp)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return "", false
		}
		return encryptedOTP, true
	}
	if opts.StoreOTP != EmailOTPStoreOTPHashed {
		return otp, true
	}
	hash, err := c.Auth.HashPassword(otp)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return "", false
	}
	return hash, true
}

func createVerificationOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		var body struct {
			Email string `json:"email"`
			Type  string `json:"type"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Email == "" || !validEmailOTPType(body.Type) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		email := auth.NormalizeEmail(body.Email)
		otp, ok := storeGeneratedEmailOTP(c, opts, email, body.Type, otpIdentifier(body.Type, email))
		if !ok {
			return
		}
		c.WriteJSON(http.StatusOK, otp)
	}
}

func getVerificationOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		email := auth.NormalizeEmail(c.R.URL.Query().Get("email"))
		typ := c.R.URL.Query().Get("type")
		if email == "" || !validEmailOTPType(typ) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		verification, err := c.Auth.Store().FindVerificationByIdentifier(c.R.Context(), otpIdentifier(typ, email))
		if errors.Is(err, berrors.ErrNotFound) {
			c.WriteJSON(http.StatusOK, map[string]*string{"otp": nil})
			return
		}
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if time.Now().After(verification.ExpiresAt) {
			c.WriteJSON(http.StatusOK, map[string]*string{"otp": nil})
			return
		}
		if emailOTPValueIsUnrecoverable(opts) {
			c.WriteError(apierror.New(http.StatusBadRequest, "BAD_REQUEST", "OTP is hashed, cannot return the plain text OTP"))
			return
		}
		storedOTP, _ := splitEmailOTPValue(verification.Value)
		otp, ok := retrieveEmailOTPValue(c, opts, storedOTP)
		if !ok {
			return
		}
		c.WriteJSON(http.StatusOK, map[string]*string{"otp": &otp})
	}
}

func generateEmailOTP(ctx context.Context, opts EmailOTPOptions, email, typ string) (string, error) {
	if opts.GenerateOTP != nil {
		otp, err := opts.GenerateOTP(ctx, email, typ)
		if err != nil {
			return "", err
		}
		if otp != "" {
			return otp, nil
		}
	}
	return numericOTP(opts.length())
}

func reuseEmailOTP(c *auth.Context, opts EmailOTPOptions, identifier string) (string, bool, bool) {
	if emailOTPValueIsUnrecoverable(opts) {
		return "", false, true
	}
	verification, err := c.Auth.Store().FindVerificationByIdentifier(c.R.Context(), identifier)
	if errors.Is(err, berrors.ErrNotFound) {
		return "", false, true
	}
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return "", false, false
	}
	if time.Now().After(verification.ExpiresAt) {
		return "", false, true
	}
	storedOTP, attempts := splitEmailOTPValue(verification.Value)
	if attempts >= opts.allowedAttempts() {
		return "", false, true
	}
	otp, ok := retrieveEmailOTPValue(c, opts, storedOTP)
	if !ok {
		return "", false, false
	}
	now := time.Now()
	err = c.Auth.Store().CreateVerification(c.R.Context(), &types.Verification{
		ID:         verification.ID,
		Identifier: verification.Identifier,
		Value:      verification.Value,
		ExpiresAt:  now.Add(opts.expires()),
		CreatedAt:  verification.CreatedAt,
		UpdatedAt:  now,
	})
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return "", false, false
	}
	return otp, true, true
}

func requestEmailChangeOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		if !opts.ChangeEmail.Enabled {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeChangeEmailDisabled))
			return
		}
		_, user, ok := c.RequireSession()
		if !ok {
			return
		}
		var body struct {
			NewEmail string `json:"newEmail"`
			OTP      string `json:"otp"`
		}
		if err := c.ParseJSON(&body); err != nil || body.NewEmail == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidEmail))
			return
		}
		newEmail := auth.NormalizeEmail(body.NewEmail)
		if !internalcrypto.ValidateEmail(newEmail) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidEmail))
			return
		}
		currentEmail := auth.NormalizeEmail(user.Email)
		if newEmail == currentEmail {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeEmailIsTheSame))
			return
		}
		if opts.ChangeEmail.VerifyCurrentEmail {
			if body.OTP == "" {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
				return
			}
			if !verifyStoredOTP(c, opts, constants.EmailOTPTypeVerification, currentEmail, body.OTP, true) {
				return
			}
		}
		identifier := otpIdentifier(constants.EmailOTPTypeEmailChange, currentEmail+"-"+newEmail)
		if _, err := c.Auth.Store().FindUserByEmail(c.R.Context(), newEmail); err == nil {
			_ = c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), identifier)
			c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			return
		} else if !errors.Is(err, berrors.ErrNotFound) {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if opts.SendOTP == nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeEmailOTPDisabled))
			return
		}
		otp, ok := createEmailOTP(c, opts, newEmail, constants.EmailOTPTypeEmailChange, identifier)
		if !ok {
			return
		}
		if err := opts.SendOTP(c.R.Context(), newEmail, otp, constants.EmailOTPTypeEmailChange); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
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
		if !validateEmailOTPAddress(c, body.Email) {
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
	matches, ok := verifyEmailOTPValue(c, opts, storedOTP, otp)
	if !ok {
		return false
	}
	if !matches {
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
	matches, ok := verifyEmailOTPValue(c, opts, storedOTP, otp)
	if !ok {
		return false
	}
	if !matches {
		if !saveEmailOTPAttempts(c, v, attempts+1) {
			return false
		}
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
		return false
	}
	return true
}

func verifyEmailOTPValue(c *auth.Context, opts EmailOTPOptions, storedOTP, otp string) (bool, bool) {
	if opts.HashOTP != nil {
		hash, err := opts.HashOTP(c.R.Context(), otp)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return false, false
		}
		return hash == storedOTP, true
	}
	if opts.StoreOTP == EmailOTPStoreOTPHashed {
		matches, err := c.Auth.VerifyPassword(storedOTP, otp)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return false, false
		}
		return matches, true
	}
	plainOTP, ok := retrieveEmailOTPValue(c, opts, storedOTP)
	if !ok {
		return false, false
	}
	return plainOTP == otp, true
}

func retrieveEmailOTPValue(c *auth.Context, opts EmailOTPOptions, storedOTP string) (string, bool) {
	if opts.EncryptOTP != nil || opts.DecryptOTP != nil {
		if opts.EncryptOTP == nil || opts.DecryptOTP == nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return "", false
		}
		otp, err := opts.DecryptOTP(c.R.Context(), storedOTP)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return "", false
		}
		return otp, true
	}
	if opts.StoreOTP != EmailOTPStoreOTPHashed {
		return storedOTP, true
	}
	c.WriteError(apierror.New(http.StatusBadRequest, "BAD_REQUEST", "OTP is hashed, cannot return the plain text OTP"))
	return "", false
}

func emailOTPValueIsUnrecoverable(opts EmailOTPOptions) bool {
	return opts.StoreOTP == EmailOTPStoreOTPHashed || opts.HashOTP != nil
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
		if !validateEmailOTPAddress(c, body.Email) {
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
			Email    string `json:"email"`
			OTP      string `json:"otp"`
			Password string `json:"password"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		minPassword, maxPassword := c.Auth.PasswordLengthLimits()
		if len(body.Password) < minPassword {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodePasswordTooShort))
			return
		}
		if len(body.Password) > maxPassword {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodePasswordTooLong))
			return
		}
		if err := c.Auth.ValidatePasswords(body.Password); err != nil {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidPassword, err.Error()))
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
		hash, err := c.Auth.HashPassword(body.Password)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if err := c.Auth.SetCredentialPassword(c.R.Context(), user.ID, hash); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if !user.EmailVerified {
			verified := true
			if _, err := c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{EmailVerified: &verified}); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
		}
		if err := c.Auth.RevokeSessionsOnPasswordReset(c.R.Context(), user.ID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func changeEmailOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		if !opts.ChangeEmail.Enabled {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeChangeEmailDisabled))
			return
		}
		sess, user, ok := c.RequireSession()
		if !ok {
			return
		}
		var body struct {
			NewEmail string `json:"newEmail"`
			OTP      string `json:"otp"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		newEmail := auth.NormalizeEmail(body.NewEmail)
		if !internalcrypto.ValidateEmail(newEmail) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidEmail))
			return
		}
		currentEmail := auth.NormalizeEmail(user.Email)
		if newEmail == currentEmail {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeEmailIsTheSame))
			return
		}
		if !verifyStoredOTP(c, opts, constants.EmailOTPTypeEmailChange, currentEmail+"-"+newEmail, body.OTP, true) {
			return
		}
		if _, err := c.Auth.Store().FindUserByEmail(c.R.Context(), currentEmail); err != nil {
			if errors.Is(err, berrors.ErrNotFound) {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeUserNotFound))
				return
			}
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if _, err := c.Auth.Store().FindUserByEmail(c.R.Context(), newEmail); err == nil {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidEmail, "Email already in use"))
			return
		} else if !errors.Is(err, berrors.ErrNotFound) {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		verified := true
		user, err := c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{Email: &newEmail, EmailVerified: &verified})
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.Auth.SyncUserSession(c, sess, user)
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}
