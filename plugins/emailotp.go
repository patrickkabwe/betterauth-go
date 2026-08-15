package plugins

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
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
	ExpiresIn       time.Duration
	OTPLength       int
	AllowedAttempts int
	DisableSignUp   bool
}

const emailOTPTypeSignIn = "sign-in"

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
			rt(http.MethodPost, "/email-otp/check-verification-otp", checkOTPHandler(opts)),
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

func otpIdentifier(typ string, email string) string {
	return typ + "-otp-" + auth.NormalizeEmail(email)
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
		if !validateEmailOTPAddress(c, body.Email) {
			return
		}
		typ := body.Type
		if typ == "" {
			typ = constants.EmailOTPTypeVerification
		}
		if typ == constants.EmailOTPTypeEmailChange {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidOTP, "Invalid OTP type"))
			return
		}
		if !validEmailOTPType(typ) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		sendOTPForType(c, opts, body.Email, typ)
	}
}

func checkOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		var body struct {
			Email string `json:"email"`
			Type  string `json:"type"`
			OTP   string `json:"otp"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Email == "" || body.OTP == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		if !validateEmailOTPAddress(c, body.Email) {
			return
		}
		typ := body.Type
		if typ == "" {
			typ = constants.EmailOTPTypeVerification
		}
		if !validEmailOTPType(typ) {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		if !verifyStoredOTP(c, opts, typ, body.Email, body.OTP, false) {
			return
		}
		if _, err := c.Auth.Store().FindUserByEmail(c.R.Context(), auth.NormalizeEmail(body.Email)); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeUserNotFound))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func verifyEmailOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		var body struct {
			Email string `json:"email"`
			OTP   string `json:"otp"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Email == "" || body.OTP == "" {
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
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeUserNotFound))
			return
		}
		verified := true
		user, err = c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{EmailVerified: &verified})
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]any{"status": true, "token": nil, "user": user})
	}
}

func signInEmailOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		var raw map[string]json.RawMessage
		if err := c.ParseJSON(&raw); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		body, err := signInEmailOTPBodyFromRaw(raw)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		if !validateEmailOTPAddress(c, body.Email) {
			return
		}
		email := auth.NormalizeEmail(body.Email)
		if !verifyStoredOTP(c, opts, emailOTPTypeSignIn, email, body.OTP, true) {
			return
		}
		user, err := c.Auth.Store().FindUserByEmail(c.R.Context(), email)
		if err != nil {
			if !errors.Is(err, berrors.ErrNotFound) {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
			if opts.DisableSignUp {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
				return
			}
			user = createEmailOTPUser(c, raw, body.Name, email, body.Image)
			if user == nil {
				return
			}
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

func requestPasswordResetEmailOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		var body struct {
			Email string `json:"email"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Email == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidEmail))
			return
		}
		if !validateEmailOTPAddress(c, body.Email) {
			return
		}
		sendOTPForType(c, opts, body.Email, constants.EmailOTPTypeForgetPassword)
	}
}

func resetPasswordOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		var body struct {
			Email    string `json:"email"`
			OTP      string `json:"otp"`
			Password string `json:"password"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Email == "" || body.OTP == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		if !validateEmailOTPAddress(c, body.Email) {
			return
		}
		if !validateEmailOTPPassword(c, body.Password) {
			return
		}
		if !verifyStoredOTP(c, opts, constants.EmailOTPTypeForgetPassword, body.Email, body.OTP, true) {
			return
		}
		user, err := c.Auth.Store().FindUserByEmail(c.R.Context(), auth.NormalizeEmail(body.Email))
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeUserNotFound))
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

func requestEmailChangeOTPHandler(opts EmailOTPOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		_, user, ok := c.RequireSession()
		if !ok {
			return
		}
		var body struct {
			NewEmail string `json:"newEmail"`
		}
		if err := c.ParseJSON(&body); err != nil || body.NewEmail == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidEmail))
			return
		}
		if !validateEmailOTPAddress(c, body.NewEmail) {
			return
		}
		newEmail := auth.NormalizeEmail(body.NewEmail)
		currentEmail := auth.NormalizeEmail(user.Email)
		if newEmail == currentEmail {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeEmailIsTheSame, "Email is the same"))
			return
		}
		identifier := otpIdentifier(constants.EmailOTPTypeEmailChange, currentEmail+"-"+newEmail)
		otp, err := numericEmailOTP(opts.length())
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if err := c.Auth.CreateVerification(c.R.Context(), identifier, otp+":0", opts.expires()); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		if _, err := c.Auth.Store().FindUserByEmail(c.R.Context(), newEmail); err == nil {
			if err := c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), identifier); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return
			}
			c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			return
		}
		if opts.SendOTP == nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeEmailOTPDisabled))
			return
		}
		if err := opts.SendOTP(c.R.Context(), newEmail, otp, constants.EmailOTPTypeEmailChange); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
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
			NewEmail string `json:"newEmail"`
			OTP      string `json:"otp"`
		}
		if err := c.ParseJSON(&body); err != nil || body.NewEmail == "" || body.OTP == "" {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
			return
		}
		if !validateEmailOTPAddress(c, body.NewEmail) {
			return
		}
		newEmail := auth.NormalizeEmail(body.NewEmail)
		currentEmail := auth.NormalizeEmail(user.Email)
		if !verifyStoredOTP(c, opts, constants.EmailOTPTypeEmailChange, currentEmail+"-"+newEmail, body.OTP, true) {
			return
		}
		if _, err := c.Auth.Store().FindUserByEmail(c.R.Context(), newEmail); err == nil {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidEmail, "Email already in use"))
			return
		}
		verified := true
		user, err := c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{Email: &newEmail, EmailVerified: &verified})
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
		_ = user
	}
}

func sendOTPForType(c *auth.Context, opts EmailOTPOptions, email string, typ string) bool {
	if opts.SendOTP == nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeEmailOTPDisabled))
		return false
	}
	normalized := auth.NormalizeEmail(email)
	otp, err := numericEmailOTP(opts.length())
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	identifier := otpIdentifier(typ, normalized)
	if err := c.Auth.CreateVerification(c.R.Context(), identifier, otp+":0", opts.expires()); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	_, err = c.Auth.Store().FindUserByEmail(c.R.Context(), normalized)
	if err != nil {
		if errors.Is(err, berrors.ErrNotFound) && (typ != emailOTPTypeSignIn || opts.DisableSignUp) {
			if err := c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), identifier); err != nil {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
				return false
			}
			c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			return false
		}
		if !errors.Is(err, berrors.ErrNotFound) {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return false
		}
	}
	if err := opts.SendOTP(c.R.Context(), normalized, otp, typ); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	return true
}

func verifyStoredOTP(c *auth.Context, opts EmailOTPOptions, typ string, email string, otp string, consume bool) bool {
	identifier := otpIdentifier(typ, email)
	v, err := c.Auth.Store().FindVerificationByIdentifier(c.R.Context(), identifier)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
		return false
	}
	if time.Now().After(v.ExpiresAt) {
		if err := c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), identifier); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return false
		}
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
		return false
	}
	storedOTP, attempts := splitEmailOTPValue(v.Value)
	if attempts >= opts.allowedAttempts() {
		if err := c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), identifier); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return false
		}
		c.WriteError(apierror.New(http.StatusForbidden, "TOO_MANY_ATTEMPTS", "Too many attempts"))
		return false
	}
	if storedOTP != otp {
		if err := saveEmailOTPAttempts(c, v, attempts+1); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return false
		}
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
		return false
	}
	if consume {
		if err := c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), identifier); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return false
		}
	}
	return true
}

type signInEmailOTPBody struct {
	Email      string
	OTP        string
	Name       string
	Image      *string
	RememberMe *bool
}

func signInEmailOTPBodyFromRaw(raw map[string]json.RawMessage) (signInEmailOTPBody, error) {
	var body signInEmailOTPBody
	if err := decodeEmailOTPString(raw, "email", &body.Email); err != nil {
		return signInEmailOTPBody{}, err
	}
	if err := decodeEmailOTPString(raw, "otp", &body.OTP); err != nil {
		return signInEmailOTPBody{}, err
	}
	if err := decodeEmailOTPString(raw, "name", &body.Name); err != nil {
		return signInEmailOTPBody{}, err
	}
	if value, ok := raw["image"]; ok {
		if err := json.Unmarshal(value, &body.Image); err != nil {
			return signInEmailOTPBody{}, err
		}
	}
	if value, ok := raw["rememberMe"]; ok {
		if err := json.Unmarshal(value, &body.RememberMe); err != nil {
			return signInEmailOTPBody{}, err
		}
	}
	if body.Email == "" || body.OTP == "" {
		return signInEmailOTPBody{}, errors.New("email and otp are required")
	}
	return body, nil
}

func decodeEmailOTPString(raw map[string]json.RawMessage, key string, dst *string) error {
	value, ok := raw[key]
	if !ok {
		return nil
	}
	return json.Unmarshal(value, dst)
}

func createEmailOTPUser(c *auth.Context, raw map[string]json.RawMessage, name string, email string, image *string) *types.User {
	additional, fieldErr := c.Auth.ParseAdditionalUserCreateInput(stripEmailOTPSignInFields(raw))
	if fieldErr != nil {
		c.WriteError(fieldErr)
		return nil
	}
	user, err := c.Auth.CreateUser(c.R.Context(), name, auth.NormalizeEmail(email), image, additional)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeFailedToCreateUser))
		return nil
	}
	verified := true
	user, err = c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{EmailVerified: &verified})
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return nil
	}
	return user
}

func stripEmailOTPSignInFields(raw map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(raw))
	for key, value := range raw {
		switch key {
		case "email", "otp", "name", "image", "rememberMe":
			continue
		default:
			out[key] = value
		}
	}
	return out
}

func validateEmailOTPAddress(c *auth.Context, email string) bool {
	if !internalcrypto.ValidateEmail(auth.NormalizeEmail(email)) {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidEmail))
		return false
	}
	return true
}

func validateEmailOTPPassword(c *auth.Context, password string) bool {
	minPassword, maxPassword := c.Auth.PasswordLengthLimits()
	if len(password) < minPassword {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodePasswordTooShort))
		return false
	}
	if len(password) > maxPassword {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodePasswordTooLong))
		return false
	}
	if err := c.Auth.ValidatePasswords(password); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidPassword, err.Error()))
		return false
	}
	return true
}

func validEmailOTPType(typ string) bool {
	switch typ {
	case emailOTPTypeSignIn, constants.EmailOTPTypeVerification, constants.EmailOTPTypeForgetPassword, constants.EmailOTPTypeEmailChange:
		return true
	default:
		return false
	}
}

func splitEmailOTPValue(value string) (string, int) {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) == 1 {
		return parts[0], 0
	}
	attempts, err := strconv.Atoi(parts[1])
	if err != nil {
		return parts[0], 0
	}
	return parts[0], attempts
}

func saveEmailOTPAttempts(c *auth.Context, v *types.Verification, attempts int) error {
	otp, _ := splitEmailOTPValue(v.Value)
	now := time.Now()
	return c.Auth.Store().CreateVerification(c.R.Context(), &types.Verification{
		ID: v.ID, Identifier: v.Identifier, Value: otp + ":" + strconv.Itoa(attempts),
		ExpiresAt: v.ExpiresAt, CreatedAt: v.CreatedAt, UpdatedAt: now,
	})
}

func numericEmailOTP(length int) (string, error) {
	raw := make([]byte, length)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	digits := make([]byte, length)
	for i := 0; i < length; i++ {
		digits[i] = '0' + raw[i]%10
	}
	return string(digits), nil
}
