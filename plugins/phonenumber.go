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
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

// PhoneNumberOptions configures phone number authentication.
type PhoneNumberOptions struct {
	SendOTP                func(ctx context.Context, phone, otp string) error
	SendPasswordResetOTP   func(ctx context.Context, phone, otp string) error
	VerifyOTP              func(ctx context.Context, phone, otp string) (bool, error)
	PhoneNumberValidator   func(ctx context.Context, phone string) (bool, error)
	CallbackOnVerification func(ctx context.Context, phone string, user *types.User) error
	SignUpOnVerification   *PhoneNumberSignUpOnVerificationOptions
	ExpiresIn              time.Duration
	OTPLength              int
	AllowedAttempts        int
	RequireVerification    bool
}

// PhoneNumberSignUpOnVerificationOptions configures user creation on phone verification.
type PhoneNumberSignUpOnVerificationOptions struct {
	GetTempEmail func(phone string) string
	GetTempName  func(phone string) string
}

const (
	codeInvalidPhoneNumberOrPassword = "INVALID_PHONE_NUMBER_OR_PASSWORD"
	codeInvalidPhoneNumber           = "INVALID_PHONE_NUMBER"
	codePhoneNumberNotVerified       = "PHONE_NUMBER_NOT_VERIFIED"
	codePhoneNumberExists            = "PHONE_NUMBER_EXIST"
	codeUnexpectedError              = "UNEXPECTED_ERROR"
	codeTooManyAttempts              = "TOO_MANY_ATTEMPTS"
)

// PhoneNumber adds phone number authentication.
func PhoneNumber(opts PhoneNumberOptions) auth.Plugin {
	expires := opts.ExpiresIn
	if expires == 0 {
		expires = 5 * time.Minute
	}
	otpLength := opts.OTPLength
	if otpLength == 0 {
		otpLength = 6
	}
	allowedAttempts := opts.AllowedAttempts
	if allowedAttempts == 0 {
		allowedAttempts = 3
	}
	return basePlugin{
		id: constants.PluginPhoneNumber,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/phone-number/send-otp", func(c *auth.Context) {
				if opts.SendOTP == nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodePhoneOTPDisabled))
					return
				}
				var body struct {
					PhoneNumber string `json:"phoneNumber"`
				}
				if err := c.ParseJSON(&body); err != nil || body.PhoneNumber == "" {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidPhone))
					return
				}
				if !validatePhoneNumber(c, opts.PhoneNumberValidator, body.PhoneNumber) {
					return
				}
				otp, err := numericOTP(otpLength)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				if err := c.Auth.CreateVerification(c.R.Context(), phoneVerificationIdentifier(body.PhoneNumber), otp+":0", expires); err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				if err := opts.SendOTP(c.R.Context(), body.PhoneNumber, otp); err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]string{"message": "code sent"})
			}),
			rt(http.MethodPost, "/phone-number/verify", func(c *auth.Context) {
				var raw map[string]json.RawMessage
				if err := c.ParseJSON(&raw); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
					return
				}
				body, err := phoneVerifyBodyFromRaw(raw)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
					return
				}
				if !verifyPhoneOTP(c, opts.VerifyOTP, body.PhoneNumber, body.Code, allowedAttempts) {
					return
				}
				if body.UpdatePhoneNumber {
					sess, user, ok := c.RequireSession()
					if !ok {
						return
					}
					_, err := c.Auth.FindUserByAdditional(c.R.Context(), constants.FieldPhoneNumber, body.PhoneNumber)
					if err != nil && !errors.Is(err, berrors.ErrNotFound) {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					if err == nil {
						c.WriteError(apierror.New(http.StatusBadRequest, codePhoneNumberExists, "Phone number already exists"))
						return
					}
					updated, err := c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{
						Additional: map[string]any{
							constants.FieldPhoneNumber:   body.PhoneNumber,
							constants.FieldPhoneVerified: true,
						},
					})
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					c.Auth.SyncUserSession(c, sess, updated)
					if !notifyPhoneVerification(c, opts.CallbackOnVerification, body.PhoneNumber, updated) {
						return
					}
					c.WriteJSON(http.StatusOK, map[string]any{"status": true, "token": sess.Token, "user": updated})
					return
				}
				user, err := c.Auth.FindUserByAdditional(c.R.Context(), constants.FieldPhoneNumber, body.PhoneNumber)
				if err != nil {
					if !errors.Is(err, berrors.ErrNotFound) {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
					var fieldErr *apierror.Error
					user, fieldErr, err = createPhoneVerificationUser(c, opts.SignUpOnVerification, body.PhoneNumber, raw)
					if fieldErr != nil {
						c.WriteError(fieldErr)
						return
					}
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeFailedToCreateUser))
						return
					}
				}
				if user == nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				if user.Additional[constants.FieldPhoneVerified] != true {
					user, err = c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{
						Additional: map[string]any{constants.FieldPhoneVerified: true},
					})
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
				}
				if !notifyPhoneVerification(c, opts.CallbackOnVerification, body.PhoneNumber, user) {
					return
				}
				token := ""
				if !body.DisableSession {
					sess, err := c.Auth.NewSession(c, user.ID, true)
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeFailedToCreateSession))
						return
					}
					token = sess.Token
				}
				c.WriteJSON(http.StatusOK, map[string]any{"status": true, "token": tokenOrNil(token), "user": user})
			}),
			rt(http.MethodPost, "/sign-in/phone-number", func(c *auth.Context) {
				var body struct {
					PhoneNumber string `json:"phoneNumber"`
					Password    string `json:"password"`
					RememberMe  *bool  `json:"rememberMe"`
				}
				if err := c.ParseJSON(&body); err != nil || body.PhoneNumber == "" || body.Password == "" {
					c.WriteError(apierror.New(http.StatusUnauthorized, codeInvalidPhoneNumberOrPassword, "Invalid phone number or password"))
					return
				}
				if !validatePhoneNumber(c, opts.PhoneNumberValidator, body.PhoneNumber) {
					return
				}
				user, err := c.Auth.FindUserByAdditional(c.R.Context(), constants.FieldPhoneNumber, body.PhoneNumber)
				if err != nil {
					c.WriteError(apierror.New(http.StatusUnauthorized, codeInvalidPhoneNumberOrPassword, "Invalid phone number or password"))
					return
				}
				if opts.RequireVerification && !auth.UserAdditionalBool(user, constants.FieldPhoneVerified) {
					if opts.SendOTP != nil {
						otp, err := numericOTP(otpLength)
						if err != nil {
							c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
							return
						}
						if err := c.Auth.CreateVerification(c.R.Context(), phoneVerificationIdentifier(body.PhoneNumber), otp+":0", expires); err != nil {
							c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
							return
						}
						if err := opts.SendOTP(c.R.Context(), body.PhoneNumber, otp); err != nil {
							c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
							return
						}
					}
					c.WriteError(apierror.New(http.StatusUnauthorized, codePhoneNumberNotVerified, "Phone number not verified"))
					return
				}
				account, err := c.Auth.Store().FindAccountByUserAndProvider(c.R.Context(), user.ID, constants.ProviderCredential)
				if err != nil || account.Password == "" {
					c.WriteError(apierror.New(http.StatusUnauthorized, codeInvalidPhoneNumberOrPassword, "Invalid phone number or password"))
					return
				}
				ok, _ := c.Auth.VerifyPassword(account.Password, body.Password)
				if !ok {
					c.WriteError(apierror.New(http.StatusUnauthorized, codeInvalidPhoneNumberOrPassword, "Invalid phone number or password"))
					return
				}
				remember := true
				if body.RememberMe != nil {
					remember = *body.RememberMe
				}
				if c.Auth.StartTwoFactorSignIn(c, user, remember) {
					return
				}
				sess, err := c.Auth.NewSession(c, user.ID, remember)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeFailedToCreateSession))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]any{"token": sess.Token, "user": user})
			}),
			rt(http.MethodPost, "/phone-number/request-password-reset", func(c *auth.Context) {
				var body struct {
					PhoneNumber string `json:"phoneNumber"`
				}
				if err := c.ParseJSON(&body); err != nil || body.PhoneNumber == "" {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidPhone))
					return
				}
				otp, err := numericOTP(otpLength)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				identifier := phonePasswordResetIdentifier(body.PhoneNumber)
				if err := c.Auth.CreateVerification(c.R.Context(), identifier, otp+":0", expires); err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				_, err = c.Auth.FindUserByAdditional(c.R.Context(), constants.FieldPhoneNumber, body.PhoneNumber)
				if err != nil {
					if errors.Is(err, berrors.ErrNotFound) {
						c.WriteJSON(http.StatusOK, map[string]bool{"status": true})
						return
					}
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				if opts.SendPasswordResetOTP != nil {
					if err := opts.SendPasswordResetOTP(c.R.Context(), body.PhoneNumber, otp); err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
				}
				c.WriteJSON(http.StatusOK, map[string]bool{"status": true})
			}),
			rt(http.MethodPost, "/phone-number/reset-password", func(c *auth.Context) {
				var body struct {
					PhoneNumber string `json:"phoneNumber"`
					OTP         string `json:"otp"`
					NewPassword string `json:"newPassword"`
				}
				if err := c.ParseJSON(&body); err != nil || body.PhoneNumber == "" || body.OTP == "" {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
					return
				}
				if !consumePhoneOTP(c, phonePasswordResetIdentifier(body.PhoneNumber), body.OTP, allowedAttempts) {
					return
				}
				user, err := c.Auth.FindUserByAdditional(c.R.Context(), constants.FieldPhoneNumber, body.PhoneNumber)
				if err != nil {
					if errors.Is(err, berrors.ErrNotFound) {
						c.WriteError(apierror.New(http.StatusBadRequest, codeUnexpectedError, "Unexpected error"))
						return
					}
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				if !validatePhoneResetPassword(c, body.NewPassword) {
					return
				}
				hash, err := c.Auth.HashPassword(body.NewPassword)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				if !setPhoneCredentialPassword(c, user.ID, hash) {
					return
				}
				if err := c.Auth.RevokeSessionsOnPasswordReset(c.R.Context(), user.ID); err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]bool{"status": true})
			}),
		},
	}
}

type phoneVerifyBody struct {
	PhoneNumber       string
	Code              string
	DisableSession    bool
	UpdatePhoneNumber bool
}

func phoneVerifyBodyFromRaw(raw map[string]json.RawMessage) (phoneVerifyBody, error) {
	var body phoneVerifyBody
	if err := decodePhoneString(raw, "phoneNumber", &body.PhoneNumber); err != nil {
		return phoneVerifyBody{}, err
	}
	if err := decodePhoneString(raw, "code", &body.Code); err != nil {
		return phoneVerifyBody{}, err
	}
	if err := decodePhoneBool(raw, "disableSession", &body.DisableSession); err != nil {
		return phoneVerifyBody{}, err
	}
	if err := decodePhoneBool(raw, "updatePhoneNumber", &body.UpdatePhoneNumber); err != nil {
		return phoneVerifyBody{}, err
	}
	if body.PhoneNumber == "" || body.Code == "" {
		return phoneVerifyBody{}, errors.New("phone number and code are required")
	}
	return body, nil
}

func decodePhoneString(raw map[string]json.RawMessage, key string, dst *string) error {
	value, ok := raw[key]
	if !ok {
		return nil
	}
	return json.Unmarshal(value, dst)
}

func decodePhoneBool(raw map[string]json.RawMessage, key string, dst *bool) error {
	value, ok := raw[key]
	if !ok {
		return nil
	}
	return json.Unmarshal(value, dst)
}

func validatePhoneNumber(c *auth.Context, validator func(context.Context, string) (bool, error), phoneNumber string) bool {
	if validator == nil {
		return true
	}
	ok, err := validator(c.R.Context(), phoneNumber)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	if !ok {
		c.WriteError(apierror.New(http.StatusBadRequest, codeInvalidPhoneNumber, "Invalid phone number"))
		return false
	}
	return true
}

func verifyPhoneOTP(c *auth.Context, verifyOTP func(context.Context, string, string) (bool, error), phoneNumber string, code string, allowedAttempts int) bool {
	if verifyOTP == nil {
		return consumePhoneOTP(c, phoneVerificationIdentifier(phoneNumber), code, allowedAttempts)
	}
	ok, err := verifyOTP(c.R.Context(), phoneNumber, code)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	if !ok {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
		return false
	}
	_, err = c.Auth.Store().FindVerificationByIdentifier(c.R.Context(), phoneVerificationIdentifier(phoneNumber))
	if err != nil {
		if errors.Is(err, berrors.ErrNotFound) {
			return true
		}
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	if err := c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), phoneVerificationIdentifier(phoneNumber)); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	return true
}

func createPhoneVerificationUser(c *auth.Context, opts *PhoneNumberSignUpOnVerificationOptions, phoneNumber string, raw map[string]json.RawMessage) (*types.User, *apierror.Error, error) {
	if opts == nil {
		return nil, nil, nil
	}
	if opts.GetTempEmail == nil {
		return nil, nil, errors.New("phone sign-up temp email callback is required")
	}
	additionalInput := stripPhoneVerifyFields(raw)
	additional, fieldErr := c.Auth.ParseAdditionalUserCreateInput(additionalInput)
	if fieldErr != nil {
		return nil, fieldErr, nil
	}
	name := phoneNumber
	if opts.GetTempName != nil {
		name = opts.GetTempName(phoneNumber)
	}
	email := opts.GetTempEmail(phoneNumber)
	additional = mergePhoneAdditional(additional, map[string]any{
		constants.FieldPhoneNumber:   phoneNumber,
		constants.FieldPhoneVerified: true,
	})
	user, err := c.Auth.CreateUser(c.R.Context(), name, email, nil, additional)
	return user, nil, err
}

func stripPhoneVerifyFields(raw map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(raw))
	for key, value := range raw {
		switch key {
		case "phoneNumber", "code", "disableSession", "updatePhoneNumber":
			continue
		default:
			out[key] = value
		}
	}
	return out
}

func mergePhoneAdditional(base map[string]any, next map[string]any) map[string]any {
	if base == nil {
		base = make(map[string]any, len(next))
	}
	for key, value := range next {
		base[key] = value
	}
	return base
}

func notifyPhoneVerification(c *auth.Context, callback func(context.Context, string, *types.User) error, phoneNumber string, user *types.User) bool {
	if callback == nil {
		return true
	}
	if err := callback(c.R.Context(), phoneNumber, user); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	return true
}

func consumePhoneOTP(c *auth.Context, identifier string, code string, allowedAttempts int) bool {
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
	otp, attempts := splitPhoneOTPValue(v.Value)
	if attempts >= allowedAttempts {
		if err := c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), identifier); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return false
		}
		c.WriteError(apierror.New(http.StatusForbidden, codeTooManyAttempts, "Too many attempts"))
		return false
	}
	if otp != code {
		if !savePhoneOTPAttempts(c, v, attempts+1) {
			return false
		}
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
		return false
	}
	if err := c.Auth.Store().DeleteVerificationByIdentifier(c.R.Context(), identifier); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	return true
}

func splitPhoneOTPValue(value string) (string, int) {
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

func savePhoneOTPAttempts(c *auth.Context, v *types.Verification, attempts int) bool {
	otp, _ := splitPhoneOTPValue(v.Value)
	now := time.Now()
	err := c.Auth.Store().CreateVerification(c.R.Context(), &types.Verification{
		ID: v.ID, Identifier: v.Identifier, Value: otp + ":" + strconv.Itoa(attempts),
		ExpiresAt: v.ExpiresAt, CreatedAt: v.CreatedAt, UpdatedAt: now,
	})
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	return true
}

func validatePhoneResetPassword(c *auth.Context, password string) bool {
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

func setPhoneCredentialPassword(c *auth.Context, userID string, password string) bool {
	if err := c.Auth.SetCredentialPassword(c.R.Context(), userID, password); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return false
	}
	return true
}

func numericOTP(length int) (string, error) {
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

func phoneVerificationIdentifier(phoneNumber string) string {
	return phoneNumber
}

func phonePasswordResetIdentifier(phoneNumber string) string {
	return phoneNumber + "-request-password-reset"
}

func tokenOrNil(token string) any {
	if token == "" {
		return nil
	}
	return token
}
