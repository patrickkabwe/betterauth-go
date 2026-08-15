package plugins

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/store"
)

// PhoneNumberOptions configures SMS OTP sign-in.
type PhoneNumberOptions struct {
	SendOTP              func(ctx context.Context, phone, otp string) error
	SendPasswordResetOTP func(ctx context.Context, phone, otp string) error
	ExpiresIn            time.Duration
}

// PhoneNumber adds phone number OTP authentication.
func PhoneNumber(opts PhoneNumberOptions) auth.Plugin {
	expires := opts.ExpiresIn
	if expires == 0 {
		expires = 5 * time.Minute
	}
	return basePlugin{
		id: constants.PluginPhoneNumber,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/phone-number/send-otp", func(c *auth.Context) {
				if opts.SendOTP == nil {
					c.WriteError(apierror.New(http.StatusNotImplemented, "SEND_OTP_NOT_IMPLEMENTED", "sendOTP not implemented"))
					return
				}
				var body struct {
					PhoneNumber string `json:"phoneNumber"`
				}
				if err := c.ParseJSON(&body); err != nil || body.PhoneNumber == "" {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidPhone))
					return
				}
				otp, err := id.Generate(6)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				otp = otp[:6]
				if err := c.Auth.CreateVerification(c.R.Context(), constants.VerificationPhoneOTP+body.PhoneNumber, otp, expires); err != nil {
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
				var body struct {
					PhoneNumber string `json:"phoneNumber"`
					Code        string `json:"code"`
				}
				if err := c.ParseJSON(&body); err != nil || body.PhoneNumber == "" || body.Code == "" {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
					return
				}
				v, err := c.Auth.ConsumeVerification(c.R.Context(), constants.VerificationPhoneOTP+body.PhoneNumber)
				if err != nil || v.Value != body.Code {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]bool{"status": true})
			}),
			rt(http.MethodPost, "/sign-in/phone-number", func(c *auth.Context) {
				var body struct {
					PhoneNumber string `json:"phoneNumber"`
					Password    string `json:"password"`
					RememberMe  *bool  `json:"rememberMe"`
				}
				if err := c.ParseJSON(&body); err != nil || body.PhoneNumber == "" || body.Password == "" {
					c.WriteError(apierror.New(http.StatusUnauthorized, "INVALID_PHONE_NUMBER_OR_PASSWORD", "Invalid phone number or password"))
					return
				}
				user, err := c.Auth.FindUserByAdditional(c.R.Context(), constants.FieldPhoneNumber, body.PhoneNumber)
				if err != nil {
					c.WriteError(apierror.New(http.StatusUnauthorized, "INVALID_PHONE_NUMBER_OR_PASSWORD", "Invalid phone number or password"))
					return
				}
				account, err := c.Auth.Store().FindAccountByUserAndProvider(c.R.Context(), user.ID, constants.ProviderCredential)
				if err != nil || account.Password == "" {
					c.WriteError(apierror.New(http.StatusUnauthorized, "INVALID_PHONE_NUMBER_OR_PASSWORD", "Invalid phone number or password"))
					return
				}
				ok, _ := c.Auth.VerifyPassword(account.Password, body.Password)
				if !ok {
					c.WriteError(apierror.New(http.StatusUnauthorized, "INVALID_PHONE_NUMBER_OR_PASSWORD", "Invalid phone number or password"))
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
			}),
			rt(http.MethodPost, "/phone-number/request-password-reset", func(c *auth.Context) {
				var body struct {
					PhoneNumber string `json:"phoneNumber"`
				}
				if err := c.ParseJSON(&body); err != nil || body.PhoneNumber == "" {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidPhone))
					return
				}
				otp, err := id.Generate(6)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				otp = otp[:6]
				identifier := body.PhoneNumber + "-request-password-reset"
				if err := c.Auth.CreateVerification(c.R.Context(), identifier, otp, expires); err != nil {
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
				identifier := body.PhoneNumber + "-request-password-reset"
				v, err := c.Auth.ConsumeVerification(c.R.Context(), identifier)
				if err != nil || v.Value != body.OTP {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
					return
				}
				user, err := c.Auth.FindUserByAdditional(c.R.Context(), constants.FieldPhoneNumber, body.PhoneNumber)
				if err != nil {
					if errors.Is(err, berrors.ErrNotFound) {
						c.WriteError(apierror.New(http.StatusBadRequest, "UNEXPECTED_ERROR", "Unexpected error"))
						return
					}
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				minPassword, maxPassword := c.Auth.PasswordLengthLimits()
				if len(body.NewPassword) < minPassword {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodePasswordTooShort))
					return
				}
				if len(body.NewPassword) > maxPassword {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodePasswordTooLong))
					return
				}
				if err := c.Auth.ValidatePasswords(body.NewPassword); err != nil {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidPassword, err.Error()))
					return
				}
				hashedPassword, err := c.Auth.HashPassword(body.NewPassword)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				if err := c.Auth.SetCredentialPassword(c.R.Context(), user.ID, hashedPassword); err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
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

var _ = store.UserUpdate{}
