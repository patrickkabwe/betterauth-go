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
	"github.com/patrickkabwe/betterauth-go/types"
)

// PhoneNumberOptions configures SMS OTP sign-in.
type PhoneNumberOptions struct {
	SendOTP   func(ctx context.Context, phone, otp string) error
	ExpiresIn time.Duration
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
					OTP         string `json:"otp"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
					return
				}
				v, err := c.Auth.ConsumeVerification(c.R.Context(), constants.VerificationPhoneOTP+body.PhoneNumber)
				if err != nil || v.Value != body.OTP {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
			rt(http.MethodPost, "/sign-in/phone-number", func(c *auth.Context) {
				var body struct {
					PhoneNumber string `json:"phoneNumber"`
					OTP         string `json:"otp"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
					return
				}
				v, err := c.Auth.ConsumeVerification(c.R.Context(), constants.VerificationPhoneOTP+body.PhoneNumber)
				if err != nil || v.Value != body.OTP {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidOTP))
					return
				}
				user, err := c.Auth.FindUserByAdditional(c.R.Context(), constants.FieldPhoneNumber, body.PhoneNumber)
				if err != nil {
					now := time.Now()
					userID, _ := id.Generate(32)
					email := fmt.Sprintf("%s@%s", body.PhoneNumber, constants.DomainPhone)
					user = &types.User{
						ID: userID, Name: body.PhoneNumber, Email: email,
						CreatedAt: now, UpdatedAt: now,
						Additional: map[string]any{
							constants.FieldPhoneNumber:   body.PhoneNumber,
							constants.FieldPhoneVerified: true,
						},
					}
					_ = c.Auth.Store().CreateUser(c.R.Context(), user)
				}
				sess, err := c.Auth.NewSession(c, user.ID, true)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeFailedToCreateSession))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]any{"token": sess.Token, "user": user})
			}),
			rt(http.MethodPost, "/phone-number/request-password-reset", func(c *auth.Context) {
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
			rt(http.MethodPost, "/phone-number/reset-password", func(c *auth.Context) {
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
		},
	}
}

var _ = store.UserUpdate{}
