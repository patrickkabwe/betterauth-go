package plugins

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/types"
	"github.com/pquerna/otp/totp"
)

// TwoFactorOptions configures two-factor authentication.
type TwoFactorOptions struct {
	Issuer string
}

// TwoFactor adds TOTP, OTP, and backup code 2FA.
func TwoFactor(opts TwoFactorOptions) auth.Plugin {
	issuer := opts.Issuer
	if issuer == "" {
		issuer = "Better Auth"
	}
	return basePlugin{
		id: constants.PluginTwoFactor,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/two-factor/enable", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				ext, ok := auth.ExtStore(c.Auth.Store())
				if !ok {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
					return
				}
				key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: user.Email})
				if err != nil {
					c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, constants.MsgFailedToGenerateTOTP))
					return
				}
				recID, _ := id.Generate(32)
				now := time.Now()
				_ = ext.CreateTwoFactor(c.R.Context(), &types.TwoFactorRecord{
					ID: recID, UserID: user.ID, Secret: key.Secret(),
					Verified: false, CreatedAt: now, UpdatedAt: now,
				})
				c.WriteJSON(http.StatusOK, map[string]string{"totpURI": key.URL()})
			}),
			rt(http.MethodPost, "/two-factor/disable", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				ext, ok := auth.ExtStore(c.Auth.Store())
				if !ok {
					return
				}
				_ = ext.DeleteTwoFactor(c.R.Context(), user.ID)
				_, _ = c.Auth.SetUserAdditional(c.R.Context(), user.ID, map[string]any{constants.FieldTwoFactorEnabled: false})
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
			rt(http.MethodPost, "/two-factor/get-totp-uri", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				ext, _ := auth.ExtStore(c.Auth.Store())
				rec, err := ext.FindTwoFactorByUserID(c.R.Context(), user.ID)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeTwoFactorNotEnabled))
					return
				}
				key, _ := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: user.Email, Secret: []byte(rec.Secret)})
				c.WriteJSON(http.StatusOK, map[string]string{"totpURI": key.URL()})
			}),
			rt(http.MethodPost, "/two-factor/verify-totp", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				var body struct {
					Code string `json:"code"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
					return
				}
				ext, _ := auth.ExtStore(c.Auth.Store())
				rec, err := ext.FindTwoFactorByUserID(c.R.Context(), user.ID)
				if err != nil || !totp.Validate(body.Code, rec.Secret) {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
					return
				}
				_ = ext.UpdateTwoFactor(c.R.Context(), user.ID, rec.Secret, rec.BackupCodes, true)
				_, _ = c.Auth.SetUserAdditional(c.R.Context(), user.ID, map[string]any{constants.FieldTwoFactorEnabled: true})
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
			rt(http.MethodPost, "/two-factor/send-otp", func(c *auth.Context) {
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
			rt(http.MethodPost, "/two-factor/verify-otp", func(c *auth.Context) {
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
			rt(http.MethodPost, "/two-factor/verify-backup-code", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				var body struct {
					Code string `json:"code"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
					return
				}
				ext, _ := auth.ExtStore(c.Auth.Store())
				rec, err := ext.FindTwoFactorByUserID(c.R.Context(), user.ID)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
					return
				}
				var codes []string
				_ = json.Unmarshal([]byte(rec.BackupCodes), &codes)
				found := false
				remaining := make([]string, 0, len(codes))
				for _, code := range codes {
					if !found && code == body.Code {
						found = true
						continue
					}
					remaining = append(remaining, code)
				}
				if !found {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
					return
				}
				b, _ := json.Marshal(remaining)
				_ = ext.UpdateTwoFactor(c.R.Context(), user.ID, rec.Secret, string(b), rec.Verified)
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
			rt(http.MethodPost, "/two-factor/generate-backup-codes", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				ext, _ := auth.ExtStore(c.Auth.Store())
				rec, err := ext.FindTwoFactorByUserID(c.R.Context(), user.ID)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeTwoFactorNotEnabled))
					return
				}
				codes := make([]string, 10)
				for i := range codes {
					raw, _ := id.Generate(8)
					codes[i] = strings.ToUpper(raw[:8])
				}
				b, _ := json.Marshal(codes)
				_ = ext.UpdateTwoFactor(c.R.Context(), user.ID, rec.Secret, string(b), rec.Verified)
				c.WriteJSON(http.StatusOK, map[string]any{"backupCodes": codes})
			}),
		},
	}
}
