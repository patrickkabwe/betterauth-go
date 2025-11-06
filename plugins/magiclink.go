package plugins

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

// MagicLinkOptions configures magic link sign-in.
type MagicLinkOptions struct {
	SendMagicLink func(ctx context.Context, email, link, token string) error
	ExpiresIn     time.Duration
	DisableSignUp bool
}

// MagicLink adds passwordless email link authentication.
func MagicLink(opts MagicLinkOptions) auth.Plugin {
	expires := opts.ExpiresIn
	if expires == 0 {
		expires = 5 * time.Minute
	}
	return basePlugin{
		id: constants.PluginMagicLink,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/sign-in/magic-link", func(c *auth.Context) {
				if opts.SendMagicLink == nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeMagicLinkDisabled))
					return
				}
				var body struct {
					Email              string `json:"email"`
					Name               string `json:"name"`
					CallbackURL        string `json:"callbackURL"`
					NewUserCallbackURL string `json:"newUserCallbackURL"`
					ErrorCallbackURL   string `json:"errorCallbackURL"`
				}
				if err := c.ParseJSON(&body); err != nil || body.Email == "" {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidEmail))
					return
				}
				token, _ := id.Generate(32)
				payload, _ := auth.MarshalVerificationPayload(map[string]string{
					"email": auth.NormalizeEmail(body.Email),
					"name":  body.Name,
				})
				_ = c.Auth.CreateVerification(c.R.Context(), token, payload, expires)
				verifyURL := c.Auth.BaseURL() + c.Auth.BasePath() + "/magic-link/verify?token=" + url.QueryEscape(token)
				if body.CallbackURL != "" {
					verifyURL += "&callbackURL=" + url.QueryEscape(body.CallbackURL)
				}
				if body.NewUserCallbackURL != "" {
					verifyURL += "&newUserCallbackURL=" + url.QueryEscape(body.NewUserCallbackURL)
				}
				if body.ErrorCallbackURL != "" {
					verifyURL += "&errorCallbackURL=" + url.QueryEscape(body.ErrorCallbackURL)
				}
				_ = opts.SendMagicLink(c.R.Context(), body.Email, verifyURL, token)
				c.WriteJSON(http.StatusOK, map[string]bool{"status": true})
			}),
			rt(http.MethodGet, "/magic-link/verify", func(c *auth.Context) {
				token := c.R.URL.Query().Get("token")
				callbackURL := c.R.URL.Query().Get("callbackURL")
				if callbackURL == "" {
					callbackURL = "/"
				}
				errorURL := c.R.URL.Query().Get("errorCallbackURL")
				if errorURL == "" {
					errorURL = callbackURL
				}
				newUserURL := c.R.URL.Query().Get("newUserCallbackURL")
				if newUserURL == "" {
					newUserURL = callbackURL
				}
				v, err := c.Auth.ConsumeVerification(c.R.Context(), token)
				if err != nil {
					c.Redirect(errorURL + "?error=INVALID_TOKEN")
					return
				}
				var data struct {
					Email string `json:"email"`
					Name  string `json:"name"`
				}
				_ = auth.VerificationPayload(v, &data)
				user, err := c.Auth.Store().FindUserByEmail(c.R.Context(), data.Email)
				isNew := false
				if err != nil {
					if opts.DisableSignUp {
						c.Redirect(errorURL + "?error=new_user_signup_disabled")
						return
					}
					now := time.Now()
					userID, _ := id.Generate(32)
					user = &types.User{
						ID: userID, Name: data.Name, Email: data.Email,
						EmailVerified: true, CreatedAt: now, UpdatedAt: now,
					}
					if err := c.Auth.Store().CreateUser(c.R.Context(), user); err != nil {
						c.Redirect(errorURL + "?error=failed_to_create_user")
						return
					}
					isNew = true
				} else if !user.EmailVerified {
					verified := true
					user, _ = c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{EmailVerified: &verified})
				}
				sess, err := c.Auth.NewSession(c, user.ID, true)
				if err != nil {
					c.Redirect(errorURL + "?error=failed_to_create_session")
					return
				}
				if c.R.Header.Get(constants.HeaderAccept) == constants.MIMEJSON || c.R.URL.Query().Get("json") == "true" {
					c.WriteJSON(http.StatusOK, map[string]any{
						"token":   sess.Token,
						"user":    user,
						"session": sess,
					})
					return
				}
				if isNew {
					c.Redirect(newUserURL)
					return
				}
				c.Redirect(callbackURL)
			}),
		},
	}
}

// unused import guard
var _ = strings.TrimSpace
