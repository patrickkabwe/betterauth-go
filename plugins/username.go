package plugins

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.]+$`)

// UsernameOptions configures username sign-in.
type UsernameOptions struct {
	MinUsernameLength int
	MaxUsernameLength int
}

// Username adds username-based sign-in.
func Username(opts UsernameOptions) auth.Plugin {
	minLen := opts.MinUsernameLength
	if minLen == 0 {
		minLen = 3
	}
	maxLen := opts.MaxUsernameLength
	if maxLen == 0 {
		maxLen = 30
	}
	return basePlugin{
		id: constants.PluginUsername,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/is-username-available", func(c *auth.Context) {
				var body struct {
					Username string `json:"username"`
				}
				if err := c.ParseJSON(&body); err != nil || body.Username == "" {
					c.WriteError(apierror.WithCode(http.StatusUnprocessableEntity, constants.CodeInvalidUsername))
					return
				}
				if len(body.Username) < minLen || len(body.Username) > maxLen || !usernamePattern.MatchString(body.Username) {
					c.WriteError(apierror.WithCode(http.StatusUnprocessableEntity, constants.CodeInvalidUsername))
					return
				}
				_, err := c.Auth.FindUserByAdditional(c.R.Context(), constants.FieldUsername, strings.ToLower(body.Username))
				c.WriteJSON(http.StatusOK, map[string]bool{"available": err != nil})
			}),
			rt(http.MethodPost, "/sign-in/username", func(c *auth.Context) {
				var body struct {
					Username   string `json:"username"`
					Password   string `json:"password"`
					RememberMe *bool  `json:"rememberMe"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				if body.Username == "" || body.Password == "" {
					c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidEmailOrPassword, constants.MsgInvalidCredentials))
					return
				}
				if len(body.Username) < minLen || len(body.Username) > maxLen || !usernamePattern.MatchString(body.Username) {
					c.WriteError(apierror.WithCode(http.StatusUnprocessableEntity, constants.CodeInvalidUsername))
					return
				}
				username := strings.ToLower(body.Username)
				user, err := c.Auth.FindUserByAdditional(c.R.Context(), constants.FieldUsername, username)
				if err != nil {
					c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidEmailOrPassword, constants.MsgInvalidCredentials))
					return
				}
				account, err := c.Auth.Store().FindAccountByUserAndProvider(c.R.Context(), user.ID, constants.ProviderCredential)
				if err != nil || account.Password == "" {
					c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidEmailOrPassword, constants.MsgInvalidCredentials))
					return
				}
				ok, _ := c.Auth.VerifyPassword(account.Password, body.Password)
				if !ok {
					c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidEmailOrPassword, constants.MsgInvalidCredentials))
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
				c.WriteJSON(http.StatusOK, map[string]any{
					"redirect": false,
					"token":    sess.Token,
					"user":     user,
				})
			}),
		},
	}
}
