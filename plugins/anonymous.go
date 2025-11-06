package plugins

import (
	"net/http"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/types"
)

// AnonymousOptions configures anonymous/guest sessions.
type AnonymousOptions struct {
	EmailDomainName string
}

// Anonymous allows guest sign-in without credentials.
func Anonymous(opts AnonymousOptions) auth.Plugin {
	domain := opts.EmailDomainName
	if domain == "" {
		domain = constants.DomainAnonymous
	}
	return basePlugin{
		id: constants.PluginAnonymous,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/sign-in/anonymous", func(c *auth.Context) {
				now := time.Now()
				userID, _ := id.Generate(32)
				emailID, _ := id.Generate(16)
				email := emailID + "@" + domain
				user := &types.User{
					ID: userID, Name: "Anonymous", Email: email,
					EmailVerified: false, CreatedAt: now, UpdatedAt: now,
					Additional: map[string]any{constants.FieldIsAnonymous: true},
				}
				if err := c.Auth.Store().CreateUser(c.R.Context(), user); err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeFailedToCreateUser))
					return
				}
				sess, err := c.Auth.NewSession(c, user.ID, true)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeFailedToCreateSession))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]any{
					"user":    user,
					"session": sess,
				})
			}),
			rt(http.MethodPost, "/delete-anonymous-user", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				if !auth.UserAdditionalBool(user, constants.FieldIsAnonymous) {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeNotAnonymous))
					return
				}
				_ = c.Auth.Store().DeleteUser(c.R.Context(), user.ID)
				c.Auth.ClearSessionCookie(c)
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
		},
	}
}
