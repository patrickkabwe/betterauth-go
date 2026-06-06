package plugins

import (
	"net/http"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

// AdminOptions configures the admin plugin.
type AdminOptions struct {
	AdminRoles []string
}

func (o AdminOptions) isAdmin(role string) bool {
	roles := o.AdminRoles
	if len(roles) == 0 {
		roles = []string{constants.RoleAdmin}
	}
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

func requireAdmin(c *auth.Context, opts AdminOptions) (*types.User, bool) {
	_, user, ok := c.RequireSession()
	if !ok {
		return nil, false
	}
	role := auth.UserAdditionalString(user, constants.FieldRole)
	if role == "" {
		role = constants.RoleUser
	}
	if !opts.isAdmin(role) {
		c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeForbidden))
		return nil, false
	}
	return user, true
}

// Admin adds user management, roles, ban, and impersonation.
func Admin(opts AdminOptions) auth.Plugin {
	return basePlugin{
		id: constants.PluginAdmin,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/admin/set-role", func(c *auth.Context) {
				if _, ok := requireAdmin(c, opts); !ok {
					return
				}
				var body struct {
					UserID string `json:"userId"`
					Role   string `json:"role"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				user, _ := c.Auth.SetUserAdditional(c.R.Context(), body.UserID, map[string]any{constants.FieldRole: body.Role})
				c.WriteJSON(http.StatusOK, map[string]any{"user": user})
			}),
			rt(http.MethodGet, "/admin/get-user", func(c *auth.Context) {
				if _, ok := requireAdmin(c, opts); !ok {
					return
				}
				id := c.R.URL.Query().Get("id")
				user, err := c.Auth.Store().FindUserByID(c.R.Context(), id)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeUserNotFound))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]any{"user": user})
			}),
			rt(http.MethodPost, "/admin/create-user", func(c *auth.Context) {
				if _, ok := requireAdmin(c, opts); !ok {
					return
				}
				var body struct {
					Email    string `json:"email"`
					Password string `json:"password"`
					Name     string `json:"name"`
					Role     string `json:"role"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				now := time.Now()
				userID, _ := id.Generate(32)
				user := &types.User{
					ID: userID, Name: body.Name, Email: auth.NormalizeEmail(body.Email),
					EmailVerified: true, CreatedAt: now, UpdatedAt: now,
					Additional: map[string]any{constants.FieldRole: body.Role},
				}
				_ = c.Auth.Store().CreateUser(c.R.Context(), user)
				if body.Password != "" {
					hash, _ := c.Auth.HashPassword(body.Password)
					accID, _ := id.Generate(32)
					_ = c.Auth.Store().CreateAccount(c.R.Context(), &types.Account{
						ID: accID, AccountID: userID, ProviderID: constants.ProviderCredential,
						UserID: userID, Password: hash, CreatedAt: now, UpdatedAt: now,
					})
				}
				c.WriteJSON(http.StatusOK, map[string]any{"user": user})
			}),
			rt(http.MethodPost, "/admin/update-user", func(c *auth.Context) {
				if _, ok := requireAdmin(c, opts); !ok {
					return
				}
				var body struct {
					UserID string  `json:"userId"`
					Name   *string `json:"name"`
					Role   *string `json:"role"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				update := store.UserUpdate{Name: body.Name}
				if body.Role != nil {
					update.Additional = map[string]any{constants.FieldRole: *body.Role}
				}
				user, err := c.Auth.Store().UpdateUser(c.R.Context(), body.UserID, update)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeUserNotFound))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]any{"user": user})
			}),
			rt(http.MethodGet, "/admin/list-users", func(c *auth.Context) {
				if _, ok := requireAdmin(c, opts); !ok {
					return
				}
				search := c.R.URL.Query().Get("search")
				users, _ := c.Auth.Store().ListUsers(c.R.Context(), store.ListUsersOpts{Search: search, Limit: 100})
				c.WriteJSON(http.StatusOK, map[string]any{"users": users, "total": len(users)})
			}),
			rt(http.MethodPost, "/admin/list-user-sessions", func(c *auth.Context) {
				if _, ok := requireAdmin(c, opts); !ok {
					return
				}
				var body struct {
					UserID string `json:"userId"`
				}
				_ = c.ParseJSON(&body)
				sessions, _ := c.Auth.Store().ListSessionsByUserID(c.R.Context(), body.UserID)
				c.WriteJSON(http.StatusOK, sessions)
			}),
			rt(http.MethodPost, "/admin/unban-user", func(c *auth.Context) {
				if _, ok := requireAdmin(c, opts); !ok {
					return
				}
				var body struct {
					UserID string `json:"userId"`
				}
				_ = c.ParseJSON(&body)
				user, _ := c.Auth.SetUserAdditional(c.R.Context(), body.UserID, map[string]any{
					constants.FieldBanned: false, constants.FieldBanReason: "", constants.FieldBanExpires: nil,
				})
				c.WriteJSON(http.StatusOK, map[string]any{"user": user})
			}),
			rt(http.MethodPost, "/admin/ban-user", func(c *auth.Context) {
				if _, ok := requireAdmin(c, opts); !ok {
					return
				}
				var body struct {
					UserID     string `json:"userId"`
					BanReason  string `json:"banReason"`
					BanExpires *int64 `json:"banExpiresIn"`
				}
				_ = c.ParseJSON(&body)
				fields := map[string]any{constants.FieldBanned: true, constants.FieldBanReason: body.BanReason}
				user, _ := c.Auth.SetUserAdditional(c.R.Context(), body.UserID, fields)
				_ = c.Auth.Store().DeleteAllSessionsByUserID(c.R.Context(), body.UserID)
				c.WriteJSON(http.StatusOK, map[string]any{"user": user})
			}),
			rt(http.MethodPost, "/admin/impersonate-user", func(c *auth.Context) {
				adminUser, ok := requireAdmin(c, opts)
				if !ok {
					return
				}
				var body struct {
					UserID string `json:"userId"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				sess, err := c.Auth.NewSession(c, body.UserID, true)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeFailedToCreateSession))
					return
				}
				_, _ = c.Auth.SetSessionAdditional(c.R.Context(), sess.Token, map[string]any{
					constants.SessionImpersonatedBy: adminUser.ID,
				})
				user, _ := c.Auth.Store().FindUserByID(c.R.Context(), body.UserID)
				c.WriteJSON(http.StatusOK, map[string]any{"session": sess, "user": user})
			}),
			rt(http.MethodPost, "/admin/stop-impersonating", func(c *auth.Context) {
				sess, _, ok := c.RequireSession()
				if !ok {
					return
				}
				adminID, _ := auth.SessionAdditional(sess, constants.SessionImpersonatedBy)
				if adminID == nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeNotImpersonating))
					return
				}
				_ = c.Auth.Store().DeleteSession(c.R.Context(), sess.Token)
				newSess, err := c.Auth.NewSession(c, adminID.(string), true)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeFailedToCreateSession))
					return
				}
				user, _ := c.Auth.Store().FindUserByID(c.R.Context(), adminID.(string))
				c.WriteJSON(http.StatusOK, map[string]any{"session": newSess, "user": user})
			}),
			rt(http.MethodPost, "/admin/revoke-user-session", func(c *auth.Context) {
				if _, ok := requireAdmin(c, opts); !ok {
					return
				}
				var body struct {
					SessionToken string `json:"sessionToken"`
				}
				_ = c.ParseJSON(&body)
				_ = c.Auth.Store().DeleteSession(c.R.Context(), body.SessionToken)
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
			rt(http.MethodPost, "/admin/revoke-user-sessions", func(c *auth.Context) {
				if _, ok := requireAdmin(c, opts); !ok {
					return
				}
				var body struct {
					UserID string `json:"userId"`
				}
				_ = c.ParseJSON(&body)
				_ = c.Auth.Store().DeleteAllSessionsByUserID(c.R.Context(), body.UserID)
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
			rt(http.MethodPost, "/admin/remove-user", func(c *auth.Context) {
				if _, ok := requireAdmin(c, opts); !ok {
					return
				}
				var body struct {
					UserID string `json:"userId"`
				}
				_ = c.ParseJSON(&body)
				_ = c.Auth.Store().DeleteUser(c.R.Context(), body.UserID)
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
			rt(http.MethodPost, "/admin/set-user-password", func(c *auth.Context) {
				if _, ok := requireAdmin(c, opts); !ok {
					return
				}
				var body struct {
					UserID   string `json:"userId"`
					Password string `json:"password"`
				}
				_ = c.ParseJSON(&body)
				hash, _ := c.Auth.HashPassword(body.Password)
				_ = c.Auth.Store().UpdateAccountPassword(c.R.Context(), body.UserID, constants.ProviderCredential, hash)
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
			rt(http.MethodPost, "/admin/has-permission", func(c *auth.Context) {
				if _, ok := requireAdmin(c, opts); !ok {
					return
				}
				var body struct {
					Permission string `json:"permission"`
				}
				_ = c.ParseJSON(&body)
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
		},
	}
}

var _ = strings.TrimSpace
