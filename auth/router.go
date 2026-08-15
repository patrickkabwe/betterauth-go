package auth

import (
	"net/http"
	"strings"

	"github.com/patrickkabwe/betterauth-go/internal/apierror"
)

type route struct {
	method  string
	pattern string
	handler func(*Context)
}

// route table; patterns may include {param} segments.
var routeTable = []route{
	{http.MethodGet, "/ok", handleOK},
	{http.MethodGet, "/client-schema", handleClientSchema},
	{http.MethodGet, "/get-session", handleGetSession},
	{http.MethodPost, "/get-session", handleGetSession},
	{http.MethodGet, "/list-sessions", handleListSessions},
	{http.MethodGet, "/list-accounts", handleListAccounts},
	{http.MethodGet, "/account-info", handleAccountInfo},
	{http.MethodGet, "/verify-email", handleVerifyEmail},
	{http.MethodGet, "/error", handleErrorPage},
	{http.MethodGet, "/reset-password/{token}", handleResetPasswordCallback},
	{http.MethodGet, "/delete-user/callback", handleDeleteUserCallback},
	{http.MethodGet, "/callback/{provider}", handleOAuthCallback},
	{http.MethodPost, "/callback/{provider}", handleOAuthCallback},

	{http.MethodPost, "/sign-up/email", handleSignUpEmail},
	{http.MethodPost, "/sign-in/social", handleSignInSocial},
	{http.MethodPost, "/sign-in/email", handleSignInEmail},
	{http.MethodPost, "/sign-out", handleSignOut},
	{http.MethodPost, "/send-verification-email", handleSendVerificationEmail},
	{http.MethodPost, "/request-password-reset", handleRequestPasswordReset},
	{http.MethodPost, "/reset-password", handleResetPassword},
	{http.MethodPost, "/verify-password", handleVerifyPassword},
	{http.MethodPost, "/update-user", handleUpdateUser},
	{http.MethodPost, "/change-password", handleChangePassword},
	{http.MethodPost, "/change-email", handleChangeEmail},
	{http.MethodPost, "/set-password", handleSetPassword},
	{http.MethodPost, "/delete-user", handleDeleteUser},
	{http.MethodPost, "/update-session", handleUpdateSession},
	{http.MethodPost, "/revoke-session", handleRevokeSession},
	{http.MethodPost, "/revoke-sessions", handleRevokeSessions},
	{http.MethodPost, "/revoke-other-sessions", handleRevokeOtherSessions},
	{http.MethodPost, "/link-social", handleLinkSocial},
	{http.MethodPost, "/unlink-account", handleUnlinkAccount},
	{http.MethodPost, "/get-access-token", handleGetAccessToken},
	{http.MethodPost, "/refresh-token", handleRefreshToken},
}

func (a *Auth) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.setCORS(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		path := normalizePath(r.URL.Path)
		if a.cfg.skipTrailingSlashes && strings.HasSuffix(r.URL.Path, "/") && r.URL.Path != "/" {
			path = normalizePath(strings.TrimSuffix(r.URL.Path, "/"))
		}
		if a.cfg.disabledPaths[path] {
			http.NotFound(w, r)
			return
		}

		ctx := &Context{Auth: a, W: w, R: r}

		// Origin-based CSRF protection for state-changing requests.
		if !a.csrfAllowed(r) {
			ctx.WriteError(apierror.New(http.StatusForbidden, "INVALID_ORIGIN", "Request origin is not trusted."))
			return
		}

		// Rate limiting (writes 429 and returns false when exceeded).
		if !a.rateLimitAllow(ctx, path) {
			return
		}

		for _, rt := range a.routes {
			if rt.method != r.Method {
				continue
			}
			if vars, ok := matchPath(rt.pattern, path); ok {
				ctx.Vars = vars
				defer func() {
					runConfigAfterHook(ctx, a.cfg.hooks)
					runPluginAfterHooks(ctx, a.cfg.plugins)
				}()
				if !runConfigBeforeHook(ctx, a.cfg.hooks) || !runPluginBeforeHooks(ctx, a.cfg.plugins) {
					return
				}
				rt.handler(ctx)
				return
			}
		}
		http.NotFound(w, r)
	})
}

func normalizePath(path string) string {
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		return "/"
	}
	return path
}

func matchPath(pattern, path string) (map[string]string, bool) {
	pParts := strings.Split(strings.Trim(pattern, "/"), "/")
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	if pattern == "/" && path == "/" {
		return map[string]string{}, true
	}
	if len(pParts) != len(pathParts) {
		return nil, false
	}
	vars := make(map[string]string)
	for i, p := range pParts {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			vars[p[1:len(p)-1]] = pathParts[i]
			continue
		}
		if p != pathParts[i] {
			return nil, false
		}
	}
	return vars, true
}

func (a *Auth) setCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	hasTrusted := len(a.cfg.trustedOrigins) > 0 || len(a.cfg.trustedOriginPatterns) > 0
	if hasTrusted && !a.isTrustedOrigin(origin) {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
	w.Header().Set("Access-Control-Expose-Headers", "set-auth-token")
	w.Header().Add("Vary", "Origin")
}
