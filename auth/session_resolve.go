package auth

import (
	"net/http"
	"strconv"
	"time"

	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/cookie"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

// SessionOpts controls session resolution behavior (query params + middleware flags).
type SessionOpts struct {
	DisableCookieCache bool
	DisableRefresh     bool
}

func parseSessionOpts(r *http.Request) SessionOpts {
	q := r.URL.Query()
	disableCache, _ := strconv.ParseBool(q.Get("disableCookieCache"))
	disableRefresh, _ := strconv.ParseBool(q.Get("disableRefresh"))
	return SessionOpts{
		DisableCookieCache: disableCache,
		DisableRefresh:     disableRefresh,
	}
}

type resolvedSession struct {
	Session      *types.Session
	User         *types.User
	NeedsRefresh bool
}

func (a *Auth) setSessionCache(c *Context, sess *types.Session, user *types.User) {
	if !a.cfg.cookieCache.enabled || a.cfg.cookieCache.strategy != "compact" {
		return
	}
	dontRemember := cookie.IsDontRememberAny(c.R, a.cfg.cookie, a.cfg.secrets)
	maxAge := a.cfg.cookieCache.maxAge
	if dontRemember {
		maxAge = 0
	}
	encoded, err := cookie.EncodeSessionCache(a.cfg.secret, cookie.CachedSessionData{
		Session:   *sess,
		User:      *user,
		UpdatedAt: time.Now().UnixMilli(),
		Version:   a.cfg.cookieCache.version,
	}, maxAge)
	if err != nil {
		return
	}
	cookie.SetSessionDataCookie(c.W, a.cfg.cookie, encoded, maxAge)
}

func (a *Auth) sessionFromCache(c *Context, opts SessionOpts) (*resolvedSession, bool) {
	if !a.cfg.cookieCache.enabled || opts.DisableCookieCache || a.cfg.cookieCache.strategy != "compact" {
		return nil, false
	}
	raw, err := c.R.Cookie(a.cfg.cookie.SessionDataName())
	if err != nil || raw.Value == "" {
		return nil, false
	}
	cached, expiresAt, err := cookie.DecodeSessionCacheAny(raw.Value, a.cfg.secrets, a.cfg.cookieCache.version)
	if err != nil {
		cookie.DeleteSessionCookies(c.W, a.cfg.cookie)
		return nil, false
	}
	if expiresAt < time.Now().UnixMilli() || cached.Session.ExpiresAt.Before(time.Now()) {
		cookie.DeleteSessionCookies(c.W, a.cfg.cookie)
		return nil, false
	}
	sess := cached.Session
	user := cached.User
	return &resolvedSession{Session: &sess, User: &user}, true
}

func (a *Auth) shouldRefresh(c *Context, sess *types.Session, opts SessionOpts) bool {
	if a.cfg.disableSessionRefresh || opts.DisableRefresh {
		return false
	}
	if cookie.IsDontRememberAny(c.R, a.cfg.cookie, a.cfg.secrets) {
		return false
	}
	threshold := sess.ExpiresAt.Add(-a.cfg.sessionExpires).Add(a.cfg.sessionUpdateAge)
	return !time.Now().Before(threshold)
}

func (a *Auth) isSessionFresh(sess *types.Session) bool {
	if a.cfg.freshAgeDisabled {
		return true
	}
	return time.Since(sess.CreatedAt) < a.cfg.freshAge
}

func (a *Auth) refreshSession(c *Context, sess *types.Session) (*types.Session, error) {
	newExpiry := time.Now().Add(a.cfg.sessionExpires)
	now := time.Now()
	dontRemember := cookie.IsDontRememberAny(c.R, a.cfg.cookie, a.cfg.secrets)
	cookieMaxAge := a.cfg.sessionCookieAge
	if dontRemember {
		cookieMaxAge = 0
	}
	updated, err := a.cfg.store.UpdateSession(c.R.Context(), sess.Token, store.SessionUpdate{
		ExpiresAt: &newExpiry,
		UpdatedAt: &now,
		IPAddress: strPtr(c.ClientIP()),
		UserAgent: strPtr(c.R.Header.Get("User-Agent")),
	})
	if err != nil {
		return sess, err
	}
	cookie.SetSessionCookie(c.W, a.cfg.cookie, a.cfg.secret, sess.Token, cookieMaxAge, dontRemember)
	return updated, nil
}

func (a *Auth) resolveSession(c *Context, opts SessionOpts, isPost bool) (*resolvedSession, bool) {
	if cached, ok := a.sessionFromCache(c, opts); ok {
		needsRefresh := a.shouldRefresh(c, cached.Session, opts)
		if a.cfg.deferSessionRefresh && !isPost {
			a.setSessionCache(c, cached.Session, cached.User)
			return &resolvedSession{
				Session:      cached.Session,
				User:         cached.User,
				NeedsRefresh: needsRefresh,
			}, true
		}
		if !needsRefresh {
			a.setSessionCache(c, cached.Session, cached.User)
			return cached, true
		}
	}

	token, ok := c.SessionToken()
	if !ok {
		return nil, false
	}

	sess, user, err := a.cfg.store.FindSessionByToken(c.R.Context(), token)
	if err != nil {
		return nil, false
	}

	if time.Now().After(sess.ExpiresAt) {
		cookie.DeleteSessionCookies(c.W, a.cfg.cookie)
		if !a.cfg.deferSessionRefresh || isPost {
			_ = a.cfg.store.DeleteSession(c.R.Context(), sess.Token)
		}
		return nil, false
	}

	needsRefresh := a.shouldRefresh(c, sess, opts)

	if a.cfg.deferSessionRefresh && !isPost {
		a.setSessionCache(c, sess, user)
		return &resolvedSession{
			Session:      sess,
			User:         user,
			NeedsRefresh: needsRefresh,
		}, true
	}

	if needsRefresh {
		if refreshed, err := a.refreshSession(c, sess); err == nil {
			sess = refreshed
		}
	}
	a.setSessionCache(c, sess, user)

	return &resolvedSession{Session: sess, User: user}, true
}

func (c *Context) requireSessionWithOpts(opts SessionOpts) (*types.Session, *types.User, bool) {
	isPost := c.R.Method == http.MethodPost
	resolved, ok := c.Auth.resolveSession(c, opts, isPost)
	if !ok {
		c.WriteError(apierror.WithCode(http.StatusUnauthorized, apierror.CodeUnauthorized))
		return nil, nil, false
	}
	return resolved.Session, resolved.User, true
}

func (c *Context) requireFreshSession(opts SessionOpts) (*types.Session, *types.User, bool) {
	sess, user, ok := c.requireSessionWithOpts(opts)
	if !ok {
		return nil, nil, false
	}
	if !c.Auth.isSessionFresh(sess) {
		c.WriteError(apierror.WithCode(http.StatusForbidden, apierror.CodeSessionNotFresh))
		return nil, nil, false
	}
	return sess, user, true
}
