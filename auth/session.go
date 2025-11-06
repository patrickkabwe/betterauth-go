package auth

import (
	"time"

	"github.com/patrickkabwe/betterauth-go/internal/cookie"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/types"
)

func (a *Auth) createSession(c *Context, userID string, rememberMe bool) (*types.Session, error) {
	now := time.Now()
	dontRemember := !rememberMe

	expiresAt := now.Add(a.cfg.sessionExpires)
	cookieMaxAge := a.cfg.sessionCookieAge
	if dontRemember {
		expiresAt = now.Add(a.cfg.dontRememberAge)
		cookieMaxAge = 0
	}

	token, err := id.Generate(32)
	if err != nil {
		return nil, err
	}
	sessID, err := id.Generate(32)
	if err != nil {
		return nil, err
	}

	sess := &types.Session{
		ID:        sessID,
		Token:     token,
		UserID:    userID,
		ExpiresAt: expiresAt,
		IPAddress: c.ClientIP(),
		UserAgent: c.R.Header.Get("User-Agent"),
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := a.cfg.store.CreateSession(c.R.Context(), sess); err != nil {
		return nil, err
	}

	cookie.SetSessionCookie(c.W, a.cfg.cookie, a.cfg.secret, token, cookieMaxAge, dontRemember)
	c.MarkAuthToken(a.SignSessionToken(token))

	user, err := a.cfg.store.FindUserByID(c.R.Context(), userID)
	if err == nil {
		a.setSessionCache(c, sess, user)
	}

	return sess, nil
}

func strPtr(s string) *string { return &s }
