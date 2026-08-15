package auth

import (
	"encoding/json"
	constants "github.com/patrickkabwe/betterauth-go/constants"
	"net/http"
	"time"

	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/cookie"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

func handleGetSession(c *Context) {
	c.W.Header().Set("cache-control", "no-store")
	c.W.Header().Set("pragma", "no-cache")
	if c.R.Method == http.MethodPost && !c.Auth.cfg.deferSessionRefresh {
		c.WriteError(apierror.WithCode(http.StatusMethodNotAllowed, apierror.CodeMethodNotAllowed))
		return
	}

	opts := parseSessionOpts(c.R)
	isPost := c.R.Method == http.MethodPost
	resolved, ok := c.Auth.resolveSession(c, opts, isPost)
	if !ok {
		c.WriteNull()
		return
	}
	if resolved.RefreshFailed {
		c.WriteError(apierror.WithCode(http.StatusUnauthorized, apierror.CodeFailedToGetSession))
		return
	}

	resp := types.SessionResponse{
		Session: toSessionResponse(resolved.Session),
		User:    toUserResponse(resolved.User),
	}
	if resolved.NeedsRefresh {
		resp.NeedsRefresh = true
	}

	if isPost && resolved.NeedsRefresh && c.Auth.shouldRefresh(c, resolved.Session, opts) {
		refreshed, err := c.Auth.refreshSession(c, resolved.Session)
		if err != nil {
			cookie.DeleteSessionCookies(c.W, c.Auth.cfg.cookie)
			c.WriteError(apierror.WithCode(http.StatusUnauthorized, apierror.CodeFailedToGetSession))
			return
		}
		resp.Session = toSessionResponse(refreshed)
		c.Auth.setSessionCache(c, refreshed, resolved.User)
		resp.NeedsRefresh = false
	}

	c.WriteJSON(http.StatusOK, resp)
}

func handleListSessions(c *Context) {
	sess, _, ok := c.requireFreshSession(SessionOpts{DisableCookieCache: true})
	if !ok {
		return
	}
	sessions, err := c.Auth.cfg.store.ListSessionsByUserID(c.R.Context(), sess.UserID)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	now := time.Now()
	active := make([]types.Session, 0, len(sessions))
	for _, s := range sessions {
		if s.ExpiresAt.After(now) {
			active = append(active, s)
		}
	}
	c.WriteJSON(http.StatusOK, active)
}

func handleUpdateSession(c *Context) {
	sess, user, ok := c.requireSessionWithOpts(SessionOpts{})
	if !ok {
		return
	}

	var body map[string]json.RawMessage
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeBodyMustBeAnObject, constants.MsgInvalidRequestBody))
		return
	}

	update := store.SessionUpdate{UpdatedAt: ptrTime(time.Now())}
	if raw, ok := body["ipAddress"]; ok {
		var ip string
		_ = json.Unmarshal(raw, &ip)
		update.IPAddress = &ip
	}
	if raw, ok := body["userAgent"]; ok {
		var ua string
		_ = json.Unmarshal(raw, &ua)
		update.UserAgent = &ua
	}

	if update.IPAddress == nil && update.UserAgent == nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeBodyMustBeAnObject, constants.MsgNoFieldsToUpdate))
		return
	}

	updated, err := c.Auth.cfg.store.UpdateSession(c.R.Context(), sess.Token, update)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	c.Auth.setSessionCache(c, updated, user)
	c.WriteJSON(http.StatusOK, types.UpdateSessionResponse{
		Session: toSessionResponse(updated),
	})
}

type revokeSessionBody struct {
	Token string `json:"token"`
}

func handleRevokeSession(c *Context) {
	sess, _, ok := c.requireSessionWithOpts(SessionOpts{DisableCookieCache: true})
	if !ok {
		return
	}
	var body revokeSessionBody
	if err := c.ParseJSON(&body); err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, apierror.CodeInvalidEmail, constants.MsgInvalidRequestBody))
		return
	}
	target, user, err := c.Auth.cfg.store.FindSessionByToken(c.R.Context(), body.Token)
	if err == nil && user.ID == sess.UserID {
		if err := c.Auth.cfg.store.DeleteSession(c.R.Context(), target.Token); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
			return
		}
	}
	c.WriteJSON(http.StatusOK, types.StatusResponse{Status: true})
}

func handleRevokeSessions(c *Context) {
	sess, _, ok := c.requireSessionWithOpts(SessionOpts{DisableCookieCache: true})
	if !ok {
		return
	}
	if err := c.Auth.cfg.store.DeleteAllSessionsByUserID(c.R.Context(), sess.UserID); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	cookie.DeleteSessionCookies(c.W, c.Auth.cfg.cookie)
	c.WriteJSON(http.StatusOK, types.StatusResponse{Status: true})
}

func handleRevokeOtherSessions(c *Context) {
	sess, _, ok := c.requireSessionWithOpts(SessionOpts{DisableCookieCache: true})
	if !ok {
		return
	}
	if err := c.Auth.cfg.store.DeleteSessionsByUserID(c.R.Context(), sess.UserID, sess.Token); err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, apierror.CodeInternalServerError))
		return
	}
	c.WriteJSON(http.StatusOK, types.StatusResponse{Status: true})
}

func ptrTime(t time.Time) *time.Time { return &t }
