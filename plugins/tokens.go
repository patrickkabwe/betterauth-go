package plugins

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

// OneTimeTokenOptions configures single-use cross-domain tokens.
type OneTimeTokenOptions struct {
	ExpiresIn time.Duration
}

// OneTimeToken issues single-use tokens for cross-domain auth.
func OneTimeToken(opts OneTimeTokenOptions) auth.Plugin {
	expires := opts.ExpiresIn
	if expires == 0 {
		expires = time.Minute
	}
	return basePlugin{
		id: constants.PluginOneTimeToken,
		routes: []auth.PluginRoute{
			rt(http.MethodGet, "/one-time-token/generate", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				token, _ := id.Generate(32)
				_ = c.Auth.CreateVerification(c.R.Context(), constants.VerificationOneTimeToken+token, user.ID, expires)
				c.WriteJSON(http.StatusOK, map[string]string{"token": token})
			}),
			rt(http.MethodPost, "/one-time-token/verify", func(c *auth.Context) {
				var body struct {
					Token string `json:"token"`
				}
				if err := c.ParseJSON(&body); err != nil || body.Token == "" {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidToken))
					return
				}
				v, err := c.Auth.ConsumeVerification(c.R.Context(), constants.VerificationOneTimeToken+body.Token)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidToken))
					return
				}
				sess, err := c.Auth.NewSession(c, v.Value, true)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeFailedToCreateSession))
					return
				}
				user, _ := c.Auth.Store().FindUserByID(c.R.Context(), v.Value)
				c.WriteJSON(http.StatusOK, map[string]any{"session": sess, "user": user})
			}),
		},
	}
}

// JWTOptions configures JWT session tokens.
type JWTOptions struct {
	JWKSPath  string
	ExpiresIn time.Duration
}

// JWT exposes JWT tokens and JWKS endpoint.
func JWT(opts JWTOptions) auth.Plugin {
	jwksPath := opts.JWKSPath
	if jwksPath == "" {
		jwksPath = "/jwks"
	}
	expires := opts.ExpiresIn
	if expires == 0 {
		expires = time.Hour
	}
	return basePlugin{
		id: constants.PluginJWT,
		routes: []auth.PluginRoute{
			rt(http.MethodGet, jwksPath, func(c *auth.Context) {
				ext, ok := auth.ExtStore(c.Auth.Store())
				if !ok {
					c.WriteJSON(http.StatusOK, map[string]any{"keys": []any{}})
					return
				}
				keys, _ := ext.ListJWKS(c.R.Context())
				out := make([]map[string]string, 0, len(keys))
				for _, k := range keys {
					out = append(out, map[string]string{
						"kid": k.ID, "kty": constants.JWTKtyOct, "alg": constants.JWTAlgHS256, "k": k.PublicKey,
					})
				}
				if len(out) == 0 {
					kid, _ := id.Generate(8)
					pub := base64.RawURLEncoding.EncodeToString([]byte(c.Auth.BaseURL()))
					_ = ext.CreateJWKS(c.R.Context(), &types.JWKSRecord{
						ID: kid, PublicKey: pub, CreatedAt: time.Now(),
					})
					out = append(out, map[string]string{"kid": kid, "kty": constants.JWTKtyOct, "alg": constants.JWTAlgHS256, "k": pub})
				}
				c.WriteJSON(http.StatusOK, map[string]any{"keys": out})
			}),
			rt(http.MethodGet, "/token", func(c *auth.Context) {
				sess, user, ok := c.RequireSession()
				if !ok {
					return
				}
				token := signHS256JWT(c.Auth.BaseURL(), map[string]any{
					"sub":   user.ID,
					"email": user.Email,
					"sid":   sess.ID,
					"exp":   time.Now().Add(expires).Unix(),
					"iat":   time.Now().Unix(),
				})
				c.WriteJSON(http.StatusOK, map[string]string{"token": token})
			}),
		},
	}
}

func signHS256JWT(secret string, claims map[string]any) string {
	headerJSON := fmt.Sprintf(`{"alg":"%s","typ":"%s"}`, constants.JWTAlgHS256, constants.JWTTypeJWT)
	header := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	payload, _ := json.Marshal(claims)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(header + "." + encoded))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return header + "." + encoded + "." + sig
}

// MultiSessionOptions configures multiple device sessions.
type MultiSessionOptions struct {
	MaximumSessions int
}

// MultiSession manages multiple concurrent sessions per user.
func MultiSession(opts MultiSessionOptions) auth.Plugin {
	max := opts.MaximumSessions
	if max == 0 {
		max = 5
	}
	return basePlugin{
		id: constants.PluginMultiSession,
		routes: []auth.PluginRoute{
			rt(http.MethodGet, "/multi-session/list-device-sessions", func(c *auth.Context) {
				sess, _, ok := c.RequireSession()
				if !ok {
					return
				}
				sessions, _ := c.Auth.Store().ListSessionsByUserID(c.R.Context(), sess.UserID)
				c.WriteJSON(http.StatusOK, sessions)
			}),
			rt(http.MethodPost, "/multi-session/set-active", func(c *auth.Context) {
				sess, _, ok := c.RequireSession()
				if !ok {
					return
				}
				var body struct {
					Token string `json:"token"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidToken))
					return
				}
				target, user, err := c.Auth.Store().FindSessionByToken(c.R.Context(), body.Token)
				if err != nil || user.ID != sess.UserID {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidToken))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]any{"session": target})
			}),
			rt(http.MethodPost, "/multi-session/revoke", func(c *auth.Context) {
				sess, _, ok := c.RequireSession()
				if !ok {
					return
				}
				var body struct {
					Token string `json:"token"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidToken))
					return
				}
				target, user, err := c.Auth.Store().FindSessionByToken(c.R.Context(), body.Token)
				if err == nil && user.ID == sess.UserID {
					_ = c.Auth.Store().DeleteSession(c.R.Context(), target.Token)
				}
				// enforce max sessions
				sessions, _ := c.Auth.Store().ListSessionsByUserID(c.R.Context(), sess.UserID)
				if len(sessions) > max {
					for i := 0; i < len(sessions)-max; i++ {
						_ = c.Auth.Store().DeleteSession(c.R.Context(), sessions[i].Token)
					}
				}
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
		},
	}
}

var _ = store.UserUpdate{}
var _ = strings.TrimSpace
