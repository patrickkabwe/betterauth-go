package plugins

import (
	"net/http"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/oauthcrypto"
	"github.com/patrickkabwe/betterauth-go/store"
)

func oauthClientMayIntrospect(c *auth.Context, ext store.ExtStore, clientID, issuerClientID string, resources []string) bool {
	if clientID == issuerClientID {
		return true
	}
	for _, r := range resources {
		if linked, _ := ext.IsOAuthClientLinkedToResource(c.R.Context(), clientID, r); linked {
			return true
		}
	}
	return false
}

// oidcIntrospectHandler implements RFC 7662 token introspection for opaque
// access and refresh tokens.
func oidcIntrospectHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthStore(c)
		if !ok {
			return
		}
		var body struct {
			Token               string `json:"token"`
			TokenTypeHint       string `json:"token_type_hint"`
			ClientID            string `json:"client_id"`
			ClientSecret        string `json:"client_secret"`
			ClientAssertion     string `json:"client_assertion"`
			ClientAssertionType string `json:"client_assertion_type"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Token == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
			return
		}
		client, ok := resolveOAuthClient(c, ext, body.ClientID, body.ClientSecret, body.ClientAssertion, body.ClientAssertionType)
		if !ok {
			return
		}
		inactive := map[string]any{"active": false}
		now := time.Now().UTC()
		iss := c.Auth.BaseURL()

		// RFC 9068 JWT access tokens are self-contained: verify the signature
		// and surface the claims (revocation state cannot be checked).
		if oauthcrypto.LooksLikeJWT(body.Token) {
			key, keyOK := oauthVerifyKey(c, ext)
			if !keyOK {
				c.WriteJSON(http.StatusOK, inactive)
				return
			}
			claims, err := oauthcrypto.ParseAccessToken(body.Token, key.Public())
			if err != nil {
				c.WriteJSON(http.StatusOK, inactive)
				return
			}
			issuerClient, _ := claims["client_id"].(string)
			var resources []string
			if aud, ok := claims["aud"].([]any); ok {
				for _, a := range aud {
					if s, ok := a.(string); ok {
						resources = append(resources, s)
					}
				}
			}
			if !oauthClientMayIntrospect(c, ext, client.ClientID, issuerClient, resources) {
				c.WriteJSON(http.StatusOK, inactive)
				return
			}
			tokenType := constants.TokenTypeBearer
			if _, ok := claims["cnf"]; ok {
				tokenType = "DPoP"
			}
			out := map[string]any{"active": true, "token_type": tokenType}
			for _, k := range []string{"iss", "sub", "client_id", "scope", "aud", "exp", "iat", "jti", "cnf"} {
				if v, ok := claims[k]; ok {
					out[k] = v
				}
			}
			c.WriteJSON(http.StatusOK, out)
			return
		}

		if body.TokenTypeHint != "refresh_token" {
			if at, err := ext.FindOAuthAccessToken(c.R.Context(), body.Token); err == nil {
				if at.Revoked != nil || at.ExpiresAt.Before(now) || !oauthClientMayIntrospect(c, ext, client.ClientID, at.ClientID, at.Resources) {
					c.WriteJSON(http.StatusOK, inactive)
					return
				}
				c.WriteJSON(http.StatusOK, map[string]any{
					"active": true, "iss": iss, "client_id": at.ClientID, "sub": at.UserID,
					"token_type": constants.TokenTypeBearer, "scope": strings.Join(at.Scopes, " "),
					"aud": at.Resources, "exp": at.ExpiresAt.Unix(), "iat": at.CreatedAt.Unix(),
				})
				return
			}
		}
		if rt, err := ext.FindOAuthRefreshToken(c.R.Context(), body.Token); err == nil {
			if rt.Revoked != nil || rt.ExpiresAt.Before(now) || !oauthClientMayIntrospect(c, ext, client.ClientID, rt.ClientID, rt.Resources) {
				c.WriteJSON(http.StatusOK, inactive)
				return
			}
			c.WriteJSON(http.StatusOK, map[string]any{
				"active": true, "iss": iss, "client_id": rt.ClientID, "sub": rt.UserID,
				"token_type": "refresh_token", "scope": strings.Join(rt.Scopes, " "),
				"aud": rt.Resources, "exp": rt.ExpiresAt.Unix(), "iat": rt.CreatedAt.Unix(),
			})
			return
		}
		c.WriteJSON(http.StatusOK, inactive)
	}
}

// oidcRevokeHandler implements RFC 7009 token revocation. Revoking an access
// token marks it revoked; revoking a refresh token tears down its whole family
// (and the access tokens linked to it). Unknown tokens still return 200.
func oidcRevokeHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthStore(c)
		if !ok {
			return
		}
		var body struct {
			Token               string `json:"token"`
			TokenTypeHint       string `json:"token_type_hint"`
			ClientID            string `json:"client_id"`
			ClientSecret        string `json:"client_secret"`
			ClientAssertion     string `json:"client_assertion"`
			ClientAssertionType string `json:"client_assertion_type"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Token == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
			return
		}
		client, ok := resolveOAuthClient(c, ext, body.ClientID, body.ClientSecret, body.ClientAssertion, body.ClientAssertionType)
		if !ok {
			return
		}
		// Only the issuing client may revoke; mismatches are ignored per RFC 7009.
		if body.TokenTypeHint != "refresh_token" {
			if at, err := ext.FindOAuthAccessToken(c.R.Context(), body.Token); err == nil {
				if at.ClientID == client.ClientID {
					_ = ext.RevokeOAuthAccessToken(c.R.Context(), body.Token)
				}
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
				return
			}
		}
		if rt, err := ext.FindOAuthRefreshToken(c.R.Context(), body.Token); err == nil {
			if rt.ClientID == client.ClientID {
				_ = ext.InvalidateOAuthRefreshFamily(c.R.Context(), rt.ClientID, rt.UserID)
			}
		}
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}
