package plugins

import (
	"net/http"
	"net/url"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/oauthcrypto"
)

func oidcEndSessionHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		param := func(k string) string {
			if v := c.R.URL.Query().Get(k); v != "" {
				return v
			}
			return c.R.PostFormValue(k)
		}
		clientID := param("client_id")
		postLogout := param("post_logout_redirect_uri")
		state := param("state")

		// Identify the client from id_token_hint when no client_id is given.
		if clientID == "" {
			if hint := param("id_token_hint"); hint != "" {
				if claims, err := oauthcrypto.UnverifiedClaims(hint); err == nil {
					clientID, _ = claims["aud"].(string)
					if clientID == "" {
						clientID, _ = claims["azp"].(string)
					}
				}
			}
		}

		c.Auth.ClearSessionCookie(c)

		if postLogout == "" {
			c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			return
		}

		// A post-logout redirect is honoured only when it is registered on an
		// enabled client that opted into end-session.
		ext, ok := auth.ExtStore(c.Auth.Store())
		if !ok || clientID == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRedirectURI, constants.MsgInvalidRedirectURI))
			return
		}
		client, err := ext.FindOAuthClientByClientID(c.R.Context(), clientID)
		if err != nil || client.Disabled || client.EnableEndSession == nil || !*client.EnableEndSession {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRedirectURI, constants.MsgInvalidRedirectURI))
			return
		}
		if !hasScope(client.PostLogoutRedirectURIs, postLogout) {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRedirectURI, "post_logout_redirect_uri is not registered"))
			return
		}
		target := postLogout
		if state != "" {
			if u, err := url.Parse(postLogout); err == nil {
				q := u.Query()
				q.Set("state", state)
				u.RawQuery = q.Encode()
				target = u.String()
			}
		}
		c.Redirect(target)
	}
}
