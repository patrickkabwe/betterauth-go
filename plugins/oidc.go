package plugins

import (
	"net/http"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/types"
)

// OIDCProviderOptions configures acting as an OIDC identity provider.
type OIDCProviderOptions struct {
	LoginPage string
}

// OIDCProvider exposes OIDC provider endpoints.
func OIDCProvider(opts OIDCProviderOptions) auth.Plugin {
	return basePlugin{
		id: constants.PluginOIDCProvider,
		routes: []auth.PluginRoute{
			rt(http.MethodGet, "/.well-known/openid-configuration", oidcMetadataHandler()),
			rt(http.MethodGet, "/oauth2/authorize", oidcAuthorizeHandler(opts)),
			rt(http.MethodPost, "/oauth2/consent", oidcConsentHandler()),
			rt(http.MethodPost, "/oauth2/token", oidcTokenHandler()),
			rt(http.MethodGet, "/oauth2/userinfo", oidcUserInfoHandler()),
			rt(http.MethodPost, "/oauth2/register", oidcRegisterHandler()),
			rt(http.MethodGet, "/oauth2/client/{id}", oidcGetClientHandler()),
			rt(http.MethodGet, "/oauth2/endsession", oidcEndSessionHandler()),
			rt(http.MethodPost, "/oauth2/endsession", oidcEndSessionHandler()),
		},
	}
}

func oidcMetadataHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		base := c.Auth.BaseURL() + c.Auth.BasePath()
		c.WriteJSON(http.StatusOK, map[string]any{
			"issuer":                                c.Auth.BaseURL(),
			"authorization_endpoint":                base + "/oauth2/authorize",
			"token_endpoint":                        base + "/oauth2/token",
			"userinfo_endpoint":                     base + "/oauth2/userinfo",
			"registration_endpoint":                 base + "/oauth2/register",
			"end_session_endpoint":                  base + "/oauth2/endsession",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{constants.JWTAlgHS256},
		})
	}
}

func oidcAuthorizeHandler(opts OIDCProviderOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		_, user, ok := c.RequireSession()
		if !ok {
			login := opts.LoginPage
			if login == "" {
				login = "/"
			}
			c.Redirect(login)
			return
		}
		code, _ := id.Generate(32)
		clientID := c.R.URL.Query().Get("client_id")
		_ = c.Auth.CreateVerification(c.R.Context(), constants.VerificationOIDCCode+code, user.ID+"|"+clientID, 10*time.Minute)
		redirectURI := c.R.URL.Query().Get("redirect_uri")
		state := c.R.URL.Query().Get("state")
		c.Redirect(redirectURI + "?code=" + code + "&state=" + state)
	}
}

func oidcConsentHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func oidcTokenHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		var body struct {
			Code         string `json:"code"`
			GrantType    string `json:"grant_type"`
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidTokenRequest))
			return
		}
		v, err := c.Auth.ConsumeVerification(c.R.Context(), constants.VerificationOIDCCode+body.Code)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
			return
		}
		accessToken, _ := id.Generate(32)
		_ = c.Auth.CreateVerification(c.R.Context(), constants.VerificationOIDCAccess+accessToken, v.Value, time.Hour)
		c.WriteJSON(http.StatusOK, map[string]any{
			"access_token": accessToken,
			"token_type":   constants.TokenTypeBearer,
			"expires_in":   3600,
		})
	}
}

func oidcUserInfoHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		token := c.R.Header.Get(constants.HeaderAuthorization)
		bearerPrefix := constants.TokenTypeBearer + " "
		if len(token) > len(bearerPrefix) && strings.EqualFold(token[:len(bearerPrefix)], bearerPrefix) {
			token = token[len(bearerPrefix):]
		}
		v, err := c.Auth.Store().FindVerificationByIdentifier(c.R.Context(), constants.VerificationOIDCAccess+token)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeUnauthorized))
			return
		}
		userID := v.Value
		if idx := len(userID); idx > 0 {
			for i, ch := range userID {
				if ch == '|' {
					userID = userID[:i]
					break
				}
			}
		}
		user, err := c.Auth.Store().FindUserByID(c.R.Context(), userID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeUnauthorized))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]any{
			"sub": user.ID, "email": user.Email, "name": user.Name,
		})
	}
}

func oidcRegisterHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := auth.ExtStore(c.Auth.Store())
		if !ok {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
			return
		}
		var body struct {
			ClientName   string   `json:"client_name"`
			RedirectURIs []string `json:"redirect_uris"`
		}
		_ = c.ParseJSON(&body)
		clientID, _ := id.Generate(16)
		secret, _ := id.Generate(32)
		now := time.Now()
		redirects := ""
		for i, u := range body.RedirectURIs {
			if i > 0 {
				redirects += ","
			}
			redirects += u
		}
		_ = ext.CreateOAuthApp(c.R.Context(), &types.OAuthApplication{
			ID: clientID, ClientID: clientID, ClientSecret: secret, Name: body.ClientName,
			RedirectURLs: redirects, Type: constants.OAuthAppTypeWeb, CreatedAt: now, UpdatedAt: now,
		})
		c.WriteJSON(http.StatusOK, map[string]string{
			"client_id": clientID, "client_secret": secret,
		})
	}
}

func oidcGetClientHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := auth.ExtStore(c.Auth.Store())
		if !ok {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
			return
		}
		app, err := ext.FindOAuthAppByClientID(c.R.Context(), c.Vars["id"])
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeClientNotFound))
			return
		}
		c.WriteJSON(http.StatusOK, app)
	}
}

func oidcEndSessionHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		c.Auth.ClearSessionCookie(c)
		postLogout := c.R.URL.Query().Get("post_logout_redirect_uri")
		if postLogout != "" {
			c.Redirect(postLogout)
			return
		}
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}
