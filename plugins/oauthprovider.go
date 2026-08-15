package plugins

import (
	"net/http"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
)

// OAuthProviderOptions configures OAuth 2.0 provider endpoints.
type OAuthProviderOptions struct {
	LoginPage string
}

// OAuthProvider exposes the OAuth provider package surface using the OIDC provider implementation.
func OAuthProvider(opts OAuthProviderOptions) auth.Plugin {
	oidc := OIDCProvider(OIDCProviderOptions{LoginPage: opts.LoginPage})
	routes := append([]auth.PluginRoute{}, oidc.Routes()...)
	routes = append(routes, rt(http.MethodGet, "/.well-known/oauth-authorization-server", oauthProviderMetadataHandler()))
	return basePlugin{id: constants.PluginOAuthProvider, routes: routes, schemaIDs: []string{constants.PluginOIDCProvider}}
}

func oauthProviderMetadataHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		base := c.Auth.BaseURL() + c.Auth.BasePath()
		c.WriteJSON(http.StatusOK, map[string]any{
			"issuer":                                c.Auth.BaseURL(),
			"authorization_endpoint":                base + "/oauth2/authorize",
			"token_endpoint":                        base + "/oauth2/token",
			"userinfo_endpoint":                     base + "/oauth2/userinfo",
			"registration_endpoint":                 base + "/oauth2/register",
			"end_session_endpoint":                  base + "/oauth2/endsession",
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"response_types_supported":              []string{"code"},
			"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{constants.JWTAlgHS256},
		})
	}
}
