package plugins

import (
	"net/http"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/types"
)

// MCPOptions configures Model Context Protocol auth endpoints.
type MCPOptions struct {
	ResourceIdentifier string
}

// MCP adds MCP OAuth discovery and token endpoints.
func MCP(opts MCPOptions) auth.Plugin {
	resource := opts.ResourceIdentifier
	if resource == "" {
		resource = "mcp"
	}
	oidc := OIDCProvider(OIDCProviderOptions{})
	oidcRoutes := oidc.Routes()
	routes := []auth.PluginRoute{
		rt(http.MethodGet, "/.well-known/oauth-authorization-server", func(c *auth.Context) {
			base := c.Auth.BaseURL() + c.Auth.BasePath()
			c.WriteJSON(http.StatusOK, map[string]any{
				"issuer":                 c.Auth.BaseURL(),
				"authorization_endpoint": base + "/mcp/authorize",
				"token_endpoint":         base + "/mcp/token",
				"registration_endpoint":  base + "/mcp/register",
			})
		}),
		rt(http.MethodGet, "/.well-known/oauth-protected-resource", func(c *auth.Context) {
			c.WriteJSON(http.StatusOK, map[string]any{
				"resource":             c.Auth.BaseURL() + "/" + resource,
				"authorization_server": c.Auth.BaseURL(),
			})
		}),
		rt(http.MethodGet, "/mcp/authorize", func(c *auth.Context) {
			_, user, ok := c.RequireSession()
			if !ok {
				c.Redirect("/")
				return
			}
			code, _ := id.Generate(32)
			_ = c.Auth.CreateVerification(c.R.Context(), constants.VerificationMCPCode+code, user.ID, 10*time.Minute)
			redirectURI := c.R.URL.Query().Get("redirect_uri")
			state := c.R.URL.Query().Get("state")
			c.Redirect(redirectURI + "?code=" + code + "&state=" + state)
		}),
		rt(http.MethodPost, "/mcp/token", func(c *auth.Context) {
			var body struct {
				Code      string `json:"code"`
				GrantType string `json:"grant_type"`
			}
			if err := c.ParseJSON(&body); err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
				return
			}
			v, err := c.Auth.ConsumeVerification(c.R.Context(), constants.VerificationMCPCode+body.Code)
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
				return
			}
			token, _ := id.Generate(32)
			_ = c.Auth.CreateVerification(c.R.Context(), constants.VerificationMCPAccess+token, v.Value, time.Hour)
			c.WriteJSON(http.StatusOK, map[string]any{
				"access_token": token, "token_type": constants.TokenTypeBearer, "expires_in": 3600,
			})
		}),
		rt(http.MethodPost, "/mcp/register", func(c *auth.Context) {
			ext, ok := auth.ExtStore(c.Auth.Store())
			if !ok {
				c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
				return
			}
			clientID, _ := id.Generate(16)
			secret, _ := id.Generate(32)
			now := time.Now()
			_ = ext.CreateOAuthApp(c.R.Context(), &types.OAuthApplication{
				ClientID: clientID, ClientSecret: secret, Name: "mcp-client",
				Type: constants.OAuthAppTypeMCP, CreatedAt: now,
			})
			c.WriteJSON(http.StatusOK, map[string]string{"client_id": clientID, "client_secret": secret})
		}),
		rt(http.MethodGet, "/mcp/get-session", func(c *auth.Context) {
			sess, user, err := c.GetSession()
			if err != nil {
				c.WriteNull()
				return
			}
			c.WriteJSON(http.StatusOK, map[string]any{"session": sess, "user": user})
		}),
	}
	// Include OIDC consent endpoint
	for _, r := range oidcRoutes {
		if r.Pattern == "/oauth2/consent" {
			routes = append(routes, r)
		}
	}
	return basePlugin{id: constants.PluginMCP, routes: routes}
}
