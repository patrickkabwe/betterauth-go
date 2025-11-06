package plugins

import (
	"net/http"
	"net/url"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
)

// GenericOAuthProviderConfig configures a custom OAuth2/OIDC provider.
type GenericOAuthProviderConfig struct {
	ProviderID       string
	ClientID         string
	ClientSecret     string
	AuthorizationURL string
	TokenURL         string
	UserInfoURL      string
	Scopes           []string
}

// GenericOAuthOptions configures the generic OAuth plugin.
type GenericOAuthOptions struct {
	Providers []GenericOAuthProviderConfig
}

// GenericOAuth adds custom OIDC/OAuth2 providers.
func GenericOAuth(opts GenericOAuthOptions) auth.Plugin {
	providers := make(map[string]GenericOAuthProviderConfig)
	for _, p := range opts.Providers {
		providers[p.ProviderID] = p
	}
	return basePlugin{
		id: constants.PluginGenericOAuth,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/sign-in/oauth2", func(c *auth.Context) {
				var body struct {
					ProviderID  string `json:"providerId"`
					CallbackURL string `json:"callbackURL"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				p, ok := providers[body.ProviderID]
				if !ok {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeProviderNotFound))
					return
				}
				state, _ := id.Generate(32)
				_ = c.Auth.CreateVerification(c.R.Context(), constants.VerificationOAuth2State+state, body.ProviderID+"|"+body.CallbackURL, 10*time.Minute)
				q := url.Values{
					"client_id":     {p.ClientID},
					"response_type": {"code"},
					"redirect_uri":  {c.Auth.BaseURL() + c.Auth.BasePath() + "/oauth2/callback/" + p.ProviderID},
					"scope":         {joinScopes(p.Scopes)},
					"state":         {state},
				}
				redirectURL := p.AuthorizationURL + "?" + q.Encode()
				c.WriteJSON(http.StatusOK, map[string]any{"url": redirectURL, "redirect": true})
			}),
			rt(http.MethodGet, "/oauth2/callback/{providerId}", func(c *auth.Context) {
				providerID := c.Vars["providerId"]
				code := c.R.URL.Query().Get("code")
				state := c.R.URL.Query().Get("state")
				if code == "" || state == "" {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOAuthError))
					return
				}
				v, err := c.Auth.ConsumeVerification(c.R.Context(), constants.VerificationOAuth2State+state)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidState))
					return
				}
				_ = v
				c.Redirect(c.Auth.BaseURL() + "?oauth=success&provider=" + providerID)
			}),
			rt(http.MethodPost, "/oauth2/link", func(c *auth.Context) {
				_, _, ok := c.RequireSession()
				if !ok {
					return
				}
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
		},
	}
}

func joinScopes(scopes []string) string {
	if len(scopes) == 0 {
		return "openid email profile"
	}
	out := ""
	for i, s := range scopes {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}
