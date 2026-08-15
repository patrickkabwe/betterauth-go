package plugins

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	oauth2pkg "github.com/patrickkabwe/betterauth-go/internal/oauth2"
	"github.com/patrickkabwe/betterauth-go/provider"
)

// GenericOAuthProviderConfig configures a custom OAuth2/OIDC provider.
type GenericOAuthProviderConfig struct {
	ProviderID              string
	ClientID                string
	ClientSecret            string
	DiscoveryURL            string
	DiscoveryHeaders        map[string]string
	Issuer                  string
	RequireIssuerValidation bool
	AuthorizationURL        string
	TokenURL                string
	UserInfoURL             string
	RedirectURI             string
	Scopes                  []string
	ResponseType            string
	ResponseMode            string
	PKCE                    bool
	Prompt                  string
	AccessType              string
	AuthorizationURLParams  map[string]string
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
					ProviderID      string   `json:"providerId"`
					CallbackURL     string   `json:"callbackURL"`
					DisableRedirect bool     `json:"disableRedirect"`
					Scopes          []string `json:"scopes"`
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
				authorizationURL, err := genericOAuthSignInAuthorizationURL(c, p)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOAuthError))
					return
				}
				codeVerifier := ""
				if p.PKCE {
					codeVerifier, err = oauth2pkg.GenerateCodeVerifier()
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
				}
				state, _ := id.Generate(32)
				_ = c.Auth.CreateVerification(c.R.Context(), constants.VerificationOAuth2State+state, body.ProviderID+"|"+body.CallbackURL, 10*time.Minute)
				q := genericOAuthAuthorizationValues(c, p, state, genericOAuthSignInScopes(body.Scopes, p.Scopes), codeVerifier)
				redirectURL := provider.BuildAuthURL(authorizationURL, q)
				c.WriteJSON(http.StatusOK, map[string]any{"url": redirectURL, "redirect": !body.DisableRedirect})
			}),
			rt(http.MethodGet, "/oauth2/callback/{providerId}", func(c *auth.Context) {
				providerID := c.Vars["providerId"]
				query := c.R.URL.Query()
				if errorCode := query.Get("error"); errorCode != "" {
					redirectGenericOAuthError(c, genericOAuthDefaultErrorURL(c), errorCode, query.Get("error_description"))
					return
				}
				code := query.Get("code")
				if code == "" {
					redirectGenericOAuthError(c, genericOAuthDefaultErrorURL(c), "oAuth_code_missing", "")
					return
				}
				state := query.Get("state")
				if state == "" {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOAuthError))
					return
				}
				p, ok := providers[providerID]
				if !ok {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeProviderNotFound))
					return
				}
				v, err := c.Auth.ConsumeVerification(c.R.Context(), constants.VerificationOAuth2State+state)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidState))
					return
				}
				storedProviderID, callbackURL, ok := parseGenericOAuthStateValue(v.Value)
				if !ok || storedProviderID != providerID {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidState))
					return
				}
				if callbackURL == "" {
					callbackURL = c.Auth.BaseURL()
				}
				if !genericOAuthIssuerAllowed(c, p) {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOAuthError))
					return
				}
				c.Redirect(callbackURL)
			}),
			rt(http.MethodPost, "/oauth2/link", func(c *auth.Context) {
				var body struct {
					ProviderID       string   `json:"providerId"`
					CallbackURL      string   `json:"callbackURL"`
					Scopes           []string `json:"scopes"`
					ErrorCallbackURL string   `json:"errorCallbackURL"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
					return
				}
				_, _, ok := c.RequireSession()
				if !ok {
					return
				}
				p, ok := providers[body.ProviderID]
				if !ok {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeProviderNotFound))
					return
				}
				authorizationURL, err := genericOAuthLinkAuthorizationURL(c, p)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeOAuthError))
					return
				}
				codeVerifier := ""
				if p.PKCE {
					codeVerifier, err = oauth2pkg.GenerateCodeVerifier()
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
						return
					}
				}
				state, _ := id.Generate(32)
				_ = c.Auth.CreateVerification(c.R.Context(), constants.VerificationOAuth2State+state, body.ProviderID+"|"+body.CallbackURL, 10*time.Minute)
				q := genericOAuthAuthorizationValues(c, p, state, genericOAuthLinkScopes(body.Scopes, p.Scopes), codeVerifier)
				redirectURL := provider.BuildAuthURL(authorizationURL, q)
				c.WriteJSON(http.StatusOK, map[string]any{"url": redirectURL, "redirect": true})
			}),
		},
	}
}

func genericOAuthSignInAuthorizationURL(c *auth.Context, p GenericOAuthProviderConfig) (string, error) {
	authorizationURL := p.AuthorizationURL
	tokenURL := p.TokenURL
	if p.DiscoveryURL != "" {
		discovery, err := genericOAuthDiscovery(c, p)
		if err != nil {
			return "", err
		}
		if discovery.AuthorizationEndpoint != "" {
			authorizationURL = discovery.AuthorizationEndpoint
		}
		if discovery.TokenEndpoint != "" {
			tokenURL = discovery.TokenEndpoint
		}
	}
	if authorizationURL == "" || tokenURL == "" {
		return "", fmt.Errorf("invalid generic oauth configuration for provider %q: authorizationURL=%q tokenURL=%q", p.ProviderID, authorizationURL, tokenURL)
	}
	return authorizationURL, nil
}

func genericOAuthLinkAuthorizationURL(c *auth.Context, p GenericOAuthProviderConfig) (string, error) {
	authorizationURL := p.AuthorizationURL
	if p.DiscoveryURL != "" {
		discovery, err := genericOAuthDiscovery(c, p)
		if err != nil {
			return "", err
		}
		if discovery.AuthorizationEndpoint != "" {
			authorizationURL = discovery.AuthorizationEndpoint
		}
	}
	if authorizationURL == "" {
		return "", fmt.Errorf("invalid generic oauth configuration for provider %q: authorizationURL=%q", p.ProviderID, authorizationURL)
	}
	return authorizationURL, nil
}

type genericOAuthDiscoveryDocument struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	Issuer                string `json:"issuer"`
}

func genericOAuthDiscovery(c *auth.Context, p GenericOAuthProviderConfig) (*genericOAuthDiscoveryDocument, error) {
	req, err := http.NewRequestWithContext(c.R.Context(), http.MethodGet, p.DiscoveryURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(constants.HeaderAccept, constants.MIMEJSON)
	for key, value := range p.DiscoveryHeaders {
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("generic oauth discovery failed for provider %q at %q with status %d: %s", p.ProviderID, p.DiscoveryURL, resp.StatusCode, string(body))
	}
	var discovery genericOAuthDiscoveryDocument
	if err := json.Unmarshal(body, &discovery); err != nil {
		return nil, err
	}
	return &discovery, nil
}

func genericOAuthIssuerAllowed(c *auth.Context, p GenericOAuthProviderConfig) bool {
	expectedIssuer, err := genericOAuthExpectedIssuer(c, p)
	if err != nil || expectedIssuer == "" {
		return err == nil && !p.RequireIssuerValidation
	}
	issuer := c.R.URL.Query().Get("iss")
	if issuer == "" {
		return !p.RequireIssuerValidation
	}
	return issuer == expectedIssuer
}

func genericOAuthExpectedIssuer(c *auth.Context, p GenericOAuthProviderConfig) (string, error) {
	if p.Issuer != "" {
		return p.Issuer, nil
	}
	if p.DiscoveryURL == "" {
		return "", nil
	}
	discovery, err := genericOAuthDiscovery(c, p)
	if err != nil {
		return "", err
	}
	return discovery.Issuer, nil
}

func parseGenericOAuthStateValue(value string) (string, string, bool) {
	providerID, callbackURL, ok := strings.Cut(value, "|")
	if !ok || providerID == "" {
		return "", "", false
	}
	return providerID, callbackURL, true
}

func genericOAuthDefaultErrorURL(c *auth.Context) string {
	return c.Auth.BaseURL() + c.Auth.BasePath() + "/error"
}

func redirectGenericOAuthError(c *auth.Context, errorURL string, code string, description string) {
	target := appendGenericOAuthQuery(errorURL, "error", code)
	if description != "" {
		target = appendGenericOAuthQuery(target, "error_description", description)
	}
	c.Redirect(target)
}

func appendGenericOAuthQuery(rawURL string, key string, value string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		separator := "?"
		if strings.Contains(rawURL, "?") {
			separator = "&"
		}
		return rawURL + separator + url.QueryEscape(key) + "=" + url.QueryEscape(value)
	}
	query := parsed.Query()
	query.Set(key, value)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func genericOAuthAuthorizationValues(c *auth.Context, p GenericOAuthProviderConfig, state string, scopes []string, codeVerifier string) url.Values {
	responseType := p.ResponseType
	if responseType == "" {
		responseType = "code"
	}
	q := url.Values{
		"client_id":     {p.ClientID},
		"response_type": {responseType},
		"redirect_uri":  {genericOAuthRedirectURI(c, p)},
		"scope":         {joinScopes(scopes)},
		"state":         {state},
	}
	if p.Prompt != "" {
		q.Set("prompt", p.Prompt)
	}
	if p.AccessType != "" {
		q.Set("access_type", p.AccessType)
	}
	if p.ResponseMode != "" {
		q.Set("response_mode", p.ResponseMode)
	}
	if codeVerifier != "" {
		q.Set("code_challenge_method", "S256")
		q.Set("code_challenge", oauth2pkg.CodeChallengeS256(codeVerifier))
	}
	for key, value := range p.AuthorizationURLParams {
		q.Set(key, value)
	}
	return q
}

func genericOAuthRedirectURI(c *auth.Context, p GenericOAuthProviderConfig) string {
	if p.RedirectURI != "" {
		return p.RedirectURI
	}
	return c.Auth.BaseURL() + c.Auth.BasePath() + "/oauth2/callback/" + p.ProviderID
}

func genericOAuthSignInScopes(requestScopes []string, configuredScopes []string) []string {
	if len(requestScopes) == 0 {
		return configuredScopes
	}
	scopes := make([]string, 0, len(requestScopes)+len(configuredScopes))
	scopes = append(scopes, requestScopes...)
	scopes = append(scopes, configuredScopes...)
	return scopes
}

func genericOAuthLinkScopes(requestScopes []string, configuredScopes []string) []string {
	if len(requestScopes) == 0 {
		return configuredScopes
	}
	return requestScopes
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
