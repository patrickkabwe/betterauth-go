package plugins

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/internal/jwt"
	oauth2pkg "github.com/patrickkabwe/betterauth-go/internal/oauth2"
	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
	dsig "github.com/russellhaering/goxmldsig"
)

const samlBindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

var errSSOOIDCProfileIncomplete = errors.New("oidc profile incomplete")

// SSOOptions configures enterprise SSO providers.
type SSOOptions struct {
	Providers []SSOProviderConfig
}

// SSOProviderConfig describes a static enterprise SSO provider.
type SSOProviderConfig struct {
	ProviderID     string        `json:"providerId"`
	Issuer         string        `json:"issuer"`
	Domain         string        `json:"domain"`
	OrganizationID string        `json:"organizationId,omitempty"`
	OIDCConfig     SSOOIDCConfig `json:"oidcConfig,omitempty"`
	SAMLConfig     SSOSAMLConfig `json:"samlConfig,omitempty"`
}

// SSOOIDCConfig stores OIDC endpoint settings for an SSO provider.
type SSOOIDCConfig struct {
	ClientID              string   `json:"clientId,omitempty"`
	ClientSecret          string   `json:"clientSecret,omitempty"`
	DiscoveryEndpoint     string   `json:"discoveryEndpoint,omitempty"`
	AuthorizationEndpoint string   `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string   `json:"tokenEndpoint,omitempty"`
	UserInfoEndpoint      string   `json:"userInfoEndpoint,omitempty"`
	Scopes                []string `json:"scopes,omitempty"`
}

// SSOSAMLConfig stores SAML SP/IdP settings for an SSO provider.
type SSOSAMLConfig struct {
	EntryPoint                    string            `json:"entryPoint"`
	Cert                          string            `json:"cert,omitempty"`
	CallbackURL                   string            `json:"callbackUrl,omitempty"`
	IDPInitiatedCallbackURL       string            `json:"idpInitiatedCallbackUrl,omitempty"`
	Audience                      string            `json:"audience,omitempty"`
	EntityID                      string            `json:"entityId,omitempty"`
	IdentifierFormat              string            `json:"identifierFormat,omitempty"`
	WantAssertionsSigned          bool              `json:"wantAssertionsSigned,omitempty"`
	AuthnRequestsSigned           bool              `json:"authnRequestsSigned,omitempty"`
	Mapping                       SSOSAMLMapping    `json:"mapping,omitempty"`
	AdditionalAuthorizationParams map[string]string `json:"additionalParams,omitempty"`
}

// SSOSAMLMapping maps SAML assertion fields to Better Auth user fields.
type SSOSAMLMapping struct {
	ID            string            `json:"id,omitempty"`
	Email         string            `json:"email,omitempty"`
	EmailVerified string            `json:"emailVerified,omitempty"`
	Name          string            `json:"name,omitempty"`
	FirstName     string            `json:"firstName,omitempty"`
	LastName      string            `json:"lastName,omitempty"`
	ExtraFields   map[string]string `json:"extraFields,omitempty"`
}

type ssoProviderPayload struct {
	ProviderID     string        `json:"providerId"`
	Issuer         string        `json:"issuer"`
	Domain         string        `json:"domain"`
	OrganizationID string        `json:"organizationId"`
	OIDCConfig     SSOOIDCConfig `json:"oidcConfig"`
	SAMLConfig     SSOSAMLConfig `json:"samlConfig"`
	DomainVerified *bool         `json:"domainVerified"`
}

type samlAssertionUser struct {
	ID            string
	Email         string
	Name          string
	EmailVerified bool
	Extra         map[string]any
}

type ssoOIDCStatePayload struct {
	ProviderID   string    `json:"providerId"`
	CallbackURL  string    `json:"callbackURL,omitempty"`
	CodeVerifier string    `json:"codeVerifier"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type ssoOIDCDiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

// SSO enables enterprise SSO provider management and SAML SP sign-in routes.
func SSO(opts SSOOptions) auth.Plugin {
	oidcCallbackHandler := func(c *auth.Context) {
		handleSSOOIDCCallback(c, opts)
	}
	return basePlugin{
		id: constants.PluginSSO,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/sso/register", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				ext, ok := requireSSOStore(c)
				if !ok {
					return
				}
				var body ssoProviderPayload
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
					return
				}
				provider, apiErr := ssoProviderFromPayload(body, user.ID)
				if apiErr != nil {
					c.WriteError(apiErr)
					return
				}
				if err := ext.CreateSSOProvider(c.R.Context(), provider); err != nil {
					status := http.StatusInternalServerError
					code := constants.CodeInternalServerError
					if errors.Is(err, berrors.ErrAlreadyExists) {
						status = http.StatusConflict
						code = constants.CodeInvalidRequest
					}
					c.WriteError(apierror.WithCode(status, code))
					return
				}
				c.WriteJSON(http.StatusOK, sanitizeSSOProvider(*provider))
			}),
			rt(http.MethodGet, "/sso/providers", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				ext, ok := requireSSOStore(c)
				if !ok {
					return
				}
				providers, err := ext.ListSSOProvidersByUserID(c.R.Context(), user.ID)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				out := make([]map[string]any, 0, len(providers)+len(opts.Providers))
				for _, provider := range providers {
					out = append(out, sanitizeSSOProvider(provider))
				}
				for _, provider := range opts.Providers {
					out = append(out, sanitizeSSOProvider(staticSSOProvider(provider)))
				}
				c.WriteJSON(http.StatusOK, out)
			}),
			rt(http.MethodGet, "/sso/get-provider", func(c *auth.Context) {
				providerID := c.R.URL.Query().Get("providerId")
				provider, ok := findSSOProvider(c, opts, providerID, "")
				if !ok {
					return
				}
				c.WriteJSON(http.StatusOK, sanitizeSSOProvider(provider))
			}),
			rt(http.MethodPost, "/sso/update-provider", func(c *auth.Context) {
				if _, _, ok := c.RequireSession(); !ok {
					return
				}
				ext, ok := requireSSOStore(c)
				if !ok {
					return
				}
				var body ssoProviderPayload
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
					return
				}
				update, apiErr := ssoProviderUpdateFromPayload(body)
				if apiErr != nil {
					c.WriteError(apiErr)
					return
				}
				provider, err := ext.UpdateSSOProvider(c.R.Context(), body.ProviderID, update)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeProviderNotFound))
					return
				}
				c.WriteJSON(http.StatusOK, sanitizeSSOProvider(*provider))
			}),
			rt(http.MethodPost, "/sso/delete-provider", func(c *auth.Context) {
				if _, _, ok := c.RequireSession(); !ok {
					return
				}
				ext, ok := requireSSOStore(c)
				if !ok {
					return
				}
				var body struct {
					ProviderID string `json:"providerId"`
				}
				if err := c.ParseJSON(&body); err != nil || body.ProviderID == "" {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
					return
				}
				if err := ext.DeleteSSOProvider(c.R.Context(), body.ProviderID); err != nil {
					c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeProviderNotFound))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
			rt(http.MethodPost, "/sign-in/sso", func(c *auth.Context) {
				var body struct {
					ProviderID  string `json:"providerId"`
					Domain      string `json:"domain"`
					CallbackURL string `json:"callbackURL"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
					return
				}
				provider, ok := findSSOProvider(c, opts, body.ProviderID, body.Domain)
				if !ok {
					return
				}
				samlConfig, ok := decodeSAMLConfig(provider.SAMLConfig)
				if ok {
					redirectURL, err := buildSAMLRedirectURL(c, provider, samlConfig, body.CallbackURL)
					if err != nil {
						c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, err.Error()))
						return
					}
					c.WriteJSON(http.StatusOK, map[string]any{"url": redirectURL, "redirect": true})
					return
				}
				oidcConfig, ok := decodeOIDCConfig(provider.OIDCConfig)
				if !ok {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeProviderNotSupported))
					return
				}
				redirectURL, err := buildSSOOIDCRedirectURL(c, provider, oidcConfig, body.CallbackURL)
				if err != nil {
					c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, err.Error()))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]any{"url": redirectURL, "redirect": true})
			}),
			rt(http.MethodGet, "/sso/oidc/callback/{providerId}", oidcCallbackHandler),
			rt(http.MethodPost, "/sso/oidc/callback/{providerId}", oidcCallbackHandler),
			rt(http.MethodGet, "/sso/saml2/sp/metadata", func(c *auth.Context) {
				provider, ok := findSSOProvider(c, opts, c.R.URL.Query().Get("providerId"), "")
				if !ok {
					return
				}
				samlConfig, ok := decodeSAMLConfig(provider.SAMLConfig)
				if !ok {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeProviderNotSupported))
					return
				}
				c.W.Header().Set(constants.HeaderContentType, "application/xml")
				c.W.WriteHeader(http.StatusOK)
				_, _ = c.W.Write([]byte(samlMetadataXML(c, provider, samlConfig)))
			}),
			rt(http.MethodPost, "/sso/saml2/sp/acs/{providerId}", func(c *auth.Context) {
				provider, ok := findSSOProvider(c, opts, c.Vars["providerId"], "")
				if !ok {
					return
				}
				samlConfig, ok := decodeSAMLConfig(provider.SAMLConfig)
				if !ok {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeProviderNotSupported))
					return
				}
				if err := c.R.ParseForm(); err != nil {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
					return
				}
				assertion, err := parseSAMLAssertion(c.R.PostForm.Get("SAMLResponse"), provider, samlConfig)
				if err != nil {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, err.Error()))
					return
				}
				user, sess, err := ssoSessionFromAssertion(c, provider, assertion)
				if err != nil {
					c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, err.Error()))
					return
				}
				relayState := c.R.PostForm.Get("RelayState")
				if relayState != "" {
					c.Redirect(relayState)
					return
				}
				c.WriteJSON(http.StatusOK, map[string]any{"user": user, "session": sess})
			}),
		},
	}
}

func requireSSOStore(c *auth.Context) (store.ExtStore, bool) {
	ext, ok := auth.ExtStore(c.Auth.Store())
	if !ok {
		c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, "SSO requires store.ExtStore"))
		return nil, false
	}
	return ext, true
}

func ssoProviderFromPayload(body ssoProviderPayload, userID string) (*types.SSOProvider, *apierror.Error) {
	if body.ProviderID == "" || body.Issuer == "" || body.Domain == "" {
		return nil, apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "providerId, issuer, and domain are required")
	}
	oidcConfig, samlConfig, apiErr := encodeSSOConfigs(body.OIDCConfig, body.SAMLConfig)
	if apiErr != nil {
		return nil, apiErr
	}
	now := time.Now().UTC()
	recordID, err := id.Generate(32)
	if err != nil {
		return nil, apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError)
	}
	domainVerified := false
	if body.DomainVerified != nil {
		domainVerified = *body.DomainVerified
	}
	return &types.SSOProvider{
		ID: recordID, ProviderID: body.ProviderID, Issuer: body.Issuer, Domain: strings.ToLower(body.Domain),
		OrganizationID: body.OrganizationID, UserID: userID, OIDCConfig: oidcConfig, SAMLConfig: samlConfig,
		DomainVerified: domainVerified, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func ssoProviderUpdateFromPayload(body ssoProviderPayload) (store.SSOProviderUpdate, *apierror.Error) {
	if body.ProviderID == "" {
		return store.SSOProviderUpdate{}, apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "providerId is required")
	}
	oidcConfig, samlConfig, apiErr := encodeSSOConfigs(body.OIDCConfig, body.SAMLConfig)
	if apiErr != nil {
		return store.SSOProviderUpdate{}, apiErr
	}
	now := time.Now().UTC()
	update := store.SSOProviderUpdate{UpdatedAt: &now}
	if body.Issuer != "" {
		update.Issuer = &body.Issuer
	}
	if body.Domain != "" {
		domain := strings.ToLower(body.Domain)
		update.Domain = &domain
	}
	if body.OrganizationID != "" {
		update.OrganizationID = &body.OrganizationID
	}
	if oidcConfig != "" {
		update.OIDCConfig = &oidcConfig
	}
	if samlConfig != "" {
		update.SAMLConfig = &samlConfig
	}
	if body.DomainVerified != nil {
		update.DomainVerified = body.DomainVerified
	}
	return update, nil
}

func encodeSSOConfigs(oidcConfig SSOOIDCConfig, samlConfig SSOSAMLConfig) (string, string, *apierror.Error) {
	hasOIDC := oidcConfig.ClientID != "" || oidcConfig.AuthorizationEndpoint != "" || oidcConfig.DiscoveryEndpoint != ""
	hasSAML := samlConfig.EntryPoint != "" || samlConfig.EntityID != "" || samlConfig.CallbackURL != ""
	if hasOIDC == hasSAML {
		return "", "", apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "exactly one of oidcConfig or samlConfig is required")
	}
	if hasOIDC {
		raw, err := json.Marshal(oidcConfig)
		if err != nil {
			return "", "", apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest)
		}
		return string(raw), "", nil
	}
	raw, err := json.Marshal(samlConfig)
	if err != nil {
		return "", "", apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest)
	}
	return "", string(raw), nil
}

func findSSOProvider(c *auth.Context, opts SSOOptions, providerID string, domain string) (types.SSOProvider, bool) {
	ext, hasStore := auth.ExtStore(c.Auth.Store())
	if providerID != "" && hasStore {
		provider, err := ext.FindSSOProviderByProviderID(c.R.Context(), providerID)
		if err == nil {
			return *provider, true
		}
	}
	if domain != "" && hasStore {
		provider, err := ext.FindSSOProviderByDomain(c.R.Context(), strings.ToLower(domain))
		if err == nil {
			return *provider, true
		}
	}
	for _, provider := range opts.Providers {
		if providerID != "" && provider.ProviderID == providerID {
			return staticSSOProvider(provider), true
		}
		if domain != "" && strings.EqualFold(provider.Domain, domain) {
			return staticSSOProvider(provider), true
		}
	}
	c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeProviderNotFound))
	return types.SSOProvider{}, false
}

func staticSSOProvider(provider SSOProviderConfig) types.SSOProvider {
	oidcConfig, samlConfig, _ := encodeSSOConfigs(provider.OIDCConfig, provider.SAMLConfig)
	now := time.Now().UTC()
	return types.SSOProvider{
		ID: provider.ProviderID, ProviderID: provider.ProviderID, Issuer: provider.Issuer, Domain: strings.ToLower(provider.Domain),
		OrganizationID: provider.OrganizationID, OIDCConfig: oidcConfig, SAMLConfig: samlConfig, DomainVerified: true,
		CreatedAt: now, UpdatedAt: now,
	}
}

func sanitizeSSOProvider(provider types.SSOProvider) map[string]any {
	out := map[string]any{
		"id":             provider.ID,
		"providerId":     provider.ProviderID,
		"issuer":         provider.Issuer,
		"domain":         provider.Domain,
		"organizationId": provider.OrganizationID,
		"domainVerified": provider.DomainVerified,
		"type":           "oidc",
	}
	if provider.SAMLConfig != "" {
		var samlConfig SSOSAMLConfig
		_ = json.Unmarshal([]byte(provider.SAMLConfig), &samlConfig)
		out["type"] = "saml"
		out["samlConfig"] = map[string]any{
			"entryPoint":           samlConfig.EntryPoint,
			"callbackUrl":          samlConfig.CallbackURL,
			"audience":             samlConfig.Audience,
			"entityId":             samlConfig.EntityID,
			"identifierFormat":     samlConfig.IdentifierFormat,
			"wantAssertionsSigned": samlConfig.WantAssertionsSigned,
			"authnRequestsSigned":  samlConfig.AuthnRequestsSigned,
		}
	}
	if provider.OIDCConfig != "" {
		var oidcConfig SSOOIDCConfig
		_ = json.Unmarshal([]byte(provider.OIDCConfig), &oidcConfig)
		out["oidcConfig"] = map[string]any{
			"clientId":              oidcConfig.ClientID,
			"discoveryEndpoint":     oidcConfig.DiscoveryEndpoint,
			"authorizationEndpoint": oidcConfig.AuthorizationEndpoint,
			"tokenEndpoint":         oidcConfig.TokenEndpoint,
			"userInfoEndpoint":      oidcConfig.UserInfoEndpoint,
			"scopes":                oidcConfig.Scopes,
		}
	}
	return out
}

func decodeSAMLConfig(raw string) (SSOSAMLConfig, bool) {
	if raw == "" {
		return SSOSAMLConfig{}, false
	}
	var cfg SSOSAMLConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil || cfg.EntryPoint == "" {
		return SSOSAMLConfig{}, false
	}
	return cfg, true
}

func decodeOIDCConfig(raw string) (SSOOIDCConfig, bool) {
	if raw == "" {
		return SSOOIDCConfig{}, false
	}
	var cfg SSOOIDCConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil || cfg.ClientID == "" {
		return SSOOIDCConfig{}, false
	}
	return cfg, true
}

func buildSSOOIDCRedirectURL(c *auth.Context, ssoProvider types.SSOProvider, cfg SSOOIDCConfig, callbackURL string) (string, error) {
	endpoints, err := ssoOIDCEndpoints(c, ssoProvider, cfg)
	if err != nil {
		return "", err
	}
	codeVerifier, err := oauth2pkg.GenerateCodeVerifier()
	if err != nil {
		return "", err
	}
	state, err := id.Generate(32)
	if err != nil {
		return "", err
	}
	payload := ssoOIDCStatePayload{
		ProviderID:   ssoProvider.ProviderID,
		CallbackURL:  callbackURL,
		CodeVerifier: codeVerifier,
		ExpiresAt:    time.Now().UTC().Add(10 * time.Minute),
	}
	value, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	if err := c.Auth.CreateVerification(c.R.Context(), constants.VerificationSSOOIDCState+state, string(value), 10*time.Minute); err != nil {
		return "", err
	}
	values := url.Values{}
	values.Set("client_id", cfg.ClientID)
	values.Set("response_type", "code")
	values.Set("redirect_uri", ssoOIDCRedirectURI(c, ssoProvider.ProviderID))
	values.Set("scope", ssoOIDCScopeString(cfg.Scopes))
	values.Set("state", state)
	values.Set("code_challenge", oauth2pkg.CodeChallengeS256(codeVerifier))
	values.Set("code_challenge_method", "S256")
	return endpoints.AuthorizationEndpoint + "?" + values.Encode(), nil
}

func handleSSOOIDCCallback(c *auth.Context, opts SSOOptions) {
	values, err := ssoOIDCCallbackValues(c)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
		return
	}
	if values.Get("error") != "" {
		c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeOAuthError, values.Get("error")))
		return
	}
	state := values.Get("state")
	code := values.Get("code")
	if state == "" || code == "" {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
		return
	}
	verification, err := c.Auth.ConsumeVerification(c.R.Context(), constants.VerificationSSOOIDCState+state)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeInvalidToken))
		return
	}
	var stateData ssoOIDCStatePayload
	if err := json.Unmarshal([]byte(verification.Value), &stateData); err != nil || stateData.ProviderID == "" || stateData.CodeVerifier == "" {
		c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeInvalidToken))
		return
	}
	providerID := c.Vars["providerId"]
	if providerID == "" {
		providerID = stateData.ProviderID
	}
	if providerID != stateData.ProviderID {
		c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeInvalidToken))
		return
	}
	ssoProvider, ok := findSSOProvider(c, opts, providerID, "")
	if !ok {
		return
	}
	cfg, ok := decodeOIDCConfig(ssoProvider.OIDCConfig)
	if !ok {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeProviderNotSupported))
		return
	}
	tokens, err := exchangeSSOOIDCCode(c, ssoProvider, cfg, code, stateData.CodeVerifier)
	if err != nil {
		c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeOAuthError, err.Error()))
		return
	}
	oidcUser, err := ssoOIDCUserInfo(c, ssoProvider, cfg, tokens)
	if err != nil {
		c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeFailedToGetUserInfo, err.Error()))
		return
	}
	user, sess, err := ssoSessionFromOIDCUser(c, ssoProvider, oidcUser, tokens)
	if err != nil {
		c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, err.Error()))
		return
	}
	if stateData.CallbackURL != "" {
		c.Redirect(stateData.CallbackURL)
		return
	}
	c.WriteJSON(http.StatusOK, map[string]any{"user": user, "session": sess})
}

func ssoOIDCCallbackValues(c *auth.Context) (url.Values, error) {
	if c.R.Method != http.MethodPost {
		return c.R.URL.Query(), nil
	}
	if err := c.R.ParseForm(); err != nil {
		return nil, err
	}
	values := url.Values{}
	for key, list := range c.R.Form {
		copied := make([]string, len(list))
		copy(copied, list)
		values[key] = copied
	}
	return values, nil
}

func exchangeSSOOIDCCode(c *auth.Context, ssoProvider types.SSOProvider, cfg SSOOIDCConfig, code string, codeVerifier string) (*provider.OAuthTokens, error) {
	endpoints, err := ssoOIDCEndpoints(c, ssoProvider, cfg)
	if err != nil {
		return nil, err
	}
	data, err := provider.ExchangeAuthorizationCode(c.R.Context(), provider.CodeExchangeOpts{
		TokenURL:       endpoints.TokenEndpoint,
		ClientID:       cfg.ClientID,
		ClientSecret:   cfg.ClientSecret,
		Code:           code,
		CodeVerifier:   codeVerifier,
		RedirectURI:    ssoOIDCRedirectURI(c, ssoProvider.ProviderID),
		Authentication: provider.OAuthClientAuthenticationPost,
	})
	if err != nil {
		return nil, err
	}
	return provider.TokensFromMap(data), nil
}

func ssoOIDCUserInfo(c *auth.Context, ssoProvider types.SSOProvider, cfg SSOOIDCConfig, tokens *provider.OAuthTokens) (provider.OAuthUser, error) {
	if tokens == nil {
		return provider.OAuthUser{}, errors.New("tokens are missing")
	}
	if tokens.IDToken != "" {
		claims, err := jwt.DecodePayload(tokens.IDToken)
		if err != nil {
			return provider.OAuthUser{}, err
		}
		if err := validateSSOOIDCClaims(ssoProvider, cfg, claims); err != nil {
			return provider.OAuthUser{}, err
		}
		user, err := ssoOIDCUserFromValidatedClaims(claims)
		if err == nil {
			return user, nil
		}
		if !errors.Is(err, errSSOOIDCProfileIncomplete) {
			return provider.OAuthUser{}, err
		}
	}
	if tokens.AccessToken == "" {
		return provider.OAuthUser{}, errors.New("access token missing")
	}
	endpoints, err := ssoOIDCEndpoints(c, ssoProvider, cfg)
	if err != nil {
		return provider.OAuthUser{}, err
	}
	if endpoints.UserInfoEndpoint == "" {
		return provider.OAuthUser{}, errors.New("userinfo endpoint is required")
	}
	req, err := http.NewRequestWithContext(c.R.Context(), http.MethodGet, endpoints.UserInfoEndpoint, nil)
	if err != nil {
		return provider.OAuthUser{}, err
	}
	req.Header.Set(constants.HeaderAccept, constants.MIMEJSON)
	req.Header.Set(constants.HeaderAuthorization, "Bearer "+tokens.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return provider.OAuthUser{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return provider.OAuthUser{}, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return provider.OAuthUser{}, fmt.Errorf("oidc userinfo failed for provider %q at %q with status %d: %s", ssoProvider.ProviderID, endpoints.UserInfoEndpoint, resp.StatusCode, string(body))
	}
	var profile map[string]any
	if err := json.Unmarshal(body, &profile); err != nil {
		return provider.OAuthUser{}, err
	}
	return ssoOIDCUserFromClaims(ssoProvider, cfg, profile)
}

func ssoOIDCUserFromClaims(ssoProvider types.SSOProvider, cfg SSOOIDCConfig, claims map[string]any) (provider.OAuthUser, error) {
	if err := validateSSOOIDCClaims(ssoProvider, cfg, claims); err != nil {
		return provider.OAuthUser{}, err
	}
	return ssoOIDCUserFromValidatedClaims(claims)
}

func ssoOIDCUserFromValidatedClaims(claims map[string]any) (provider.OAuthUser, error) {
	accountID := ssoOIDCString(claims, "sub", "id")
	email := auth.NormalizeEmail(ssoOIDCString(claims, "email"))
	name := ssoOIDCString(claims, "name", "preferred_username")
	if name == "" {
		name = email
	}
	image := ssoOIDCString(claims, "picture", "avatar_url", "image")
	emailVerified, _ := claims["email_verified"].(bool)
	if accountID == "" {
		return provider.OAuthUser{}, fmt.Errorf("%w: subject is required", errSSOOIDCProfileIncomplete)
	}
	if email == "" {
		return provider.OAuthUser{}, fmt.Errorf("%w: email is required", errSSOOIDCProfileIncomplete)
	}
	return provider.OAuthUser{
		ID: accountID, Name: name, Email: email, Image: optionalSSOImage(image), EmailVerified: emailVerified,
	}, nil
}

func validateSSOOIDCClaims(ssoProvider types.SSOProvider, cfg SSOOIDCConfig, claims map[string]any) error {
	if issuer := ssoOIDCString(claims, "iss"); issuer != "" && ssoProvider.Issuer != "" && issuer != ssoProvider.Issuer {
		return fmt.Errorf("oidc issuer mismatch: expected %q got %q", ssoProvider.Issuer, issuer)
	}
	if aud, ok := claims["aud"]; ok && !ssoOIDCAudienceContains(aud, cfg.ClientID) {
		return fmt.Errorf("oidc audience mismatch for client %q", cfg.ClientID)
	}
	if exp, ok := ssoOIDCNumericClaim(claims["exp"]); ok && time.Now().Unix() >= exp {
		return errors.New("oidc token expired")
	}
	return nil
}

func ssoSessionFromOIDCUser(c *auth.Context, ssoProvider types.SSOProvider, oidcUser provider.OAuthUser, tokens *provider.OAuthTokens) (*types.User, *types.Session, error) {
	accountProviderID := "sso:" + ssoProvider.ProviderID
	if account, err := c.Auth.Store().FindAccountByProviderAndAccountID(c.R.Context(), accountProviderID, oidcUser.ID); err == nil {
		if err := updateSSOOIDCAccount(c, account.ID, tokens); err != nil {
			return nil, nil, err
		}
		user, err := c.Auth.Store().FindUserByID(c.R.Context(), account.UserID)
		if err != nil {
			return nil, nil, err
		}
		sess, err := c.Auth.NewSession(c, user.ID, true)
		return user, sess, err
	}
	user, err := c.Auth.Store().FindUserByEmail(c.R.Context(), oidcUser.Email)
	if err != nil {
		if !errors.Is(err, berrors.ErrNotFound) {
			return nil, nil, err
		}
		user, err = c.Auth.CreateUser(c.R.Context(), oidcUser.Name, oidcUser.Email, oidcUser.Image, nil)
		if err != nil {
			return nil, nil, err
		}
	}
	if oidcUser.EmailVerified && !user.EmailVerified {
		verified := true
		updated, err := c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{EmailVerified: &verified})
		if err != nil {
			return nil, nil, err
		}
		user = updated
	}
	accountID, err := id.Generate(32)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	err = c.Auth.Store().CreateAccount(c.R.Context(), &types.Account{
		ID: accountID, AccountID: oidcUser.ID, ProviderID: accountProviderID, UserID: user.ID,
		AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken, IDToken: tokens.IDToken,
		AccessTokenExpiresAt: tokens.AccessTokenExpiresAt, RefreshTokenExpiresAt: tokens.RefreshTokenExpiresAt,
		Scope: strings.Join(tokens.Scopes, ","), CreatedAt: now, UpdatedAt: now,
	})
	if err != nil && !errors.Is(err, berrors.ErrAlreadyExists) {
		return nil, nil, err
	}
	sess, err := c.Auth.NewSession(c, user.ID, true)
	return user, sess, err
}

func updateSSOOIDCAccount(c *auth.Context, accountID string, tokens *provider.OAuthTokens) error {
	if tokens == nil {
		return nil
	}
	update := store.AccountUpdate{
		AccessTokenExpiresAt:  tokens.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: tokens.RefreshTokenExpiresAt,
	}
	hasUpdate := tokens.AccessTokenExpiresAt != nil || tokens.RefreshTokenExpiresAt != nil
	if tokens.AccessToken != "" {
		update.AccessToken = &tokens.AccessToken
		hasUpdate = true
	}
	if tokens.RefreshToken != "" {
		update.RefreshToken = &tokens.RefreshToken
		hasUpdate = true
	}
	if tokens.IDToken != "" {
		update.IDToken = &tokens.IDToken
		hasUpdate = true
	}
	if len(tokens.Scopes) > 0 {
		scope := strings.Join(tokens.Scopes, ",")
		update.Scope = &scope
		hasUpdate = true
	}
	if !hasUpdate {
		return nil
	}
	_, err := c.Auth.Store().UpdateAccount(c.R.Context(), accountID, update)
	return err
}

func ssoOIDCEndpoints(c *auth.Context, ssoProvider types.SSOProvider, cfg SSOOIDCConfig) (ssoOIDCDiscoveryDocument, error) {
	endpoints := ssoOIDCDiscoveryDocument{
		Issuer:                ssoProvider.Issuer,
		AuthorizationEndpoint: cfg.AuthorizationEndpoint,
		TokenEndpoint:         cfg.TokenEndpoint,
		UserInfoEndpoint:      cfg.UserInfoEndpoint,
	}
	discoveryURL := cfg.DiscoveryEndpoint
	if discoveryURL == "" && ssoProvider.Issuer != "" && (endpoints.AuthorizationEndpoint == "" || endpoints.TokenEndpoint == "") {
		discoveryURL = strings.TrimRight(ssoProvider.Issuer, "/") + "/.well-known/openid-configuration"
	}
	if discoveryURL != "" {
		discovery, err := fetchSSOOIDCDiscovery(c, ssoProvider.ProviderID, discoveryURL)
		if err != nil {
			return ssoOIDCDiscoveryDocument{}, err
		}
		if discovery.Issuer != "" {
			endpoints.Issuer = discovery.Issuer
		}
		if discovery.AuthorizationEndpoint != "" {
			endpoints.AuthorizationEndpoint = discovery.AuthorizationEndpoint
		}
		if discovery.TokenEndpoint != "" {
			endpoints.TokenEndpoint = discovery.TokenEndpoint
		}
		if discovery.UserInfoEndpoint != "" {
			endpoints.UserInfoEndpoint = discovery.UserInfoEndpoint
		}
	}
	if endpoints.AuthorizationEndpoint == "" || endpoints.TokenEndpoint == "" {
		return ssoOIDCDiscoveryDocument{}, fmt.Errorf("invalid oidc configuration for provider %q: authorizationEndpoint=%q tokenEndpoint=%q", ssoProvider.ProviderID, endpoints.AuthorizationEndpoint, endpoints.TokenEndpoint)
	}
	return endpoints, nil
}

func fetchSSOOIDCDiscovery(c *auth.Context, providerID string, discoveryURL string) (ssoOIDCDiscoveryDocument, error) {
	req, err := http.NewRequestWithContext(c.R.Context(), http.MethodGet, discoveryURL, nil)
	if err != nil {
		return ssoOIDCDiscoveryDocument{}, err
	}
	req.Header.Set(constants.HeaderAccept, constants.MIMEJSON)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ssoOIDCDiscoveryDocument{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ssoOIDCDiscoveryDocument{}, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return ssoOIDCDiscoveryDocument{}, fmt.Errorf("oidc discovery failed for provider %q at %q with status %d: %s", providerID, discoveryURL, resp.StatusCode, string(body))
	}
	var discovery ssoOIDCDiscoveryDocument
	if err := json.Unmarshal(body, &discovery); err != nil {
		return ssoOIDCDiscoveryDocument{}, err
	}
	return discovery, nil
}

func ssoOIDCRedirectURI(c *auth.Context, providerID string) string {
	return c.Auth.BaseURL() + c.Auth.BasePath() + "/sso/oidc/callback/" + url.PathEscape(providerID)
}

func ssoOIDCScopeString(scopes []string) string {
	if len(scopes) == 0 {
		return "openid profile email"
	}
	out := make([]string, 0, len(scopes)+1)
	seen := map[string]struct{}{}
	for _, scope := range append([]string{"openid"}, scopes...) {
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	return strings.Join(out, " ")
}

func ssoOIDCString(claims map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := claims[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			if typed != "" {
				return typed
			}
		case float64:
			return strconv.FormatFloat(typed, 'f', -1, 64)
		case bool:
			return strconv.FormatBool(typed)
		}
	}
	return ""
}

func ssoOIDCAudienceContains(value any, audience string) bool {
	switch typed := value.(type) {
	case string:
		return typed == audience
	case []any:
		for _, item := range typed {
			if item == audience {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func ssoOIDCNumericClaim(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), true
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	default:
		return 0, false
	}
}

func optionalSSOImage(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func buildSAMLRedirectURL(c *auth.Context, provider types.SSOProvider, cfg SSOSAMLConfig, callbackURL string) (string, error) {
	requestID, err := id.Generate(24)
	if err != nil {
		return "", err
	}
	acsURL := cfg.CallbackURL
	if acsURL == "" {
		acsURL = c.Auth.BaseURL() + c.Auth.BasePath() + "/sso/saml2/sp/acs/" + url.PathEscape(provider.ProviderID)
	}
	entityID := cfg.EntityID
	if entityID == "" {
		entityID = provider.Issuer
	}
	authnRequest := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="` + xmlEscape("id-"+requestID) + `" Version="2.0" IssueInstant="` + time.Now().UTC().Format(time.RFC3339) + `" Destination="` + xmlEscape(cfg.EntryPoint) + `" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="` + xmlEscape(acsURL) + `"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` + xmlEscape(entityID) + `</saml:Issuer></samlp:AuthnRequest>`
	encoded, err := deflateAndBase64(authnRequest)
	if err != nil {
		return "", err
	}
	values := url.Values{}
	values.Set("SAMLRequest", encoded)
	if callbackURL != "" {
		values.Set("RelayState", callbackURL)
	}
	for key, value := range cfg.AdditionalAuthorizationParams {
		values.Set(key, value)
	}
	return cfg.EntryPoint + "?" + values.Encode(), nil
}

func samlMetadataXML(c *auth.Context, provider types.SSOProvider, cfg SSOSAMLConfig) string {
	entityID := cfg.EntityID
	if entityID == "" {
		entityID = provider.Issuer
	}
	acsURL := cfg.CallbackURL
	if acsURL == "" {
		acsURL = c.Auth.BaseURL() + c.Auth.BasePath() + "/sso/saml2/sp/acs/" + url.PathEscape(provider.ProviderID)
	}
	nameIDFormat := cfg.IdentifierFormat
	if nameIDFormat == "" {
		nameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	}
	return `<?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + xmlEscape(entityID) + `"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="` + boolString(cfg.AuthnRequestsSigned) + `" WantAssertionsSigned="` + boolString(cfg.WantAssertionsSigned) + `"><md:NameIDFormat>` + xmlEscape(nameIDFormat) + `</md:NameIDFormat><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + xmlEscape(acsURL) + `" index="0" isDefault="true"/></md:SPSSODescriptor></md:EntityDescriptor>`
}

func deflateAndBase64(input string) (string, error) {
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := writer.Write([]byte(input)); err != nil {
		_ = writer.Close()
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func parseSAMLAssertion(encoded string, provider types.SSOProvider, cfg SSOSAMLConfig) (samlAssertionUser, error) {
	if encoded == "" {
		return samlAssertionUser{}, errors.New("SAMLResponse is required")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return samlAssertionUser{}, errors.New("invalid SAMLResponse")
	}
	if err := validateSAMLResponse(raw, provider, cfg); err != nil {
		return samlAssertionUser{}, err
	}
	attrs := map[string]string{}
	var nameID string
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "NameID":
			text, err := readElementText(decoder, start.Name.Local)
			if err == nil {
				nameID = text
			}
		case "Attribute":
			name := xmlAttr(start, "Name")
			if name == "" {
				name = xmlAttr(start, "FriendlyName")
			}
			if name == "" {
				continue
			}
			value, err := readAttributeValue(decoder)
			if err == nil {
				attrs[name] = value
			}
		}
	}
	email := mappedAttr(attrs, cfg.Mapping.Email, "email", "Email", "mail")
	if email == "" && strings.Contains(nameID, "@") {
		email = nameID
	}
	if email == "" {
		return samlAssertionUser{}, errors.New("SAML assertion email is required")
	}
	name := mappedAttr(attrs, cfg.Mapping.Name, "name", "displayName", "cn")
	if name == "" {
		firstName := mappedAttr(attrs, cfg.Mapping.FirstName, "firstName", "givenName")
		lastName := mappedAttr(attrs, cfg.Mapping.LastName, "lastName", "sn", "surname")
		name = strings.TrimSpace(firstName + " " + lastName)
	}
	if name == "" {
		name = email
	}
	accountID := mappedAttr(attrs, cfg.Mapping.ID, "id", "uid", "sub")
	if accountID == "" {
		accountID = nameID
	}
	if accountID == "" {
		accountID = email
	}
	extra := make(map[string]any, len(cfg.Mapping.ExtraFields))
	for key, attrName := range cfg.Mapping.ExtraFields {
		if value := attrs[attrName]; value != "" {
			extra[key] = value
		}
	}
	emailVerified := true
	if value := mappedAttr(attrs, cfg.Mapping.EmailVerified, "emailVerified"); value != "" {
		emailVerified = strings.EqualFold(value, "true")
	}
	return samlAssertionUser{ID: accountID, Email: strings.ToLower(email), Name: name, EmailVerified: emailVerified, Extra: extra}, nil
}

func validateSAMLResponse(raw []byte, provider types.SSOProvider, cfg SSOSAMLConfig) error {
	if cfg.Cert != "" || cfg.WantAssertionsSigned {
		if err := validateSAMLSignature(raw, cfg.Cert); err != nil {
			return err
		}
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	now := time.Now().UTC()
	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "Issuer":
			if provider.Issuer == "" {
				continue
			}
			issuer, err := readElementText(decoder, start.Name.Local)
			if err == nil && issuer != "" && issuer != provider.Issuer {
				return fmt.Errorf("SAML issuer mismatch: expected %q got %q", provider.Issuer, issuer)
			}
		case "Audience":
			audience, err := readElementText(decoder, start.Name.Local)
			if err == nil && cfg.Audience != "" && audience != "" && audience != cfg.Audience {
				return fmt.Errorf("SAML audience mismatch: expected %q got %q", cfg.Audience, audience)
			}
		case "Conditions":
			if err := validateSAMLConditions(start, now); err != nil {
				return err
			}
		case "SubjectConfirmationData":
			if err := validateSAMLSubjectConfirmation(start, cfg, now); err != nil {
				return err
			}
		}
	}
}

func validateSAMLSignature(raw []byte, certValue string) error {
	if certValue == "" {
		return errors.New("SAML certificate is required for signed assertions")
	}
	cert, err := parseSAMLCertificate(certValue)
	if err != nil {
		return err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return err
	}
	certStore := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	ctx := dsig.NewDefaultValidationContext(certStore)
	if _, err := ctx.Validate(doc.Root()); err == nil {
		return nil
	}
	for _, assertion := range doc.FindElements(".//*[local-name()='Assertion']") {
		if _, err := ctx.Validate(assertion); err == nil {
			return nil
		}
	}
	return errors.New("SAML signature validation failed")
}

func parseSAMLCertificate(value string) (*x509.Certificate, error) {
	cleaned := strings.TrimSpace(value)
	if strings.Contains(cleaned, "BEGIN CERTIFICATE") {
		cleaned = strings.ReplaceAll(cleaned, "-----BEGIN CERTIFICATE-----", "")
		cleaned = strings.ReplaceAll(cleaned, "-----END CERTIFICATE-----", "")
	}
	cleaned = strings.NewReplacer("\n", "", "\r", "", "\t", "", " ", "").Replace(cleaned)
	raw, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, errors.New("invalid SAML certificate")
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func validateSAMLConditions(start xml.StartElement, now time.Time) error {
	notBefore := xmlAttr(start, "NotBefore")
	if notBefore != "" {
		value, err := time.Parse(time.RFC3339, notBefore)
		if err != nil {
			return err
		}
		if now.Before(value.UTC()) {
			return errors.New("SAML assertion is not active yet")
		}
	}
	notOnOrAfter := xmlAttr(start, "NotOnOrAfter")
	if notOnOrAfter != "" {
		value, err := time.Parse(time.RFC3339, notOnOrAfter)
		if err != nil {
			return err
		}
		if !now.Before(value.UTC()) {
			return errors.New("SAML assertion expired")
		}
	}
	return nil
}

func validateSAMLSubjectConfirmation(start xml.StartElement, cfg SSOSAMLConfig, now time.Time) error {
	notOnOrAfter := xmlAttr(start, "NotOnOrAfter")
	if notOnOrAfter != "" {
		value, err := time.Parse(time.RFC3339, notOnOrAfter)
		if err != nil {
			return err
		}
		if !now.Before(value.UTC()) {
			return errors.New("SAML subject confirmation expired")
		}
	}
	recipient := xmlAttr(start, "Recipient")
	if cfg.CallbackURL != "" && recipient != "" && recipient != cfg.CallbackURL {
		return fmt.Errorf("SAML recipient mismatch: expected %q got %q", cfg.CallbackURL, recipient)
	}
	return nil
}

func ssoSessionFromAssertion(c *auth.Context, provider types.SSOProvider, assertion samlAssertionUser) (*types.User, *types.Session, error) {
	accountProviderID := "sso:" + provider.ProviderID
	if account, err := c.Auth.Store().FindAccountByProviderAndAccountID(c.R.Context(), accountProviderID, assertion.ID); err == nil {
		user, err := c.Auth.Store().FindUserByID(c.R.Context(), account.UserID)
		if err != nil {
			return nil, nil, err
		}
		sess, err := c.Auth.NewSession(c, user.ID, true)
		return user, sess, err
	}
	user, err := c.Auth.Store().FindUserByEmail(c.R.Context(), assertion.Email)
	if err != nil {
		if !errors.Is(err, berrors.ErrNotFound) {
			return nil, nil, err
		}
		user, err = c.Auth.CreateUser(c.R.Context(), assertion.Name, assertion.Email, nil, assertion.Extra)
		if err != nil {
			return nil, nil, err
		}
	}
	if assertion.EmailVerified && !user.EmailVerified {
		verified := true
		updated, err := c.Auth.Store().UpdateUser(c.R.Context(), user.ID, store.UserUpdate{EmailVerified: &verified})
		if err != nil {
			return nil, nil, err
		}
		user = updated
	}
	accountID, err := id.Generate(32)
	if err != nil {
		return nil, nil, err
	}
	err = c.Auth.Store().CreateAccount(c.R.Context(), &types.Account{
		ID: accountID, AccountID: assertion.ID, ProviderID: accountProviderID, UserID: user.ID,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	})
	if err != nil && !errors.Is(err, berrors.ErrAlreadyExists) {
		return nil, nil, err
	}
	sess, err := c.Auth.NewSession(c, user.ID, true)
	return user, sess, err
}

func readAttributeValue(decoder *xml.Decoder) (string, error) {
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", err
		}
		start, ok := token.(xml.StartElement)
		if ok && start.Name.Local == "AttributeValue" {
			return readElementText(decoder, start.Name.Local)
		}
	}
}

func readElementText(decoder *xml.Decoder, endLocal string) (string, error) {
	var builder strings.Builder
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", err
		}
		switch t := token.(type) {
		case xml.CharData:
			builder.Write([]byte(t))
		case xml.EndElement:
			if t.Name.Local == endLocal {
				return strings.TrimSpace(builder.String()), nil
			}
		}
	}
}

func xmlAttr(start xml.StartElement, name string) string {
	for _, attr := range start.Attr {
		if attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}

func mappedAttr(attrs map[string]string, preferred string, fallbacks ...string) string {
	if preferred != "" && attrs[preferred] != "" {
		return attrs[preferred]
	}
	for _, fallback := range fallbacks {
		if attrs[fallback] != "" {
			return attrs[fallback]
		}
	}
	return ""
}

func xmlEscape(value string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(value))
	return buf.String()
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
