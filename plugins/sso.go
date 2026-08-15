package plugins

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

const samlBindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

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

// SSO enables enterprise SSO provider management and SAML SP sign-in routes.
func SSO(opts SSOOptions) auth.Plugin {
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
				if !ok {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeProviderNotSupported, "OIDC SSO is not implemented yet"))
					return
				}
				redirectURL, err := buildSAMLRedirectURL(c, provider, samlConfig, body.CallbackURL)
				if err != nil {
					c.WriteError(apierror.New(http.StatusInternalServerError, constants.CodeInternalServerError, err.Error()))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]any{"url": redirectURL, "redirect": true})
			}),
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
				assertion, err := parseSAMLAssertion(c.R.PostForm.Get("SAMLResponse"), samlConfig.Mapping)
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

func parseSAMLAssertion(encoded string, mapping SSOSAMLMapping) (samlAssertionUser, error) {
	if encoded == "" {
		return samlAssertionUser{}, errors.New("SAMLResponse is required")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return samlAssertionUser{}, errors.New("invalid SAMLResponse")
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
	email := mappedAttr(attrs, mapping.Email, "email", "Email", "mail")
	if email == "" && strings.Contains(nameID, "@") {
		email = nameID
	}
	if email == "" {
		return samlAssertionUser{}, errors.New("SAML assertion email is required")
	}
	name := mappedAttr(attrs, mapping.Name, "name", "displayName", "cn")
	if name == "" {
		firstName := mappedAttr(attrs, mapping.FirstName, "firstName", "givenName")
		lastName := mappedAttr(attrs, mapping.LastName, "lastName", "sn", "surname")
		name = strings.TrimSpace(firstName + " " + lastName)
	}
	if name == "" {
		name = email
	}
	accountID := mappedAttr(attrs, mapping.ID, "id", "uid", "sub")
	if accountID == "" {
		accountID = nameID
	}
	if accountID == "" {
		accountID = email
	}
	extra := make(map[string]any, len(mapping.ExtraFields))
	for key, attrName := range mapping.ExtraFields {
		if value := attrs[attrName]; value != "" {
			extra[key] = value
		}
	}
	emailVerified := true
	if value := mappedAttr(attrs, mapping.EmailVerified, "emailVerified"); value != "" {
		emailVerified = strings.EqualFold(value, "true")
	}
	return samlAssertionUser{ID: accountID, Email: strings.ToLower(email), Name: name, EmailVerified: emailVerified, Extra: extra}, nil
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
