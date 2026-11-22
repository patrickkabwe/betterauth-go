package plugins

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/types"
)

var registrationAuthMethods = map[string]bool{
	"client_secret_basic": true, "client_secret_post": true,
	"private_key_jwt": true, "none": true,
}

// registrationGrantTypes are the grant_type values a dynamic registration may
// request; the server drops any it does not support (RFC 7591 §3.2.1).
var registrationGrantTypes = map[string]bool{
	constants.OAuthGrantTypeCode:        true,
	constants.OAuthGrantTypeRefresh:     true,
	constants.OAuthGrantTypeClientCreds: true,
	constants.OAuthGrantTypeDeviceCode:  true,
}

// oidcRegisterHandler implements RFC 7591 dynamic client registration. It
// applies the server defaults, validates the requested metadata, persists the
// client, and returns the client information response (status 201).
//
// Deferred vs Better Auth: registration-access-token issuance and the RFC 7592
// client-management endpoints, software_statement verification, admin/privilege
// gating, metadata documents, strict native redirect-URI rules, and open vs
// authenticated registration policy.
func oidcRegisterHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := auth.ExtStore(c.Auth.Store())
		if !ok {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
			return
		}
		var body struct {
			ClientName              string         `json:"client_name"`
			RedirectURIs            []string       `json:"redirect_uris"`
			GrantTypes              []string       `json:"grant_types"`
			ResponseTypes           []string       `json:"response_types"`
			TokenEndpointAuthMethod string         `json:"token_endpoint_auth_method"`
			ApplicationType         string         `json:"application_type"`
			Scope                   string         `json:"scope"`
			ClientURI               string         `json:"client_uri"`
			LogoURI                 string         `json:"logo_uri"`
			Contacts                []string       `json:"contacts"`
			TOSURI                  string         `json:"tos_uri"`
			PolicyURI               string         `json:"policy_uri"`
			JWKS                    map[string]any `json:"jwks"`
			JWKSURI                 string         `json:"jwks_uri"`
			SoftwareID              string         `json:"software_id"`
			SoftwareVersion         string         `json:"software_version"`
			SubjectType             string         `json:"subject_type"`
			PostLogoutRedirectURIs  []string       `json:"post_logout_redirect_uris"`
			DPoPBoundAccessTokens   bool           `json:"dpop_bound_access_tokens"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidClientMetadata, constants.MsgInvalidClientMetadata))
			return
		}

		// Server defaults (RFC 7591 §2 / §3.2.1).
		authMethod := body.TokenEndpointAuthMethod
		if authMethod == "" {
			authMethod = "client_secret_basic"
		}
		if !registrationAuthMethods[authMethod] {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidClientMetadata, "unsupported token_endpoint_auth_method "+authMethod))
			return
		}
		appType := body.ApplicationType
		if appType == "" {
			appType = "web"
		}
		if appType != "web" && appType != "native" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidClientMetadata, "application_type must be web or native"))
			return
		}

		grants := body.GrantTypes
		if len(grants) == 0 {
			grants = []string{constants.OAuthGrantTypeCode}
		}
		// Keep only grants the server supports; reject when none are shared.
		supported := make([]string, 0, len(grants))
		for _, g := range grants {
			if registrationGrantTypes[g] {
				supported = append(supported, g)
			}
		}
		if len(supported) == 0 {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidClientMetadata, "no mutually supported grant_type"))
			return
		}
		grants = supported
		usesAuthCode := hasScope(grants, constants.OAuthGrantTypeCode)

		responseTypes := body.ResponseTypes
		if len(responseTypes) == 0 && usesAuthCode {
			responseTypes = []string{"code"}
		}

		// authorization_code clients must register at least one valid redirect URI.
		if usesAuthCode {
			if len(body.RedirectURIs) == 0 {
				c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRedirectURI, "redirect_uris is required for authorization_code clients"))
				return
			}
			for _, ru := range body.RedirectURIs {
				u, err := url.Parse(ru)
				if err != nil || !u.IsAbs() {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRedirectURI, "redirect URI must be an absolute URI: "+ru))
					return
				}
			}
		}

		// private_key_jwt requires a way to resolve the client's public keys.
		jwksJSON := ""
		if body.JWKS != nil {
			if b, err := json.Marshal(body.JWKS); err == nil {
				jwksJSON = string(b)
			}
		}
		if authMethod == "private_key_jwt" && jwksJSON == "" && body.JWKSURI == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidClientMetadata, "private_key_jwt requires jwks or jwks_uri"))
			return
		}

		clientID, _ := id.Generate(16)
		secret := ""
		if authMethod != "none" {
			secret, _ = id.Generate(32)
		}
		now := time.Now().UTC()
		client := &types.OAuthClient{
			ID: clientID, ClientID: clientID, ClientSecret: secret, Name: body.ClientName,
			RedirectURIs: body.RedirectURIs, PostLogoutRedirectURIs: body.PostLogoutRedirectURIs,
			GrantTypes: grants, ResponseTypes: responseTypes,
			TokenEndpointAuthMethod: authMethod, ApplicationType: appType,
			Scopes: scopeList(body.Scope),
			URI:    body.ClientURI, Icon: body.LogoURI, Contacts: body.Contacts,
			TOS: body.TOSURI, Policy: body.PolicyURI,
			JWKS: jwksJSON, JWKSURI: body.JWKSURI,
			SoftwareID: body.SoftwareID, SoftwareVersion: body.SoftwareVersion,
			SubjectType: body.SubjectType, DPoPBoundAccessTokens: body.DPoPBoundAccessTokens,
			CreatedAt: now, UpdatedAt: now,
		}
		if err := ext.CreateOAuthClient(c.R.Context(), client); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}

		resp := map[string]any{
			"client_id":                  clientID,
			"client_id_issued_at":        now.Unix(),
			"redirect_uris":              body.RedirectURIs,
			"grant_types":                grants,
			"token_endpoint_auth_method": authMethod,
			"application_type":           appType,
		}
		if secret != "" {
			resp["client_secret"] = secret
			resp["client_secret_expires_at"] = 0 // non-expiring
		}
		if len(responseTypes) > 0 {
			resp["response_types"] = responseTypes
		}
		addNonEmpty(resp, "client_name", body.ClientName)
		addNonEmpty(resp, "scope", body.Scope)
		addNonEmpty(resp, "client_uri", body.ClientURI)
		addNonEmpty(resp, "logo_uri", body.LogoURI)
		addNonEmpty(resp, "tos_uri", body.TOSURI)
		addNonEmpty(resp, "policy_uri", body.PolicyURI)
		addNonEmpty(resp, "jwks_uri", body.JWKSURI)
		addNonEmpty(resp, "software_id", body.SoftwareID)
		addNonEmpty(resp, "software_version", body.SoftwareVersion)
		addNonEmpty(resp, "subject_type", body.SubjectType)
		if len(body.Contacts) > 0 {
			resp["contacts"] = body.Contacts
		}
		if len(body.PostLogoutRedirectURIs) > 0 {
			resp["post_logout_redirect_uris"] = body.PostLogoutRedirectURIs
		}
		if body.JWKS != nil {
			resp["jwks"] = body.JWKS
		}
		if body.DPoPBoundAccessTokens {
			resp["dpop_bound_access_tokens"] = true
		}
		c.WriteJSON(http.StatusCreated, resp)
	}
}

// addNonEmpty sets key=val on m only when val is non-empty.
func addNonEmpty(m map[string]any, key, val string) {
	if val != "" {
		m[key] = val
	}
}

func oidcGetClientHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := auth.ExtStore(c.Auth.Store())
		if !ok {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
			return
		}
		client, err := ext.FindOAuthClientByClientID(c.R.Context(), c.Vars["id"])
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeClientNotFound))
			return
		}
		c.WriteJSON(http.StatusOK, client)
	}
}

// oidcEndSessionHandler implements OIDC RP-Initiated Logout 1.0. It ends the
// end-user's session and, when a post_logout_redirect_uri is supplied, redirects
// only to a URI registered on the identified client (carrying state through).
//
// Deferred vs Better Auth: the interactive logout-confirmation page and
// OIDC Back-Channel Logout (logout_token delivery to registered clients).
