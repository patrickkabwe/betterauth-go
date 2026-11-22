package plugins

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/internal/oauthcrypto"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

const dpopProofMaxAge = time.Minute

// oauthSigningKey loads the provider's EdDSA signing key from the jwks table,
// generating and persisting one on first use. Used for RFC 9068 JWT access
// tokens; the public key is exposed at the JWKS endpoint.
func oauthSigningKey(c *auth.Context, ext store.ExtStore) (oauthcrypto.SigningKey, error) {
	keys, _ := ext.ListJWKS(c.R.Context())
	for _, k := range keys {
		if k.Alg != nil && *k.Alg == "EdDSA" && k.PrivateKey != "" {
			return oauthcrypto.SigningKeyFromSeed(k.ID, k.PrivateKey)
		}
	}
	kid, _ := id.Generate(16)
	key, seed, err := oauthcrypto.NewSigningKey(kid)
	if err != nil {
		return oauthcrypto.SigningKey{}, err
	}
	alg, crv := "EdDSA", "Ed25519"
	_ = ext.CreateJWKS(c.R.Context(), &types.JWKSRecord{
		ID: kid, PublicKey: key.PublicX, PrivateKey: seed, Alg: &alg, Crv: &crv, CreatedAt: time.Now().UTC(),
	})
	return key, nil
}

// endpointURL is the public URL for a provider endpoint (the DPoP `htu`).
func endpointURL(c *auth.Context, path string) string {
	return c.Auth.BaseURL() + c.Auth.BasePath() + path
}

// accessTokenTTL and refreshTokenTTL are the Phase 2 defaults (Better Auth uses
// 1h / 30d). refreshReplayWindow is how long a just-rotated refresh token still
// replays its rotation response to absorb client retries.
const (
	accessTokenTTL      = time.Hour
	refreshTokenTTL     = 30 * 24 * time.Hour
	refreshReplayWindow = 30 * time.Second
)

// oidcCodeData is the JSON stored in the authorization-code verification so the
// token endpoint can bind the issued tokens to a session and carry scopes.
type oidcCodeData struct {
	UserID    string   `json:"userId"`
	ClientID  string   `json:"clientId"`
	SessionID string   `json:"sessionId"`
	Scope     string   `json:"scope"`
	Resources []string `json:"resources,omitempty"`
}

// oidcTokenResponse is the OAuth token endpoint response.
type oidcTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func requireOAuthStore(c *auth.Context) (store.ExtStore, bool) {
	ext, ok := auth.ExtStore(c.Auth.Store())
	if !ok {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
		return nil, false
	}
	return ext, true
}

func scopeList(scope string) []string {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	return strings.Fields(scope)
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// oidcGrant carries the resolved inputs for issuing a token grant.
type oidcGrant struct {
	clientID        string
	userID          string
	sessionID       string
	scopes          []string
	resources       []string // RFC 8707 resource indicators bound to the tokens
	accessTTL       time.Duration
	jwtAccessTokens bool   // issue an RFC 9068 JWT access token instead of opaque
	dpopJKT         string // RFC 9449 confirmation thumbprint, when DPoP-bound
}

// issueOAuthGrant mints the access token (JWT or opaque) and, when
// offline_access is granted, an opaque refresh token, and returns the token
// response. RFC 8707 resources become the audience; a DPoP jkt sender-constrains
// the token (cnf claim on JWTs, confirmation column on opaque tokens).
func issueOAuthGrant(c *auth.Context, ext store.ExtStore, g oidcGrant) (oidcTokenResponse, error) {
	now := time.Now().UTC()
	accessTTL := g.accessTTL
	if accessTTL <= 0 {
		accessTTL = accessTokenTTL
	}
	refreshID := ""
	refreshTok := ""
	if hasScope(g.scopes, "offline_access") {
		refreshID, _ = id.Generate(32)
		refreshTok, _ = id.Generate(32)
		if err := ext.CreateOAuthRefreshToken(c.R.Context(), &types.OAuthRefreshToken{
			ID: refreshID, Token: refreshTok, ClientID: g.clientID, SessionID: g.sessionID, UserID: g.userID,
			Scopes: g.scopes, Resources: g.resources, ExpiresAt: now.Add(refreshTokenTTL), CreatedAt: now,
		}); err != nil {
			return oidcTokenResponse{}, err
		}
	}

	var accessTok string
	if g.jwtAccessTokens {
		key, err := oauthSigningKey(c, ext)
		if err != nil {
			return oidcTokenResponse{}, err
		}
		jti, _ := id.Generate(16)
		claims := jwt.MapClaims{
			"iss": c.Auth.BaseURL(), "sub": g.userID, "client_id": g.clientID,
			"iat": now.Unix(), "exp": now.Add(accessTTL).Unix(), "jti": jti,
			"scope": strings.Join(g.scopes, " "),
		}
		if len(g.resources) > 0 {
			claims["aud"] = g.resources
		}
		if g.dpopJKT != "" {
			claims["cnf"] = map[string]any{"jkt": g.dpopJKT}
		}
		if accessTok, err = key.SignAccessToken(claims); err != nil {
			return oidcTokenResponse{}, err
		}
		// RFC 9068 JWT access tokens are self-contained and not stored.
	} else {
		accessID, _ := id.Generate(32)
		accessTok, _ = id.Generate(32)
		var confirmation map[string]any
		if g.dpopJKT != "" {
			confirmation = map[string]any{"jkt": g.dpopJKT}
		}
		if err := ext.CreateOAuthAccessToken(c.R.Context(), &types.OAuthAccessToken{
			ID: accessID, Token: accessTok, ClientID: g.clientID, SessionID: g.sessionID, UserID: g.userID,
			Scopes: g.scopes, Resources: g.resources, RefreshID: refreshID, Confirmation: confirmation,
			ExpiresAt: now.Add(accessTTL), CreatedAt: now,
		}); err != nil {
			return oidcTokenResponse{}, err
		}
	}

	tokenType := constants.TokenTypeBearer
	if g.dpopJKT != "" {
		tokenType = "DPoP"
	}
	return oidcTokenResponse{
		AccessToken:  accessTok,
		TokenType:    tokenType,
		ExpiresIn:    int(accessTTL.Seconds()),
		Scope:        strings.Join(g.scopes, " "),
		RefreshToken: refreshTok,
	}, nil
}

// verifyDPoPAtEndpoint verifies a DPoP proof for an endpoint, enforcing single
// use of its jti via the verification store. Returns the key thumbprint.
func verifyDPoPAtEndpoint(c *auth.Context, proof, method, path, ath string) (string, error) {
	res, err := oauthcrypto.VerifyDPoPProof(proof, method, endpointURL(c, path), time.Now().UTC(), dpopProofMaxAge)
	if err != nil {
		return "", err
	}
	if ath != "" && res.ATH != ath {
		return "", apierror.New(http.StatusUnauthorized, constants.CodeUnauthorized, "dpop ath mismatch")
	}
	// Replay protection: the jti may be presented only once within its lifetime.
	if _, err := c.Auth.Store().FindVerificationByIdentifier(c.R.Context(), "dpop:"+res.JTI); err == nil {
		return "", apierror.New(http.StatusUnauthorized, constants.CodeInvalidDPoPProof, "dpop proof replayed")
	}
	_ = c.Auth.CreateVerification(c.R.Context(), "dpop:"+res.JTI, "1", dpopProofMaxAge+30*time.Second)
	return res.JKT, nil
}

// validateResources resolves the RFC 8707 resource indicators for a request:
// every identifier must map to an enabled oauthResource row, the client must be
// linked when per-client enforcement is on, and each resource's allowedScopes
// (when set) must intersect the requested scopes. It returns the validated
// resource list and the minimum per-resource access-token TTL (0 = default).
func validateResources(c *auth.Context, ext store.ExtStore, client *types.OAuthClient, scopes, resources []string, enforcePerClient bool) ([]string, time.Duration, *apierror.Error) {
	if len(resources) == 0 {
		return nil, 0, nil
	}
	var minTTL time.Duration
	seen := map[string]bool{}
	out := make([]string, 0, len(resources))
	for _, identifier := range resources {
		if seen[identifier] {
			continue
		}
		seen[identifier] = true
		res, err := ext.FindOAuthResource(c.R.Context(), identifier)
		if err != nil {
			return nil, 0, apierror.New(http.StatusBadRequest, constants.CodeInvalidTarget, "requested resource "+identifier+" is not configured")
		}
		if res.Disabled {
			return nil, 0, apierror.New(http.StatusBadRequest, constants.CodeInvalidTarget, "requested resource "+identifier+" is disabled")
		}
		if enforcePerClient {
			linked, _ := ext.IsOAuthClientLinkedToResource(c.R.Context(), client.ClientID, identifier)
			if !linked {
				return nil, 0, apierror.New(http.StatusBadRequest, constants.CodeInvalidTarget, "client is not allowed to request resource "+identifier)
			}
		}
		if len(res.AllowedScopes) > 0 {
			intersects := false
			for _, s := range scopes {
				if hasScope(res.AllowedScopes, s) {
					intersects = true
					break
				}
			}
			if !intersects {
				return nil, 0, apierror.New(http.StatusBadRequest, constants.CodeInvalidScope, "requested scopes are not allowed for resource "+identifier)
			}
		}
		if res.AccessTokenTTL != nil {
			ttl := time.Duration(*res.AccessTokenTTL) * time.Second
			if minTTL == 0 || ttl < minTTL {
				minTTL = ttl
			}
		}
		out = append(out, identifier)
	}
	return out, minTTL, nil
}

// OIDCProviderOptions configures acting as an OIDC identity provider.
type OIDCProviderOptions struct {
	LoginPage string
	// ConsentPage, when set, is where /oauth2/authorize redirects the user to
	// collect consent. When empty, authorize responds with JSON
	// {"consentRequired": true, ...} so a front end can render its own screen.
	ConsentPage string
	// EnforcePerClientResources requires a client to be explicitly linked to a
	// requested RFC 8707 resource (via oauthClientResource) before a token may
	// be issued for it. When false, any enabled resource may be requested.
	EnforcePerClientResources bool
	// JWTAccessTokens issues stateless RFC 9068 EdDSA-signed JWT access tokens
	// instead of opaque ones. When a DPoP proof accompanies the token request,
	// the JWT is sender-constrained with a cnf:{jkt} claim (RFC 9449).
	JWTAccessTokens bool
}

// OIDCProvider exposes OIDC provider endpoints.
func OIDCProvider(opts OIDCProviderOptions) auth.Plugin {
	return basePlugin{
		id: constants.PluginOIDCProvider,
		routes: []auth.PluginRoute{
			rt(http.MethodGet, "/.well-known/openid-configuration", oidcMetadataHandler()),
			rt(http.MethodGet, "/oauth2/authorize", oidcAuthorizeHandler(opts)),
			rt(http.MethodPost, "/oauth2/consent", oidcConsentHandler(opts)),
			rt(http.MethodGet, "/oauth2/get-consent", oidcGetConsentHandler()),
			rt(http.MethodGet, "/oauth2/get-consents", oidcGetConsentsHandler()),
			rt(http.MethodPost, "/oauth2/update-consent", oidcUpdateConsentHandler()),
			rt(http.MethodPost, "/oauth2/delete-consent", oidcDeleteConsentHandler()),
			rt(http.MethodPost, "/oauth2/resource", oidcCreateResourceHandler()),
			rt(http.MethodGet, "/oauth2/resources", oidcListResourcesHandler()),
			rt(http.MethodGet, "/oauth2/resource", oidcGetResourceHandler()),
			rt(http.MethodPost, "/oauth2/resource/update", oidcUpdateResourceHandler()),
			rt(http.MethodPost, "/oauth2/resource/delete", oidcDeleteResourceHandler()),
			rt(http.MethodPost, "/oauth2/client-resource/link", oidcLinkClientResourceHandler()),
			rt(http.MethodPost, "/oauth2/client-resource/unlink", oidcUnlinkClientResourceHandler()),
			rt(http.MethodGet, "/oauth2/client-resource", oidcListClientResourcesHandler()),
			rt(http.MethodPost, "/oauth2/token", oidcTokenHandler(opts)),
			rt(http.MethodPost, "/oauth2/introspect", oidcIntrospectHandler()),
			rt(http.MethodPost, "/oauth2/revoke", oidcRevokeHandler()),
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
			"introspection_endpoint":                base + "/oauth2/introspect",
			"revocation_endpoint":                   base + "/oauth2/revoke",
			"userinfo_endpoint":                     base + "/oauth2/userinfo",
			"registration_endpoint":                 base + "/oauth2/register",
			"end_session_endpoint":                  base + "/oauth2/endsession",
			"jwks_uri":                              c.Auth.BaseURL() + c.Auth.BasePath() + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{constants.JWTAlgHS256},
			"dpop_signing_alg_values_supported":     []string{"EdDSA", "ES256"},
		})
	}
}

// issueAuthCode stores the authorization-code grant data in a verification and
// returns the opaque code. Used by authorize (consent satisfied) and by the
// consent endpoint after the user accepts.
func issueAuthCode(c *auth.Context, userID, clientID, sessionID, scope string, resources []string) string {
	code, _ := id.Generate(32)
	data, _ := json.Marshal(oidcCodeData{UserID: userID, ClientID: clientID, SessionID: sessionID, Scope: scope, Resources: resources})
	_ = c.Auth.CreateVerification(c.R.Context(), constants.VerificationOIDCCode+code, string(data), 10*time.Minute)
	return code
}

// consentSatisfied reports whether the client may skip the consent screen for
// the requested scopes — either the client is marked skipConsent, or a stored
// consent already covers every requested scope.
func consentSatisfied(c *auth.Context, ext store.ExtStore, client *types.OAuthClient, userID string, scopes []string) bool {
	if client.SkipConsent != nil && *client.SkipConsent {
		return true
	}
	consent, err := ext.FindOAuthConsent(c.R.Context(), client.ClientID, userID)
	if err != nil {
		return false
	}
	for _, s := range scopes {
		if !hasScope(consent.Scopes, s) {
			return false
		}
	}
	return true
}

func oidcAuthorizeHandler(opts OIDCProviderOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, err := c.GetSession()
		if err != nil {
			login := opts.LoginPage
			if login == "" {
				login = "/"
			}
			c.Redirect(login)
			return
		}
		ext, ok := requireOAuthStore(c)
		if !ok {
			return
		}
		q := c.R.URL.Query()
		clientID := q.Get("client_id")
		scope := q.Get("scope")
		redirectURI := q.Get("redirect_uri")
		state := q.Get("state")
		client, err := ext.FindOAuthClientByClientID(c.R.Context(), clientID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeClientNotFound))
			return
		}
		// RFC 8707: validate requested resource indicators up front.
		resources, _, apiErr := validateResources(c, ext, client, scopeList(scope), q["resource"], opts.EnforcePerClientResources)
		if apiErr != nil {
			if redirectURI != "" {
				c.Redirect(redirectURI + "?error=" + url.QueryEscape(strings.ToLower(apiErr.Code)) + "&state=" + url.QueryEscape(state))
				return
			}
			c.WriteError(apiErr)
			return
		}
		if !consentSatisfied(c, ext, client, user.ID, scopeList(scope)) {
			// Consent required: hand off to the consent page, or tell the caller.
			if opts.ConsentPage != "" {
				c.Redirect(opts.ConsentPage + "?client_id=" + url.QueryEscape(clientID) + "&scope=" + url.QueryEscape(scope) + "&redirect_uri=" + url.QueryEscape(redirectURI) + "&state=" + url.QueryEscape(state))
				return
			}
			c.WriteJSON(http.StatusOK, map[string]any{
				"consentRequired": true,
				"clientId":        clientID,
				"scope":           scope,
				"resource":        resources,
				"redirectUri":     redirectURI,
				"state":           state,
			})
			return
		}
		code := issueAuthCode(c, user.ID, clientID, sess.ID, scope, resources)
		c.Redirect(redirectURI + "?code=" + code + "&state=" + state)
	}
}

// oidcConsentHandler records a user's consent decision for a client. On accept
// it upserts the oauthConsent row and returns the redirect URL carrying a fresh
// authorization code; on deny it returns a redirect carrying access_denied.
func oidcConsentHandler(opts OIDCProviderOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthStore(c)
		if !ok {
			return
		}
		sess, user, err := c.GetSession()
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeUnauthorized))
			return
		}
		var body struct {
			ClientID    string   `json:"client_id"`
			Scope       string   `json:"scope"`
			Resource    []string `json:"resource"`
			Accept      bool     `json:"accept"`
			RedirectURI string   `json:"redirect_uri"`
			State       string   `json:"state"`
		}
		if err := c.ParseJSON(&body); err != nil || body.ClientID == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
			return
		}
		if !body.Accept {
			c.WriteJSON(http.StatusOK, map[string]any{
				"redirect": body.RedirectURI + "?error=access_denied&state=" + url.QueryEscape(body.State),
			})
			return
		}
		scopes := scopeList(body.Scope)
		client, err := ext.FindOAuthClientByClientID(c.R.Context(), body.ClientID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeClientNotFound))
			return
		}
		resources, _, apiErr := validateResources(c, ext, client, scopes, body.Resource, opts.EnforcePerClientResources)
		if apiErr != nil {
			c.WriteError(apiErr)
			return
		}
		now := time.Now().UTC()
		if existing, err := ext.FindOAuthConsent(c.R.Context(), body.ClientID, user.ID); err == nil {
			_ = ext.UpdateOAuthConsent(c.R.Context(), existing.ID, scopes, resources, existing.RequestedUserInfoClaims)
		} else {
			consentID, _ := id.Generate(32)
			_ = ext.CreateOAuthConsent(c.R.Context(), &types.OAuthConsent{
				ID: consentID, ClientID: body.ClientID, UserID: user.ID, Scopes: scopes, Resources: resources, CreatedAt: now, UpdatedAt: now,
			})
		}
		code := issueAuthCode(c, user.ID, body.ClientID, sess.ID, body.Scope, resources)
		c.WriteJSON(http.StatusOK, map[string]any{
			"redirect": body.RedirectURI + "?code=" + code + "&state=" + url.QueryEscape(body.State),
		})
	}
}

func oidcGetConsentsHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthStore(c)
		if !ok {
			return
		}
		_, user, err := c.GetSession()
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeUnauthorized))
			return
		}
		consents, err := ext.ListOAuthConsentsByUser(c.R.Context(), user.ID)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, consents)
	}
}

func oidcGetConsentHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthStore(c)
		if !ok {
			return
		}
		_, user, err := c.GetSession()
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeUnauthorized))
			return
		}
		consent, err := ext.FindOAuthConsentByID(c.R.Context(), c.R.URL.Query().Get("id"))
		if err != nil || consent.UserID != user.ID {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeNotFound))
			return
		}
		c.WriteJSON(http.StatusOK, consent)
	}
}

func oidcUpdateConsentHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthStore(c)
		if !ok {
			return
		}
		_, user, err := c.GetSession()
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeUnauthorized))
			return
		}
		var body struct {
			ID     string `json:"id"`
			Update struct {
				Scopes []string `json:"scopes"`
			} `json:"update"`
		}
		if err := c.ParseJSON(&body); err != nil || body.ID == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
			return
		}
		consent, err := ext.FindOAuthConsentByID(c.R.Context(), body.ID)
		if err != nil || consent.UserID != user.ID {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeNotFound))
			return
		}
		if err := ext.UpdateOAuthConsent(c.R.Context(), body.ID, body.Update.Scopes, consent.Resources, consent.RequestedUserInfoClaims); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		updated, _ := ext.FindOAuthConsentByID(c.R.Context(), body.ID)
		c.WriteJSON(http.StatusOK, updated)
	}
}

func oidcDeleteConsentHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthStore(c)
		if !ok {
			return
		}
		_, user, err := c.GetSession()
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeUnauthorized))
			return
		}
		var body struct {
			ID string `json:"id"`
		}
		if err := c.ParseJSON(&body); err != nil || body.ID == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
			return
		}
		consent, err := ext.FindOAuthConsentByID(c.R.Context(), body.ID)
		if err != nil || consent.UserID != user.ID {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeNotFound))
			return
		}
		_ = ext.DeleteOAuthConsent(c.R.Context(), body.ID)
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

// requireOAuthAdmin resolves a session for the resource-management endpoints.
// NOTE: Better Auth gates these on admin privileges (assertResourcePrivileges).
// The Go port currently requires only an authenticated session; wiring an admin
// check to the admin plugin is a follow-up.
func requireOAuthAdmin(c *auth.Context) (store.ExtStore, bool) {
	ext, ok := requireOAuthStore(c)
	if !ok {
		return nil, false
	}
	if _, _, err := c.GetSession(); err != nil {
		c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeUnauthorized))
		return nil, false
	}
	return ext, true
}

func oidcCreateResourceHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		var r types.OAuthResource
		if err := c.ParseJSON(&r); err != nil || r.Identifier == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "identifier is required"))
			return
		}
		if r.Name == "" {
			r.Name = r.Identifier
		}
		r.ID, _ = id.Generate(32)
		now := time.Now().UTC()
		r.CreatedAt, r.UpdatedAt = now, now
		if r.PolicyVersion == 0 {
			r.PolicyVersion = 1
		}
		if err := ext.CreateOAuthResource(c.R.Context(), &r); err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, r)
	}
}

func oidcListResourcesHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		list, err := ext.ListOAuthResources(c.R.Context())
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, list)
	}
}

func oidcGetResourceHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		r, err := ext.FindOAuthResource(c.R.Context(), c.R.URL.Query().Get("identifier"))
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeNotFound))
			return
		}
		c.WriteJSON(http.StatusOK, r)
	}
}

func oidcUpdateResourceHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		var r types.OAuthResource
		if err := c.ParseJSON(&r); err != nil || r.Identifier == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "identifier is required"))
			return
		}
		if err := ext.UpdateOAuthResource(c.R.Context(), &r); err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeNotFound))
			return
		}
		updated, _ := ext.FindOAuthResource(c.R.Context(), r.Identifier)
		c.WriteJSON(http.StatusOK, updated)
	}
}

func oidcDeleteResourceHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		var body struct {
			Identifier string `json:"identifier"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Identifier == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "identifier is required"))
			return
		}
		if err := ext.DeleteOAuthResource(c.R.Context(), body.Identifier); err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeNotFound))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func oidcLinkClientResourceHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		var body struct {
			ClientID   string `json:"client_id"`
			ResourceID string `json:"resource_id"`
		}
		if err := c.ParseJSON(&body); err != nil || body.ClientID == "" || body.ResourceID == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "client_id and resource_id are required"))
			return
		}
		linkID, _ := id.Generate(32)
		if err := ext.LinkOAuthClientResource(c.R.Context(), &types.OAuthClientResource{
			ID: linkID, ClientID: body.ClientID, ResourceID: body.ResourceID, CreatedAt: time.Now().UTC(),
		}); err != nil {
			c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidRequest))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func oidcUnlinkClientResourceHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		var body struct {
			ClientID   string `json:"client_id"`
			ResourceID string `json:"resource_id"`
		}
		if err := c.ParseJSON(&body); err != nil || body.ClientID == "" || body.ResourceID == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, "client_id and resource_id are required"))
			return
		}
		if err := ext.UnlinkOAuthClientResource(c.R.Context(), body.ClientID, body.ResourceID); err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeNotFound))
			return
		}
		c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
	}
}

func oidcListClientResourcesHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthAdmin(c)
		if !ok {
			return
		}
		list, err := ext.ListOAuthClientResources(c.R.Context(), c.R.URL.Query().Get("client_id"))
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, list)
	}
}

// authenticateOAuthClient resolves and authenticates the client from the
// request body (client_id / client_secret). A client with a stored secret must
// present a matching one; a public client (no secret) needs only client_id.
func authenticateOAuthClient(c *auth.Context, ext store.ExtStore, clientID, clientSecret string) (*types.OAuthClient, bool) {
	if clientID == "" {
		c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidClient, "client authentication failed"))
		return nil, false
	}
	client, err := ext.FindOAuthClientByClientID(c.R.Context(), clientID)
	if err != nil || (client.ClientSecret != "" && client.ClientSecret != clientSecret) {
		c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidClient, "client authentication failed"))
		return nil, false
	}
	return client, true
}

// oauthClientMayIntrospect reports whether the introspecting client is allowed
// to see a token's metadata: it issued the token, or it is linked to one of the
// token's audience resources. Otherwise the caller gets {active:false}.
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
			Token         string `json:"token"`
			TokenTypeHint string `json:"token_type_hint"`
			ClientID      string `json:"client_id"`
			ClientSecret  string `json:"client_secret"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Token == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
			return
		}
		client, ok := authenticateOAuthClient(c, ext, body.ClientID, body.ClientSecret)
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
			Token         string `json:"token"`
			TokenTypeHint string `json:"token_type_hint"`
			ClientID      string `json:"client_id"`
			ClientSecret  string `json:"client_secret"`
		}
		if err := c.ParseJSON(&body); err != nil || body.Token == "" {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
			return
		}
		client, ok := authenticateOAuthClient(c, ext, body.ClientID, body.ClientSecret)
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

func oidcTokenHandler(opts OIDCProviderOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthStore(c)
		if !ok {
			return
		}
		var body struct {
			Code         string `json:"code"`
			GrantType    string `json:"grant_type"`
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := c.ParseJSON(&body); err != nil {
			c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidTokenRequest))
			return
		}
		// RFC 9449: a DPoP proof on the token request sender-constrains the token.
		dpopJKT := ""
		if proof := c.R.Header.Get("DPoP"); proof != "" {
			jkt, err := verifyDPoPAtEndpoint(c, proof, http.MethodPost, "/oauth2/token", "")
			if err != nil {
				c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidDPoPProof, "invalid dpop proof"))
				return
			}
			dpopJKT = jkt
		}
		switch body.GrantType {
		case "refresh_token":
			oidcRefreshTokenGrant(c, ext, opts, body.ClientID, body.RefreshToken, dpopJKT)
		default: // authorization_code (default preserves prior behaviour)
			oidcAuthorizationCodeGrant(c, ext, opts, body.Code, dpopJKT)
		}
	}
}

func oidcAuthorizationCodeGrant(c *auth.Context, ext store.ExtStore, opts OIDCProviderOptions, code, dpopJKT string) {
	v, err := c.Auth.ConsumeVerification(c.R.Context(), constants.VerificationOIDCCode+code)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
		return
	}
	var data oidcCodeData
	if err := json.Unmarshal([]byte(v.Value), &data); err != nil {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCode))
		return
	}
	resp, err := issueOAuthGrant(c, ext, oidcGrant{
		clientID: data.ClientID, userID: data.UserID, sessionID: data.SessionID,
		scopes: scopeList(data.Scope), resources: data.Resources,
		jwtAccessTokens: opts.JWTAccessTokens, dpopJKT: dpopJKT,
	})
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return
	}
	c.WriteJSON(http.StatusOK, resp)
}

// oidcRefreshTokenGrant rotates a refresh token: it issues a new access +
// refresh token, then revokes the presented one and records the response for a
// short replay window. A revoked token presented again replays that response
// inside the window, or triggers family invalidation (reuse) outside it.
func oidcRefreshTokenGrant(c *auth.Context, ext store.ExtStore, opts OIDCProviderOptions, clientID, refreshToken, dpopJKT string) {
	rt, err := ext.FindOAuthRefreshToken(c.R.Context(), refreshToken)
	if err != nil {
		c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidGrant, "session not found"))
		return
	}
	now := time.Now().UTC()
	if rt.Revoked != nil {
		if rt.RotationReplayExpiresAt != nil && rt.RotationReplayExpiresAt.After(now) && rt.RotationReplayResponse != "" {
			c.W.Header().Set(constants.HeaderContentType, "application/json")
			c.W.WriteHeader(http.StatusOK)
			_, _ = c.W.Write([]byte(rt.RotationReplayResponse))
			return
		}
		// Reuse of an already-rotated token: tear down the whole family.
		_ = ext.InvalidateOAuthRefreshFamily(c.R.Context(), rt.ClientID, rt.UserID)
		c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidGrant, "invalid refresh token"))
		return
	}
	if (clientID != "" && rt.ClientID != clientID) || rt.ExpiresAt.Before(now) {
		c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidGrant, "invalid refresh token"))
		return
	}
	resp, err := issueOAuthGrant(c, ext, oidcGrant{
		clientID: rt.ClientID, userID: rt.UserID, sessionID: rt.SessionID,
		scopes: rt.Scopes, resources: rt.Resources,
		jwtAccessTokens: opts.JWTAccessTokens, dpopJKT: dpopJKT,
	})
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return
	}
	replay, _ := json.Marshal(resp)
	_ = ext.RotateOAuthRefreshToken(c.R.Context(), rt.ID, string(replay), now.Add(refreshReplayWindow))
	c.WriteJSON(http.StatusOK, resp)
}

// oauthVerifyKey loads the provider's EdDSA public key for verifying JWT access
// tokens, without creating one (read-only, unlike oauthSigningKey).
func oauthVerifyKey(c *auth.Context, ext store.ExtStore) (oauthcrypto.SigningKey, bool) {
	keys, _ := ext.ListJWKS(c.R.Context())
	for _, k := range keys {
		if k.Alg != nil && *k.Alg == "EdDSA" && k.PrivateKey != "" {
			if sk, err := oauthcrypto.SigningKeyFromSeed(k.ID, k.PrivateKey); err == nil {
				return sk, true
			}
		}
	}
	return oauthcrypto.SigningKey{}, false
}

// bearerToken extracts the access token from the Authorization header, accepting
// both the Bearer and DPoP schemes.
func bearerToken(c *auth.Context) string {
	h := c.R.Header.Get(constants.HeaderAuthorization)
	for _, scheme := range []string{constants.TokenTypeBearer + " ", "DPoP "} {
		if len(h) > len(scheme) && strings.EqualFold(h[:len(scheme)], scheme) {
			return h[len(scheme):]
		}
	}
	return h
}

func oidcUserInfoHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthStore(c)
		if !ok {
			return
		}
		token := bearerToken(c)
		now := time.Now().UTC()
		var userID, cnfJKT string

		if oauthcrypto.LooksLikeJWT(token) {
			key, ok := oauthVerifyKey(c, ext)
			if !ok {
				c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeUnauthorized))
				return
			}
			claims, err := oauthcrypto.ParseAccessToken(token, key.Public())
			if err != nil {
				c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeUnauthorized))
				return
			}
			if iss, _ := claims["iss"].(string); iss != c.Auth.BaseURL() {
				c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeUnauthorized))
				return
			}
			userID, _ = claims["sub"].(string)
			if cnf, ok := claims["cnf"].(map[string]any); ok {
				cnfJKT, _ = cnf["jkt"].(string)
			}
		} else {
			at, err := ext.FindOAuthAccessToken(c.R.Context(), token)
			if err != nil || at.Revoked != nil || at.ExpiresAt.Before(now) {
				c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeUnauthorized))
				return
			}
			userID = at.UserID
			if at.Confirmation != nil {
				cnfJKT, _ = at.Confirmation["jkt"].(string)
			}
		}

		// RFC 9449: a sender-constrained token requires a matching DPoP proof.
		if cnfJKT != "" {
			proof := c.R.Header.Get("DPoP")
			if proof == "" {
				c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidDPoPProof, "dpop proof required"))
				return
			}
			jkt, err := verifyDPoPAtEndpoint(c, proof, http.MethodGet, "/oauth2/userinfo", oauthcrypto.AccessTokenHash(token))
			if err != nil || jkt != cnfJKT {
				c.WriteError(apierror.New(http.StatusUnauthorized, constants.CodeInvalidDPoPProof, "invalid dpop proof"))
				return
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
		_ = ext.CreateOAuthClient(c.R.Context(), &types.OAuthClient{
			ID: clientID, ClientID: clientID, ClientSecret: secret, Name: body.ClientName,
			RedirectURIs: body.RedirectURIs, CreatedAt: now, UpdatedAt: now,
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
		client, err := ext.FindOAuthClientByClientID(c.R.Context(), c.Vars["id"])
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeClientNotFound))
			return
		}
		c.WriteJSON(http.StatusOK, client)
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
