package plugins

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

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
	UserID    string `json:"userId"`
	ClientID  string `json:"clientId"`
	SessionID string `json:"sessionId"`
	Scope     string `json:"scope"`
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

// issueOAuthGrant creates an access token (and, when offline_access is granted,
// a rotating refresh token) for the given client/user/session and returns the
// token response. A non-empty parentRefreshID links tokens created by rotation.
func issueOAuthGrant(c *auth.Context, ext store.ExtStore, clientID, userID, sessionID string, scopes []string) (oidcTokenResponse, error) {
	now := time.Now().UTC()
	accessID, _ := id.Generate(32)
	accessTok, _ := id.Generate(32)
	refreshID := ""
	refreshTok := ""
	if hasScope(scopes, "offline_access") {
		refreshID, _ = id.Generate(32)
		refreshTok, _ = id.Generate(32)
		if err := ext.CreateOAuthRefreshToken(c.R.Context(), &types.OAuthRefreshToken{
			ID: refreshID, Token: refreshTok, ClientID: clientID, SessionID: sessionID, UserID: userID,
			Scopes: scopes, ExpiresAt: now.Add(refreshTokenTTL), CreatedAt: now,
		}); err != nil {
			return oidcTokenResponse{}, err
		}
	}
	if err := ext.CreateOAuthAccessToken(c.R.Context(), &types.OAuthAccessToken{
		ID: accessID, Token: accessTok, ClientID: clientID, SessionID: sessionID, UserID: userID,
		Scopes: scopes, RefreshID: refreshID, ExpiresAt: now.Add(accessTokenTTL), CreatedAt: now,
	}); err != nil {
		return oidcTokenResponse{}, err
	}
	return oidcTokenResponse{
		AccessToken:  accessTok,
		TokenType:    constants.TokenTypeBearer,
		ExpiresIn:    int(accessTokenTTL.Seconds()),
		Scope:        strings.Join(scopes, " "),
		RefreshToken: refreshTok,
	}, nil
}

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
		sess, user, err := c.GetSession()
		if err != nil {
			login := opts.LoginPage
			if login == "" {
				login = "/"
			}
			c.Redirect(login)
			return
		}
		code, _ := id.Generate(32)
		data, _ := json.Marshal(oidcCodeData{
			UserID:    user.ID,
			ClientID:  c.R.URL.Query().Get("client_id"),
			SessionID: sess.ID,
			Scope:     c.R.URL.Query().Get("scope"),
		})
		_ = c.Auth.CreateVerification(c.R.Context(), constants.VerificationOIDCCode+code, string(data), 10*time.Minute)
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
		switch body.GrantType {
		case "refresh_token":
			oidcRefreshTokenGrant(c, ext, body.ClientID, body.RefreshToken)
		default: // authorization_code (default preserves prior behaviour)
			oidcAuthorizationCodeGrant(c, ext, body.Code)
		}
	}
}

func oidcAuthorizationCodeGrant(c *auth.Context, ext store.ExtStore, code string) {
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
	resp, err := issueOAuthGrant(c, ext, data.ClientID, data.UserID, data.SessionID, scopeList(data.Scope))
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
func oidcRefreshTokenGrant(c *auth.Context, ext store.ExtStore, clientID, refreshToken string) {
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
	resp, err := issueOAuthGrant(c, ext, rt.ClientID, rt.UserID, rt.SessionID, rt.Scopes)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
		return
	}
	replay, _ := json.Marshal(resp)
	_ = ext.RotateOAuthRefreshToken(c.R.Context(), rt.ID, string(replay), now.Add(refreshReplayWindow))
	c.WriteJSON(http.StatusOK, resp)
}

func oidcUserInfoHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		ext, ok := requireOAuthStore(c)
		if !ok {
			return
		}
		token := c.R.Header.Get(constants.HeaderAuthorization)
		bearerPrefix := constants.TokenTypeBearer + " "
		if len(token) > len(bearerPrefix) && strings.EqualFold(token[:len(bearerPrefix)], bearerPrefix) {
			token = token[len(bearerPrefix):]
		}
		at, err := ext.FindOAuthAccessToken(c.R.Context(), token)
		if err != nil || at.Revoked != nil || at.ExpiresAt.Before(time.Now().UTC()) {
			c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeUnauthorized))
			return
		}
		user, err := c.Auth.Store().FindUserByID(c.R.Context(), at.UserID)
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
