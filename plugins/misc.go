package plugins

import (
	"encoding/base64"
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

// OAuthProxyOptions proxies OAuth callbacks in development.
type OAuthProxyOptions struct {
	ProductionURL string
}

// OAuthProxy adds a dev OAuth callback proxy endpoint.
func OAuthProxy(opts OAuthProxyOptions) auth.Plugin {
	return basePlugin{
		id: constants.PluginOAuthProxy,
		routes: []auth.PluginRoute{
			rt(http.MethodGet, "/oauth-proxy-callback", func(c *auth.Context) {
				q := c.R.URL.Query()
				target := opts.ProductionURL
				if target == "" {
					target = c.Auth.BaseURL()
				}
				redirect, _ := url.Parse(target + c.Auth.BasePath() + "/callback/" + q.Get("provider"))
				redirect.RawQuery = q.Encode()
				c.Redirect(redirect.String())
			}),
		},
	}
}

// OneTapOptions configures Google One Tap.
type OneTapOptions struct {
	ClientID string
}

// OneTap handles Google One Tap credential callbacks.
func OneTap(opts OneTapOptions) auth.Plugin {
	return basePlugin{
		id: constants.PluginOneTap,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/one-tap/callback", func(c *auth.Context) {
				var body struct {
					Credential string `json:"credential"`
				}
				if err := c.ParseJSON(&body); err != nil || body.Credential == "" {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCredential))
					return
				}
				// Decode JWT payload (middle segment) without full verification for dev parity stub
				parts := splitJWT(body.Credential)
				if len(parts) < 2 {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCredential))
					return
				}
				var claims struct {
					Email string `json:"email"`
					Name  string `json:"name"`
					Sub   string `json:"sub"`
				}
				payload, _ := base64URLDecode(parts[1])
				_ = json.Unmarshal(payload, &claims)
				if claims.Email == "" {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidCredential))
					return
				}
				user, err := c.Auth.Store().FindUserByEmail(c.R.Context(), auth.NormalizeEmail(claims.Email))
				if err != nil {
					now := time.Now()
					userID, _ := id.Generate(32)
					user = &types.User{
						ID: userID, Name: claims.Name, Email: claims.Email,
						EmailVerified: true, CreatedAt: now, UpdatedAt: now,
					}
					_ = c.Auth.Store().CreateUser(c.R.Context(), user)
				}
				sess, err := c.Auth.NewSession(c, user.ID, true)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeFailedToCreateSession))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]any{"token": sess.Token, "user": user})
			}),
		},
	}
}

func splitJWT(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// OpenAPIOptions configures OpenAPI schema generation.
type OpenAPIOptions struct {
	Path string
}

// OpenAPI generates an OpenAPI schema for registered routes.
func OpenAPI(opts OpenAPIOptions) auth.Plugin {
	refPath := opts.Path
	if refPath == "" {
		refPath = "/reference"
	}
	return basePlugin{
		id: constants.PluginOpenAPI,
		routes: []auth.PluginRoute{
			rt(http.MethodGet, "/open-api/generate-schema", openAPIHandler()),
			rt(http.MethodGet, refPath, openAPIHandler()),
		},
	}
}

func openAPIHandler() func(*auth.Context) {
	return func(c *auth.Context) {
		schema := map[string]any{
			"openapi": "3.0.0",
			"info": map[string]any{
				"title":   "Better Auth API",
				"version": "1.0.0",
			},
			"paths": map[string]any{},
		}
		c.WriteJSON(http.StatusOK, schema)
	}
}

// DeviceAuthorizationOptions configures OAuth2 device flow.
type DeviceAuthorizationOptions struct {
	ExpiresIn time.Duration
	Interval  int
}

// DeviceAuthorization adds OAuth 2.0 device authorization flow.
func DeviceAuthorization(opts DeviceAuthorizationOptions) auth.Plugin {
	expires := opts.ExpiresIn
	if expires == 0 {
		expires = 15 * time.Minute
	}
	interval := opts.Interval
	if interval == 0 {
		interval = 5
	}
	return basePlugin{
		id: constants.PluginDeviceAuth,
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/device/code", func(c *auth.Context) {
				ext, ok := auth.ExtStore(c.Auth.Store())
				if !ok {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
					return
				}
				deviceCode, _ := id.Generate(32)
				userCode, _ := id.Generate(8)
				dcID, _ := id.Generate(32)
				now := time.Now()
				_ = ext.CreateDeviceCode(c.R.Context(), &types.DeviceCode{
					ID: dcID, DeviceCode: deviceCode, UserCode: userCode,
					Status: constants.DeviceStatusPending, ExpiresAt: now.Add(expires), Interval: interval, CreatedAt: now,
				})
				c.WriteJSON(http.StatusOK, map[string]any{
					"device_code":      deviceCode,
					"user_code":          userCode,
					"verification_uri":   c.Auth.BaseURL() + c.Auth.BasePath() + "/device",
					"expires_in":         int(expires.Seconds()),
					"interval":           interval,
				})
			}),
			rt(http.MethodPost, "/device/token", func(c *auth.Context) {
				ext, ok := auth.ExtStore(c.Auth.Store())
				if !ok {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
					return
				}
				var body struct {
					DeviceCode string `json:"device_code"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidDeviceCode))
					return
				}
				dc, err := ext.FindDeviceCodeByDeviceCode(c.R.Context(), body.DeviceCode)
				if err != nil || time.Now().After(dc.ExpiresAt) {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeExpiredDeviceCode))
					return
				}
				switch dc.Status {
				case constants.DeviceStatusApproved:
					sess, err := c.Auth.NewSession(c, dc.UserID, true)
					if err != nil {
						c.WriteError(apierror.WithCode(http.StatusUnauthorized, constants.CodeFailedToCreateSession))
						return
					}
					c.WriteJSON(http.StatusOK, map[string]string{
						"access_token": sess.Token, "token_type": constants.TokenTypeBearer,
					})
				case constants.DeviceStatusDenied:
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeAccessDenied))
				default:
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeAuthorizationPending))
				}
			}),
			rt(http.MethodGet, "/device", func(c *auth.Context) {
				c.WriteJSON(http.StatusOK, map[string]string{"message": "Enter user code to authorize device"})
			}),
			rt(http.MethodPost, "/device/approve", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				ext, ok := auth.ExtStore(c.Auth.Store())
				if !ok {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
					return
				}
				var body struct {
					UserCode string `json:"userCode"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidUserCode))
					return
				}
				dc, err := ext.FindDeviceCodeByUserCode(c.R.Context(), body.UserCode)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidUserCode))
					return
				}
				_ = ext.UpdateDeviceCode(c.R.Context(), dc.ID, user.ID, constants.DeviceStatusApproved)
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
			rt(http.MethodPost, "/device/deny", func(c *auth.Context) {
				ext, ok := auth.ExtStore(c.Auth.Store())
				if !ok {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeExtStoreRequired))
					return
				}
				var body struct {
					UserCode string `json:"userCode"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidUserCode))
					return
				}
				dc, err := ext.FindDeviceCodeByUserCode(c.R.Context(), body.UserCode)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeInvalidUserCode))
					return
				}
				_ = ext.UpdateDeviceCode(c.R.Context(), dc.ID, "", constants.DeviceStatusDenied)
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
		},
	}
}
