package plugins

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

// APIKeyOptions configures the API key plugin.
type APIKeyOptions struct {
	Headers                 []string
	DefaultKeyLength        int
	Prefix                  string
	RequireName             bool
	EnableSessionForAPIKeys bool
	DefaultExpiresIn        time.Duration
	RateLimitMax            int
	RateLimitTimeWindow     time.Duration
}

// APIKey enables database-backed API key management.
func APIKey(opts APIKeyOptions) auth.Plugin {
	headers := opts.Headers
	if len(headers) == 0 {
		headers = []string{"x-api-key"}
	}
	keyLength := opts.DefaultKeyLength
	if keyLength == 0 {
		keyLength = 64
	}
	rateLimitMax := opts.RateLimitMax
	if rateLimitMax == 0 {
		rateLimitMax = 10
	}
	rateLimitWindow := opts.RateLimitTimeWindow
	if rateLimitWindow == 0 {
		rateLimitWindow = 24 * time.Hour
	}
	return basePlugin{
		id:        constants.PluginAPIKey,
		schemaIDs: []string{constants.PluginAPIKey},
		hooks: &auth.PluginHooks{Before: []func(*auth.Context) bool{
			func(c *auth.Context) bool {
				if !opts.EnableSessionForAPIKeys {
					return true
				}
				rawKey := apiKeyFromHeaders(c.R, headers)
				if rawKey == "" {
					return true
				}
				key, user, err := verifyAPIKey(c, rawKey)
				if err != nil {
					c.WriteError(apiKeyError(err))
					return false
				}
				now := time.Now().UTC()
				session := &types.Session{
					ID: key.ID, Token: rawKey, UserID: key.ReferenceID, ExpiresAt: apiKeySessionExpiry(key),
					IPAddress: c.ClientIP(), UserAgent: c.R.Header.Get("User-Agent"), CreatedAt: now, UpdatedAt: now,
				}
				c.SetSessionOverride(session, user)
				return true
			},
		}},
		routes: []auth.PluginRoute{
			rt(http.MethodPost, "/api-key/create", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				var body struct {
					Name        string         `json:"name"`
					Prefix      string         `json:"prefix"`
					ExpiresIn   int64          `json:"expiresIn"`
					ExpiresAt   *time.Time     `json:"expiresAt"`
					Permissions map[string]any `json:"permissions"`
					Metadata    map[string]any `json:"metadata"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
					return
				}
				if opts.RequireName && strings.TrimSpace(body.Name) == "" {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeMissingField, "name "+constants.MsgMissingField))
					return
				}
				ext, ok := apiKeyStore(c)
				if !ok {
					return
				}
				rawKey, err := generateAPIKey(keyLength, firstNonEmpty(body.Prefix, opts.Prefix))
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				now := time.Now().UTC()
				expiresAt := apiKeyExpiry(now, body.ExpiresAt, body.ExpiresIn, opts.DefaultExpiresIn)
				keyID, err := id.Generate(32)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				rec := &types.APIKey{
					ID: keyID, ConfigID: "default", Name: strings.TrimSpace(body.Name), Start: apiKeyStart(rawKey),
					ReferenceID: user.ID, Prefix: firstNonEmpty(body.Prefix, opts.Prefix), Key: hashAPIKey(rawKey),
					Enabled: true, RateLimitEnabled: true, RateLimitTimeWindow: rateLimitWindow.Milliseconds(),
					RateLimitMax: rateLimitMax, RequestCount: 0, ExpiresAt: expiresAt, CreatedAt: now, UpdatedAt: now,
					Permissions: marshalAPIKeyJSON(body.Permissions), Metadata: marshalAPIKeyJSON(body.Metadata),
				}
				if err := ext.CreateAPIKey(c.R.Context(), rec); err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]any{"key": rawKey, "apiKey": apiKeyResponse(rec)})
			}),
			rt(http.MethodGet, "/api-key/list", func(c *auth.Context) {
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				ext, ok := apiKeyStore(c)
				if !ok {
					return
				}
				keys, err := ext.ListAPIKeysByReference(c.R.Context(), user.ID)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				out := make([]map[string]any, 0, len(keys))
				for _, key := range keys {
					out = append(out, apiKeyResponse(&key))
				}
				c.WriteJSON(http.StatusOK, out)
			}),
			rt(http.MethodPost, "/api-key/get", func(c *auth.Context) {
				_, user, key, ok := requireOwnedAPIKey(c)
				if !ok {
					return
				}
				if key.ReferenceID != user.ID {
					c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeAccessDenied))
					return
				}
				c.WriteJSON(http.StatusOK, apiKeyResponse(key))
			}),
			rt(http.MethodPost, "/api-key/update", func(c *auth.Context) {
				var body struct {
					ID          string         `json:"id"`
					Name        *string        `json:"name"`
					Enabled     *bool          `json:"enabled"`
					ExpiresAt   *time.Time     `json:"expiresAt"`
					Permissions map[string]any `json:"permissions"`
					Metadata    map[string]any `json:"metadata"`
				}
				if err := c.ParseJSON(&body); err != nil {
					c.WriteError(apierror.New(http.StatusBadRequest, constants.CodeInvalidRequest, constants.MsgInvalidRequestBody))
					return
				}
				_, user, ok := c.RequireSession()
				if !ok {
					return
				}
				ext, ok := apiKeyStore(c)
				if !ok {
					return
				}
				key, err := ext.FindAPIKeyByID(c.R.Context(), body.ID)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeAPIKeyNotFound))
					return
				}
				if key.ReferenceID != user.ID {
					c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeAccessDenied))
					return
				}
				now := time.Now().UTC()
				update := store.APIKeyUpdate{UpdatedAt: &now, Name: body.Name, Enabled: body.Enabled, ExpiresAt: body.ExpiresAt}
				if body.Permissions != nil {
					permissions := marshalAPIKeyJSON(body.Permissions)
					update.Permissions = &permissions
				}
				if body.Metadata != nil {
					metadata := marshalAPIKeyJSON(body.Metadata)
					update.Metadata = &metadata
				}
				updated, err := ext.UpdateAPIKey(c.R.Context(), key.ID, update)
				if err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				c.WriteJSON(http.StatusOK, apiKeyResponse(updated))
			}),
			rt(http.MethodPost, "/api-key/delete", func(c *auth.Context) {
				ext, user, key, ok := requireOwnedAPIKey(c)
				if !ok {
					return
				}
				if key.ReferenceID != user.ID {
					c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeAccessDenied))
					return
				}
				if err := ext.DeleteAPIKey(c.R.Context(), key.ID); err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
			rt(http.MethodPost, "/api-key/verify", func(c *auth.Context) {
				var body struct {
					Key string `json:"key"`
				}
				if err := c.ParseJSON(&body); err != nil || body.Key == "" {
					c.WriteError(apierror.WithCode(http.StatusForbidden, constants.CodeInvalidAPIKey))
					return
				}
				key, _, err := verifyAPIKey(c, body.Key)
				if err != nil {
					c.WriteError(apiKeyError(err))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]any{"valid": true, "key": apiKeyResponse(key)})
			}),
			srt(http.MethodPost, "/api-key/delete-all-expired-api-keys", func(c *auth.Context) {
				ext, ok := apiKeyStore(c)
				if !ok {
					return
				}
				if err := ext.DeleteExpiredAPIKeys(c.R.Context(), time.Now().UTC()); err != nil {
					c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
					return
				}
				c.WriteJSON(http.StatusOK, map[string]bool{"success": true})
			}),
		},
	}
}

func apiKeyStore(c *auth.Context) (store.ExtStore, bool) {
	ext, ok := auth.ExtStore(c.Auth.Store())
	if !ok {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeExtStoreRequired))
		return nil, false
	}
	return ext, true
}

func requireOwnedAPIKey(c *auth.Context) (store.ExtStore, *types.User, *types.APIKey, bool) {
	_, user, ok := c.RequireSession()
	if !ok {
		return nil, nil, nil, false
	}
	ext, ok := apiKeyStore(c)
	if !ok {
		return nil, nil, nil, false
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := c.ParseJSON(&body); err != nil || body.ID == "" {
		c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeAPIKeyNotFound))
		return nil, nil, nil, false
	}
	key, err := ext.FindAPIKeyByID(c.R.Context(), body.ID)
	if err != nil {
		c.WriteError(apierror.WithCode(http.StatusNotFound, constants.CodeAPIKeyNotFound))
		return nil, nil, nil, false
	}
	return ext, user, key, true
}

func verifyAPIKey(c *auth.Context, rawKey string) (*types.APIKey, *types.User, error) {
	ext, ok := auth.ExtStore(c.Auth.Store())
	if !ok {
		return nil, nil, apiKeyErrStore
	}
	key, err := ext.FindAPIKeyByKey(c.R.Context(), hashAPIKey(rawKey))
	if err != nil {
		return nil, nil, apiKeyErrInvalid
	}
	now := time.Now().UTC()
	if !key.Enabled {
		return nil, nil, apiKeyErrDisabled
	}
	if key.ExpiresAt != nil && key.ExpiresAt.Before(now) {
		return nil, nil, apiKeyErrExpired
	}
	user, err := c.Auth.Store().FindUserByID(c.R.Context(), key.ReferenceID)
	if err != nil {
		return nil, nil, apiKeyErrInvalid
	}
	count := key.RequestCount + 1
	_, _ = ext.UpdateAPIKey(c.R.Context(), key.ID, store.APIKeyUpdate{RequestCount: &count, LastRequest: &now, UpdatedAt: &now})
	return key, user, nil
}

type apiKeyPluginError string

const (
	apiKeyErrInvalid  apiKeyPluginError = "invalid"
	apiKeyErrDisabled apiKeyPluginError = "disabled"
	apiKeyErrExpired  apiKeyPluginError = "expired"
	apiKeyErrStore    apiKeyPluginError = "store"
)

func (e apiKeyPluginError) Error() string {
	return string(e)
}

func apiKeyError(err error) *apierror.Error {
	switch err {
	case apiKeyErrDisabled:
		return apierror.WithCode(http.StatusForbidden, constants.CodeAPIKeyDisabled)
	case apiKeyErrExpired:
		return apierror.WithCode(http.StatusForbidden, constants.CodeAPIKeyExpired)
	case apiKeyErrStore:
		return apierror.WithCode(http.StatusBadRequest, constants.CodeExtStoreRequired)
	default:
		return apierror.WithCode(http.StatusForbidden, constants.CodeInvalidAPIKey)
	}
}

func apiKeyFromHeaders(r *http.Request, headers []string) string {
	for _, header := range headers {
		value := strings.TrimSpace(r.Header.Get(header))
		if value != "" {
			return value
		}
	}
	return ""
}

func generateAPIKey(length int, prefix string) (string, error) {
	randomLength := length
	if randomLength < 1 {
		randomLength = 64
	}
	bytes := make([]byte, randomLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	key := base64.RawURLEncoding.EncodeToString(bytes)
	if len(key) > randomLength {
		key = key[:randomLength]
	}
	return prefix + key, nil
}

func hashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func apiKeyStart(key string) string {
	if len(key) <= 6 {
		return key
	}
	return key[:6]
}

func apiKeyExpiry(now time.Time, explicit *time.Time, expiresIn int64, defaultExpiresIn time.Duration) *time.Time {
	if explicit != nil {
		return explicit
	}
	if expiresIn > 0 {
		expires := now.Add(time.Duration(expiresIn) * time.Second)
		return &expires
	}
	if defaultExpiresIn > 0 {
		expires := now.Add(defaultExpiresIn)
		return &expires
	}
	return nil
}

func apiKeySessionExpiry(key *types.APIKey) time.Time {
	if key.ExpiresAt != nil {
		return *key.ExpiresAt
	}
	return time.Now().UTC().Add(24 * time.Hour)
}

func marshalAPIKeyJSON(value map[string]any) string {
	if value == nil {
		return ""
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(raw)
}

func apiKeyResponse(key *types.APIKey) map[string]any {
	return map[string]any{
		"id": key.ID, "configId": key.ConfigID, "name": key.Name, "start": key.Start,
		"referenceId": key.ReferenceID, "prefix": key.Prefix, "enabled": key.Enabled,
		"rateLimitEnabled": key.RateLimitEnabled, "rateLimitTimeWindow": key.RateLimitTimeWindow,
		"rateLimitMax": key.RateLimitMax, "requestCount": key.RequestCount, "remaining": key.Remaining,
		"lastRequest": key.LastRequest, "expiresAt": key.ExpiresAt, "createdAt": key.CreatedAt,
		"updatedAt": key.UpdatedAt, "permissions": key.Permissions, "metadata": key.Metadata,
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
