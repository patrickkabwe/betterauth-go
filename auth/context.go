package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/patrickkabwe/betterauth-go/constants"
	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/internal/cookie"
	"github.com/patrickkabwe/betterauth-go/types"
)

// Context carries request state for a single HTTP call.
type Context struct {
	Auth *Auth
	W    http.ResponseWriter
	R    *http.Request
	Vars map[string]string

	sessionTokenOverride string
	sessionOverride      *types.Session
	userOverride         *types.User
	authTokenExposed     bool
	pendingAuthToken     string
}

func (c *Context) WriteJSON(status int, v any) {
	c.W.Header().Set(constants.HeaderContentType, constants.MIMEJSON)
	c.W.WriteHeader(status)
	_ = json.NewEncoder(c.W).Encode(v)
}

func (c *Context) WriteNull() {
	c.W.Header().Set(constants.HeaderContentType, constants.MIMEJSON)
	c.W.WriteHeader(http.StatusOK)
	_, _ = c.W.Write([]byte("null"))
}

func (c *Context) WriteError(err *apierror.Error) {
	if c.Auth != nil && c.Auth.cfg.onAPIError.OnError != nil {
		c.Auth.cfg.onAPIError.OnError(err, c)
	}
	apierror.WriteJSON(c.W, err)
}

func (c *Context) Redirect(url string) {
	http.Redirect(c.W, c.R, url, http.StatusFound)
}

func (c *Context) ParseJSON(v any) error {
	if isFormURLEncoded(c.R.Header.Get(constants.HeaderContentType)) {
		defer c.R.Body.Close()
		if err := c.R.ParseForm(); err != nil {
			return err
		}
		body, err := marshalFormBody(c.R.PostForm, v)
		if err != nil {
			return err
		}
		return json.Unmarshal(body, v)
	}
	defer c.R.Body.Close()
	body, err := io.ReadAll(io.LimitReader(c.R.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, v)
}

func isFormURLEncoded(contentType string) bool {
	return strings.HasPrefix(strings.ToLower(contentType), "application/x-www-form-urlencoded")
}

func marshalFormBody(values url.Values, dst any) ([]byte, error) {
	obj := make(map[string]any, len(values))
	boolFields := jsonBoolFields(dst)
	for key, list := range values {
		if len(list) == 0 {
			continue
		}
		value := list[0]
		if boolFields[key] {
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return nil, err
			}
			obj[key] = parsed
			continue
		}
		obj[key] = value
	}
	return json.Marshal(obj)
}

func jsonBoolFields(dst any) map[string]bool {
	fields := map[string]bool{"rememberMe": true}
	t := reflect.TypeOf(dst)
	if t == nil {
		return fields
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return fields
	}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		ft := field.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Bool {
			fields[name] = true
		}
	}
	return fields
}

func (c *Context) ClientIP() string {
	// When IP tracking is disabled, never read forwarding headers or the peer
	// address (advanced.disableIpTracking).
	if c.Auth != nil && c.Auth.cfg.disableIPTracking {
		return ""
	}

	// Honor explicitly configured trusted headers first, in order.
	headers := []string{"X-Forwarded-For", "X-Real-IP"}
	if c.Auth != nil && len(c.Auth.cfg.ipAddressHeaders) > 0 {
		headers = c.Auth.cfg.ipAddressHeaders
	}
	for _, h := range headers {
		if v := c.R.Header.Get(h); v != "" {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
	}

	host := c.R.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}

func (c *Context) SessionToken() (string, bool) {
	if c.sessionTokenOverride != "" {
		return c.sessionTokenOverride, true
	}
	return cookie.GetSessionTokenAny(c.R, c.Auth.cfg.cookie, c.Auth.cfg.secrets)
}

// SetSessionTokenOverride injects a bearer token as the active session token.
func (c *Context) SetSessionTokenOverride(token string) {
	c.sessionTokenOverride = token
}

// SetSessionOverride injects an already-authenticated session and user.
func (c *Context) SetSessionOverride(sess *types.Session, user *types.User) {
	c.sessionOverride = sess
	c.userOverride = user
}

// MarkAuthToken queues a session token for bearer clients and exposes the header
// before the response body is written (headers cannot be set after WriteHeader).
func (c *Context) MarkAuthToken(token string) {
	c.pendingAuthToken = token
	c.ExposeAuthToken(token)
}

// ExposeAuthToken adds set-auth-token to the response for bearer clients.
func (c *Context) ExposeAuthToken(token string) {
	if token == "" || c.authTokenExposed {
		return
	}
	c.W.Header().Set("set-auth-token", token)
	exposed := c.W.Header().Get("Access-Control-Expose-Headers")
	if exposed == "" {
		c.W.Header().Set("Access-Control-Expose-Headers", "set-auth-token")
	} else if !strings.Contains(exposed, "set-auth-token") {
		c.W.Header().Set("Access-Control-Expose-Headers", exposed+", set-auth-token")
	}
	c.authTokenExposed = true
}

func (c *Context) GetSession() (*types.Session, *types.User, error) {
	token, ok := c.SessionToken()
	if !ok {
		return nil, nil, berrors.ErrNotFound
	}
	return c.Auth.cfg.store.FindSessionByToken(c.R.Context(), token)
}

func (c *Context) RequireSession() (*types.Session, *types.User, bool) {
	return c.requireSessionWithOpts(SessionOpts{})
}

func toUserResponse(u *types.User) types.User {
	return *u
}

func toSessionResponse(s *types.Session) types.Session {
	return *s
}

func toAccountResponse(a types.Account) types.AccountResponse {
	scopes := []string{}
	if a.Scope != "" {
		scopes = strings.Split(a.Scope, ",")
	}
	return types.AccountResponse{
		ID:         a.ID,
		AccountID:  a.AccountID,
		ProviderID: a.ProviderID,
		UserID:     a.UserID,
		Scopes:     scopes,
		CreatedAt:  a.CreatedAt,
		UpdatedAt:  a.UpdatedAt,
	}
}
