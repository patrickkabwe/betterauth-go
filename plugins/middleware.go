package plugins

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/apierror"
	"github.com/patrickkabwe/betterauth-go/types"
)

// CaptchaOptions configures captcha verification.
type CaptchaOptions struct {
	Provider   string // turnstile, recaptcha, hcaptcha
	SecretKey  string
	VerifyURL  string
	Endpoints  []string
	HeaderName string
}

// Captcha validates captcha tokens on protected endpoints.
func Captcha(opts CaptchaOptions) auth.Plugin {
	paths := opts.Endpoints
	if len(paths) == 0 {
		paths = []string{"/sign-up/email", "/sign-in/email", "/request-password-reset"}
	}
	header := opts.HeaderName
	if header == "" {
		header = constants.HeaderCaptchaResponse
	}
	return basePlugin{
		id: constants.PluginCaptcha,
		hooks: &auth.PluginHooks{
			Before: []func(*auth.Context) bool{
				func(c *auth.Context) bool {
					path := c.R.URL.Path
					if !strings.HasSuffix(path, c.Auth.BasePath()) {
						path = strings.TrimPrefix(path, c.Auth.BasePath())
					}
					matched := false
					for _, p := range paths {
						if strings.HasSuffix(path, p) || path == p {
							matched = true
							break
						}
					}
					if !matched {
						return true
					}
					token := c.R.Header.Get(header)
					if token == "" {
						c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeCaptchaRequired))
						return false
					}
					if opts.SecretKey != "" && !verifyCaptcha(opts, token, c.ClientIP()) {
						c.WriteError(apierror.WithCode(http.StatusBadRequest, constants.CodeCaptchaInvalid))
						return false
					}
					return true
				},
			},
		},
	}
}

func verifyCaptcha(opts CaptchaOptions, token, ip string) bool {
	url := opts.VerifyURL
	if url == "" {
		switch opts.Provider {
		case "turnstile":
			url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
		default:
			url = "https://www.google.com/recaptcha/api/siteverify"
		}
	}
	body := fmt.Sprintf("secret=%s&response=%s&remoteip=%s", opts.SecretKey, token, ip)
	resp, err := http.Post(url, "application/x-www-form-urlencoded", strings.NewReader(body))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var result struct {
		Success bool `json:"success"`
	}
	_ = json.Unmarshal(data, &result)
	return result.Success
}

// HaveIBeenPwnedOptions configures breached password checking.
type HaveIBeenPwnedOptions struct {
	MinBreachCount int
}

type hibpPlugin struct {
	basePlugin
	opts HaveIBeenPwnedOptions
}

func (h hibpPlugin) ValidatePassword(password string) error {
	min := h.opts.MinBreachCount
	if min == 0 {
		min = 1
	}
	sha := sha1.Sum([]byte(password))
	hash := strings.ToUpper(hex.EncodeToString(sha[:]))
	prefix := hash[:5]
	suffix := hash[5:]
	resp, err := http.Get("https://api.pwnedpasswords.com/range/" + prefix)
	if err != nil {
		return nil // fail open on network errors
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) == 2 && parts[0] == suffix {
			return fmt.Errorf(constants.MsgPasswordBreach)
		}
	}
	return nil
}

// HaveIBeenPwned rejects passwords found in known breaches.
func HaveIBeenPwned(opts HaveIBeenPwnedOptions) auth.Plugin {
	return hibpPlugin{basePlugin: basePlugin{id: constants.PluginHaveIBeenPwned}, opts: opts}
}

// LastLoginMethodOptions configures login method tracking.
type LastLoginMethodOptions struct {
	StoreInCookie bool
}

// LastLoginMethod tracks how the user last signed in.
func LastLoginMethod(opts LastLoginMethodOptions) auth.Plugin {
	return basePlugin{
		id: constants.PluginLastLoginMethod,
		hooks: &auth.PluginHooks{
			After: []func(*auth.Context){
				func(c *auth.Context) {
					method := c.R.Header.Get(constants.HeaderLastLoginMethod)
					if method == "" {
						return
					}
					sess, user, err := c.GetSession()
					if err != nil {
						return
					}
					_, _ = c.Auth.SetUserAdditional(c.R.Context(), user.ID, map[string]any{
						constants.FieldLastLoginMethod: method,
					})
					if opts.StoreInCookie {
						http.SetCookie(c.W, &http.Cookie{
							Name: constants.CookieLastLoginMethod, Value: method,
							Path: "/", MaxAge: int((365 * 24 * time.Hour).Seconds()),
						})
					}
					_ = sess
				},
			},
		},
	}
}

// CustomSessionOptions transforms get-session responses.
type CustomSessionOptions struct {
	Transform func(ctx context.Context, session types.Session, user types.User) (map[string]any, error)
}

// CustomSession overrides GET/POST /get-session with custom data.
func CustomSession(opts CustomSessionOptions) auth.Plugin {
	return basePlugin{
		id: constants.PluginCustomSession,
		routes: []auth.PluginRoute{
			rt(http.MethodGet, "/get-session", customSessionHandler(opts)),
			rt(http.MethodPost, "/get-session", customSessionHandler(opts)),
		},
	}
}

func customSessionHandler(opts CustomSessionOptions) func(*auth.Context) {
	return func(c *auth.Context) {
		sess, user, err := c.GetSession()
		if err != nil {
			c.WriteNull()
			return
		}
		if opts.Transform == nil {
			c.WriteJSON(http.StatusOK, types.SessionResponse{Session: *sess, User: *user})
			return
		}
		out, err := opts.Transform(c.R.Context(), *sess, *user)
		if err != nil {
			c.WriteError(apierror.WithCode(http.StatusInternalServerError, constants.CodeInternalServerError))
			return
		}
		c.WriteJSON(http.StatusOK, out)
	}
}
