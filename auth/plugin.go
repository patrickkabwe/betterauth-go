package auth

import (
	"net/http"

	"github.com/patrickkabwe/betterauth-go/types"
)

// Plugin extends Better Auth with routes and lifecycle hooks.
type Plugin interface {
	ID() string
	Routes() []PluginRoute
	Hooks() *PluginHooks
}

// PasswordValidatorPlugin optionally validates passwords (e.g. have-i-been-pwned).
type PasswordValidatorPlugin interface {
	Plugin
	ValidatePassword(password string) error
}

// EmailVerificationSenderPlugin can replace the core verification email sender.
type EmailVerificationSenderPlugin interface {
	Plugin
	OverrideEmailVerification() bool
	SendVerificationEmail(c *Context, user *types.User) error
}

// SignUpVerificationPlugin can send additional verification after email sign-up.
type SignUpVerificationPlugin interface {
	Plugin
	SendVerificationOnSignUp() bool
	SendSignUpVerification(c *Context, user *types.User) error
}

// PluginRoute is an HTTP route registered by a plugin.
type PluginRoute struct {
	Method     string
	Pattern    string
	Handler    func(*Context)
	ServerOnly bool
}

// PluginHooks configures request/response middleware for a plugin.
type PluginHooks struct {
	// Before runs before route handlers. Return false to stop processing.
	Before []func(*Context) bool
	// After runs after a handler writes a response (best-effort via defer in router).
	After []func(*Context)
}

// noopPlugin is a helper embed for plugins without hooks.
type noopPlugin struct{}

func (noopPlugin) Hooks() *PluginHooks { return nil }

func mergePluginRoutes(base []route, plugins []Plugin) []route {
	if len(plugins) == 0 {
		return base
	}
	overrides := make(map[string]route)
	var extra []route
	for _, p := range plugins {
		for _, r := range p.Routes() {
			key := r.Method + " " + r.Pattern
			rt := route{method: r.Method, pattern: r.Pattern, handler: r.Handler}
			if r.Pattern == "/get-session" && (r.Method == http.MethodGet || r.Method == http.MethodPost) {
				overrides[key] = rt
				continue
			}
			extra = append(extra, rt)
		}
	}
	out := make([]route, 0, len(base)+len(extra))
	for _, rt := range base {
		key := rt.method + " " + rt.pattern
		if o, ok := overrides[key]; ok {
			out = append(out, o)
			delete(overrides, key)
			continue
		}
		out = append(out, rt)
	}
	for _, rt := range overrides {
		out = append(out, rt)
	}
	out = append(out, extra...)
	return out
}

func runPluginBeforeHooks(c *Context, plugins []Plugin) bool {
	for _, p := range plugins {
		h := p.Hooks()
		if h == nil {
			continue
		}
		for _, fn := range h.Before {
			if fn != nil && !fn(c) {
				return false
			}
		}
	}
	return true
}

func runPluginAfterHooks(c *Context, plugins []Plugin) {
	for _, p := range plugins {
		h := p.Hooks()
		if h == nil {
			continue
		}
		for _, fn := range h.After {
			if fn != nil {
				fn(c)
			}
		}
	}
	if c.pendingAuthToken != "" && !c.authTokenExposed {
		c.ExposeAuthToken(c.pendingAuthToken)
	}
}

func emailVerificationOverridePlugin(plugins []Plugin) (EmailVerificationSenderPlugin, bool) {
	for _, plugin := range plugins {
		sender, ok := plugin.(EmailVerificationSenderPlugin)
		if ok && sender.OverrideEmailVerification() {
			return sender, true
		}
	}
	return nil, false
}

func runSignUpVerificationPlugins(c *Context, plugins []Plugin, user *types.User) error {
	for _, plugin := range plugins {
		sender, ok := plugin.(SignUpVerificationPlugin)
		if !ok || !sender.SendVerificationOnSignUp() {
			continue
		}
		if err := sender.SendSignUpVerification(c, user); err != nil {
			return err
		}
	}
	return nil
}
