package plugins

import (
	"strings"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/constants"
)

// BearerOptions configures the bearer token plugin.
type BearerOptions struct {
	RequireSignature bool
}

// Bearer enables session authentication via Authorization: Bearer header.
func Bearer(opts BearerOptions) auth.Plugin {
	return basePlugin{
		id: constants.PluginBearer,
		hooks: &auth.PluginHooks{
			Before: []func(*auth.Context) bool{
				func(c *auth.Context) bool {
					authHeader := c.R.Header.Get(constants.HeaderAuthorization)
					if authHeader == "" {
						return true
					}
					bearerPrefix := strings.ToLower(constants.TokenTypeBearer) + " "
					if len(authHeader) < len(bearerPrefix) || strings.ToLower(authHeader[:len(bearerPrefix)]) != bearerPrefix {
						return true
					}
					token := strings.TrimSpace(authHeader[len(bearerPrefix):])
					if token == "" {
						return true
					}
					decoded := token
					if strings.Contains(token, ".") {
						if v, ok := c.Auth.VerifySignedSessionToken(token); ok {
							decoded = v
						}
					} else if opts.RequireSignature {
						return true
					}
					c.SetSessionTokenOverride(decoded)
					return true
				},
			},
		},
	}
}
