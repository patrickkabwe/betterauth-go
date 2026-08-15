package plugins

import "github.com/patrickkabwe/betterauth-go/auth"

// clientPluginPackage is the official TS client plugins entry point.
const clientPluginPackage = "better-auth/client/plugins"

// clientPluginImports maps server plugin IDs to TS client plugin factory exports.
var clientPluginImports = map[string]string{
	"admin":                "adminClient",
	"anonymous":            "anonymousClient",
	"device-authorization": "deviceAuthorizationClient",
	"email-otp":            "emailOTPClient",
	"generic-oauth":        "genericOAuthClient",
	"jwt":                  "jwtClient",
	"last-login-method":    "lastLoginMethodClient",
	"magic-link":           "magicLinkClient",
	"multi-session":        "multiSessionClient",
	"custom-session":       "customSessionClient",
	"oidc-provider":        "oidcClient",
	"oauth-provider":       "oauthProviderClient",
	"one-tap":              "oneTapClient",
	"one-time-token":       "oneTimeTokenClient",
	"organization":         "organizationClient",
	"phone-number":         "phoneNumberClient",
	"siwe":                 "siweClient",
	"two-factor":           "twoFactorClient",
	"username":             "usernameClient",
	"api-key":              "apiKeyClient",
	"passkey":              "passkeyClient",
	"sso":                  "ssoClient",
	"scim":                 "scimClient",
	"stripe":               "stripeClient",
	"i18n":                 "i18nClient",
}

func clientPluginInfo(pluginID string) *auth.ClientPluginInfo {
	imp, ok := clientPluginImports[pluginID]
	if !ok {
		return nil
	}
	return &auth.ClientPluginInfo{
		Package: clientPluginPackage,
		Import:  imp,
	}
}
