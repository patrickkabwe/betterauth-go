package plugins

import "github.com/patrickkabwe/betterauth-go/auth"

// AllOptions bundles optional configuration for every plugin.
type AllOptions struct {
	Bearer          BearerOptions
	MagicLink       MagicLinkOptions
	Anonymous       AnonymousOptions
	Username        UsernameOptions
	EmailOTP        EmailOTPOptions
	OneTimeToken    OneTimeTokenOptions
	JWT             JWTOptions
	MultiSession    MultiSessionOptions
	CustomSession   CustomSessionOptions
	LastLoginMethod LastLoginMethodOptions
	HaveIBeenPwned  HaveIBeenPwnedOptions
	Captcha         CaptchaOptions
	OAuthProxy      OAuthProxyOptions
	GenericOAuth    GenericOAuthOptions
	OneTap          OneTapOptions
	OpenAPI         OpenAPIOptions
	DeviceAuth      DeviceAuthorizationOptions
	PhoneNumber     PhoneNumberOptions
	SIWE            SIWEOptions
	TwoFactor       TwoFactorOptions
	Admin           AdminOptions
	Organization    OrganizationOptions
	OIDCProvider    OIDCProviderOptions
	MCP             MCPOptions
	APIKey          APIKeyOptions
	I18n            I18nOptions
	SCIM            SCIMOptions
	Stripe          StripeOptions
}

// All returns every core Better Auth plugin.
func All(opts AllOptions) []auth.Plugin {
	return []auth.Plugin{
		Bearer(opts.Bearer),
		MagicLink(opts.MagicLink),
		Anonymous(opts.Anonymous),
		Username(opts.Username),
		EmailOTP(opts.EmailOTP),
		OneTimeToken(opts.OneTimeToken),
		JWT(opts.JWT),
		MultiSession(opts.MultiSession),
		CustomSession(opts.CustomSession),
		LastLoginMethod(opts.LastLoginMethod),
		HaveIBeenPwned(opts.HaveIBeenPwned),
		Captcha(opts.Captcha),
		OAuthProxy(opts.OAuthProxy),
		GenericOAuth(opts.GenericOAuth),
		OneTap(opts.OneTap),
		OpenAPI(opts.OpenAPI),
		DeviceAuthorization(opts.DeviceAuth),
		PhoneNumber(opts.PhoneNumber),
		SIWE(opts.SIWE),
		TwoFactor(opts.TwoFactor),
		Admin(opts.Admin),
		Organization(opts.Organization),
		OIDCProvider(opts.OIDCProvider),
		MCP(opts.MCP),
		APIKey(opts.APIKey),
		I18n(opts.I18n),
		SCIM(opts.SCIM),
		Stripe(opts.Stripe),
	}
}
