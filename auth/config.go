package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/constants"
	"github.com/patrickkabwe/betterauth-go/internal/cookie"
	"github.com/patrickkabwe/betterauth-go/internal/crypto"
	"github.com/patrickkabwe/betterauth-go/provider"
	"github.com/patrickkabwe/betterauth-go/provider/github"
	"github.com/patrickkabwe/betterauth-go/provider/google"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

const (
	defaultBasePath             = "/api/auth"
	defaultSessionExpires       = 7 * 24 * time.Hour
	defaultSessionCookie        = 7 * 24 * 60 * 60
	defaultDontRemember         = 24 * time.Hour
	defaultSessionUpdateAge     = 24 * time.Hour
	defaultMinPassword          = 8
	defaultMaxPassword          = 128
	defaultVerificationExpires  = time.Hour
	defaultResetPasswordExpires = time.Hour
	defaultFreshAge             = 24 * time.Hour
	defaultCookieCacheMaxAge    = 5 * time.Minute
)

// Config configures a Better Auth instance.
type Config struct {
	Secret string
	// OldSecrets lets you rotate Secret without invalidating existing signed
	// cookies and tokens. New values are always signed with Secret; verification
	// also accepts any value listed here (most recent first).
	OldSecrets       []string
	BaseURL          string
	BasePath         string
	Store            store.Store
	TrustedOrigins   []string
	CookiePrefix     string
	UseSecureCookies bool
	DisableSignUp    bool
	AppName          string

	EmailAndPassword  EmailAndPasswordConfig
	EmailVerification EmailVerificationConfig
	Session           SessionConfig
	User              UserConfig
	Account           AccountConfig
	SocialProviders   map[string]provider.SocialProvider
	Google            GoogleProviderConfig
	GitHub            GitHubProviderConfig

	Advanced         AdvancedConfig
	Database         DatabaseConfig
	RateLimit        RateLimitConfig
	SecondaryStorage SecondaryStorage
	Hooks            HooksConfig
	DatabaseHooks    DatabaseHooksConfig
	OnAPIError       OnAPIErrorConfig
	DisabledPaths    []string

	Hasher  crypto.Hasher
	Plugins []Plugin
}

// GoogleProviderConfig configures the built-in Google OAuth provider.
type GoogleProviderConfig struct {
	ClientID              string
	ClientSecret          string
	Scopes                []string
	Disabled              bool
	DisableImplicitSignUp bool
	DisableSignUp         bool
}

// GitHubProviderConfig configures the built-in GitHub OAuth provider.
type GitHubProviderConfig struct {
	ClientID              string
	ClientSecret          string
	Scopes                []string
	Disabled              bool
	DisableImplicitSignUp bool
	DisableSignUp         bool
}

// AccountConfig configures account linking and management.
type AccountConfig struct {
	AccountLinking AccountLinkingConfig
}

// AccountLinkingConfig configures social account linking rules.
type AccountLinkingConfig struct {
	// Enabled defaults to true when nil.
	Enabled                   *bool
	TrustedProviders          []string
	AllowDifferentEmails      bool
	AllowUnlinkingAll         bool
	UpdateUserInfoOnLink      bool
	DisableImplicitLinking    bool
	RequireLocalEmailVerified *bool
}

// EmailAndPasswordConfig configures email/password authentication.
type EmailAndPasswordConfig struct {
	Enabled                       bool
	RequireEmailVerification      bool
	AutoSignIn                    *bool
	MinPasswordLength             int
	MaxPasswordLength             int
	SendResetPassword             func(ctx context.Context, data types.ResetPasswordEmailData) error
	ResetPasswordTokenExpiresIn   time.Duration
	RevokeSessionsOnPasswordReset bool
}

// EmailVerificationConfig configures email verification.
type EmailVerificationConfig struct {
	SendVerificationEmail func(ctx context.Context, data types.VerificationEmailData) error
	SendOnSignUp          *bool
	SendOnSignIn          bool
	ExpiresIn             time.Duration
}

// CookieCacheConfig configures the session_data cookie cache.
type CookieCacheConfig struct {
	Enabled bool
	MaxAge  time.Duration
	// Strategy is "compact" (default). JWT and JWE are reserved for future use.
	Strategy string
	Version  string
}

// SessionConfig configures session behavior.
type SessionConfig struct {
	ExpiresIn             time.Duration
	UpdateAge             time.Duration
	DeferSessionRefresh   bool
	DisableSessionRefresh bool
	// FreshAge controls how long after creation a session is considered fresh.
	// nil = default (24h), 0 = disable freshness checks.
	FreshAge    *time.Duration
	CookieCache CookieCacheConfig
}

// ChangeEmailConfig configures the change-email flow.
type ChangeEmailConfig struct {
	Enabled                        bool
	UpdateEmailWithoutVerification bool
	SendChangeEmailConfirmation    func(ctx context.Context, data types.ChangeEmailData) error
}

// DeleteUserConfig configures account deletion.
type DeleteUserConfig struct {
	Enabled              *bool
	DeleteTokenExpiresIn time.Duration
	SendDeleteAccountURL func(ctx context.Context, user types.User, url, token string) error
	BeforeDelete         func(ctx context.Context, user types.User) error
	AfterDelete          func(ctx context.Context, user types.User) error
}

// UserConfig configures user management.
type UserConfig struct {
	AdditionalFields     map[string]AdditionalFieldDef
	ChangeEmail          ChangeEmailConfig
	DeleteUser           DeleteUserConfig
	DeleteTokenExpiresIn time.Duration
	SendDeleteAccountURL func(ctx context.Context, user types.User, url, token string) error
}

type resolved struct {
	appName               string
	secret                string
	secrets               []string
	baseURL               string
	basePath              string
	store                 store.Store
	trustedOrigins        map[string]bool
	trustedOriginPatterns []string
	cookie                cookie.Config
	hasher                crypto.Hasher
	sessionExpires        time.Duration
	sessionCookieAge      int
	sessionUpdateAge      time.Duration
	dontRememberAge       time.Duration
	deferSessionRefresh   bool
	disableSessionRefresh bool
	freshAge              time.Duration
	freshAgeDisabled      bool
	cookieCache           cookieCacheResolved
	minPassword           int
	maxPassword           int
	disableSignUp         bool
	emailPassword         emailPasswordResolved
	emailVerification     emailVerificationResolved
	user                  userResolved
	account               accountResolved
	socialProviders       map[string]provider.SocialProvider
	plugins               []Plugin
	passwordValidators    []func(string) error
	advanced              AdvancedConfig
	database              DatabaseConfig
	rateLimit             resolvedRateLimit
	secondaryStorage      SecondaryStorage
	hooks                 HooksConfig
	databaseHooks         DatabaseHooksConfig
	onAPIError            OnAPIErrorConfig
	disabledPaths         map[string]bool
	generateID            func() (string, error)
	ipAddressHeaders      []string
	disableIPTracking     bool
	skipTrailingSlashes   bool
	csrfDisabled          bool
}

type emailPasswordResolved struct {
	enabled                       bool
	requireEmailVerification      bool
	autoSignIn                    bool
	sendResetPassword             func(ctx context.Context, data types.ResetPasswordEmailData) error
	resetPasswordTokenExpires     time.Duration
	revokeSessionsOnPasswordReset bool
}

type emailVerificationResolved struct {
	sendVerificationEmail func(ctx context.Context, data types.VerificationEmailData) error
	sendOnSignUp          *bool
	sendOnSignIn          bool
	expiresIn             time.Duration
}

type userResolved struct {
	additionalFields            map[string]AdditionalFieldDef
	changeEmailEnabled          bool
	updateEmailWithoutVerify    bool
	sendChangeEmailConfirmation func(ctx context.Context, data types.ChangeEmailData) error
	deleteUserEnabled           bool
	deleteTokenExpires          time.Duration
	sendDeleteAccount           func(ctx context.Context, user types.User, url, token string) error
	beforeDelete                func(ctx context.Context, user types.User) error
	afterDelete                 func(ctx context.Context, user types.User) error
}

type cookieCacheResolved struct {
	enabled  bool
	maxAge   int
	strategy string
	version  string
}

type accountResolved struct {
	linkingEnabled            bool
	trustedProviders          map[string]bool
	allowDifferentEmails      bool
	allowUnlinkingAll         bool
	updateUserInfoOnLink      bool
	disableImplicitLinking    bool
	requireLocalEmailVerified bool
}

func resolveConfig(opts Config) resolved {
	basePath := opts.BasePath
	if basePath == "" {
		basePath = defaultBasePath
	}

	sessionExpires := opts.Session.ExpiresIn
	if sessionExpires == 0 {
		sessionExpires = defaultSessionExpires
	}

	sessionUpdateAge := opts.Session.UpdateAge
	if sessionUpdateAge == 0 {
		sessionUpdateAge = defaultSessionUpdateAge
	}

	minPassword := opts.EmailAndPassword.MinPasswordLength
	if minPassword == 0 {
		minPassword = defaultMinPassword
	}
	maxPassword := opts.EmailAndPassword.MaxPasswordLength
	if maxPassword == 0 {
		maxPassword = defaultMaxPassword
	}

	appName := opts.AppName
	if appName == "" {
		appName = defaultAppName
	}

	prefix := opts.CookiePrefix
	if prefix == "" && opts.Advanced.CookiePrefix != "" {
		prefix = opts.Advanced.CookiePrefix
	}
	if prefix == "" {
		prefix = "better-auth"
	}

	useSecure := opts.UseSecureCookies || opts.Advanced.UseSecureCookies

	secrets := append([]string{opts.Secret}, opts.OldSecrets...)

	cookieDomain := ""
	if opts.Advanced.CrossSubDomainCookies.Enabled {
		cookieDomain = opts.Advanced.CrossSubDomainCookies.Domain
	}

	sameSite := http.SameSiteLaxMode
	if opts.Advanced.CookieAttributes.SameSite != 0 {
		sameSite = opts.Advanced.CookieAttributes.SameSite
	}

	var cookieNameOverrides map[string]string
	if len(opts.Advanced.Cookies) > 0 {
		cookieNameOverrides = make(map[string]string, len(opts.Advanced.Cookies))
		for key, override := range opts.Advanced.Cookies {
			if override.Name != "" {
				cookieNameOverrides[key] = override.Name
			}
		}
	}

	generateID := opts.Advanced.GenerateID
	if generateID == nil {
		generateID = opts.Database.GenerateID
	}

	disabled := make(map[string]bool, len(opts.DisabledPaths))
	for _, p := range opts.DisabledPaths {
		disabled[normalizePath(p)] = true
	}

	onAPIError := opts.OnAPIError
	if onAPIError.ErrorURL == "" {
		onAPIError.ErrorURL = defaultBasePath + "/error"
	}

	trusted := make(map[string]bool)
	var trustedPatterns []string
	for _, origin := range opts.TrustedOrigins {
		if strings.Contains(origin, "*") {
			trustedPatterns = append(trustedPatterns, origin)
			continue
		}
		trusted[origin] = true
	}
	if opts.BaseURL != "" {
		trusted[opts.BaseURL] = true
	}

	hasher := opts.Hasher
	if hasher == nil {
		hasher = crypto.ScryptHasher{}
	}

	autoSignIn := true
	if opts.EmailAndPassword.AutoSignIn != nil {
		autoSignIn = *opts.EmailAndPassword.AutoSignIn
	}

	emailEnabled := opts.EmailAndPassword.Enabled
	if !emailEnabled && opts.EmailAndPassword.SendResetPassword == nil {
		emailEnabled = true
	}

	verificationExpires := opts.EmailVerification.ExpiresIn
	if verificationExpires == 0 {
		verificationExpires = defaultVerificationExpires
	}

	resetExpires := opts.EmailAndPassword.ResetPasswordTokenExpiresIn
	if resetExpires == 0 {
		resetExpires = defaultResetPasswordExpires
	}

	deleteExpires := opts.User.DeleteUser.DeleteTokenExpiresIn
	if deleteExpires == 0 {
		deleteExpires = opts.User.DeleteTokenExpiresIn
	}
	if deleteExpires == 0 {
		deleteExpires = defaultVerificationExpires
	}

	deleteEnabled := true
	if opts.User.DeleteUser.Enabled != nil {
		deleteEnabled = *opts.User.DeleteUser.Enabled
	}

	sendDelete := opts.User.DeleteUser.SendDeleteAccountURL
	if sendDelete == nil {
		sendDelete = opts.User.SendDeleteAccountURL
	}

	changeEmailEnabled := opts.User.ChangeEmail.Enabled
	if !changeEmailEnabled && (opts.User.ChangeEmail.SendChangeEmailConfirmation != nil || opts.EmailVerification.SendVerificationEmail != nil) {
		changeEmailEnabled = true
	}

	freshAge := defaultFreshAge
	freshAgeDisabled := false
	if opts.Session.FreshAge != nil {
		if *opts.Session.FreshAge == 0 {
			freshAgeDisabled = true
		} else {
			freshAge = *opts.Session.FreshAge
		}
	}

	cookieCacheMaxAge := opts.Session.CookieCache.MaxAge
	if cookieCacheMaxAge == 0 {
		cookieCacheMaxAge = defaultCookieCacheMaxAge
	}
	cookieCacheVersion := opts.Session.CookieCache.Version
	if cookieCacheVersion == "" {
		cookieCacheVersion = "1"
	}
	cookieCacheStrategy := opts.Session.CookieCache.Strategy
	if cookieCacheStrategy == "" {
		cookieCacheStrategy = "compact"
	}
	requireLocalEmailVerified := true
	if opts.Account.AccountLinking.RequireLocalEmailVerified != nil {
		requireLocalEmailVerified = *opts.Account.AccountLinking.RequireLocalEmailVerified
	}

	return resolved{
		appName:               appName,
		secret:                opts.Secret,
		secrets:               secrets,
		baseURL:               opts.BaseURL,
		basePath:              basePath,
		store:                 wrapWithHooks(opts.Store, opts.DatabaseHooks),
		trustedOrigins:        trusted,
		trustedOriginPatterns: trustedPatterns,
		hasher:                hasher,
		cookie: cookie.Config{
			Prefix:        prefix,
			Secure:        useSecure,
			SameSite:      sameSite,
			Path:          "/",
			Domain:        cookieDomain,
			Partitioned:   opts.Advanced.CookieAttributes.Partitioned,
			NameOverrides: cookieNameOverrides,
		},
		sessionExpires:        sessionExpires,
		sessionCookieAge:      int(sessionExpires.Seconds()),
		sessionUpdateAge:      sessionUpdateAge,
		dontRememberAge:       defaultDontRemember,
		deferSessionRefresh:   opts.Session.DeferSessionRefresh,
		disableSessionRefresh: opts.Session.DisableSessionRefresh,
		freshAge:              freshAge,
		freshAgeDisabled:      freshAgeDisabled,
		cookieCache: cookieCacheResolved{
			enabled:  opts.Session.CookieCache.Enabled,
			maxAge:   int(cookieCacheMaxAge.Seconds()),
			strategy: cookieCacheStrategy,
			version:  cookieCacheVersion,
		},
		minPassword:   minPassword,
		maxPassword:   maxPassword,
		disableSignUp: opts.DisableSignUp,
		emailPassword: emailPasswordResolved{
			enabled:                       emailEnabled,
			requireEmailVerification:      opts.EmailAndPassword.RequireEmailVerification,
			autoSignIn:                    autoSignIn,
			sendResetPassword:             opts.EmailAndPassword.SendResetPassword,
			resetPasswordTokenExpires:     resetExpires,
			revokeSessionsOnPasswordReset: opts.EmailAndPassword.RevokeSessionsOnPasswordReset,
		},
		emailVerification: emailVerificationResolved{
			sendVerificationEmail: opts.EmailVerification.SendVerificationEmail,
			sendOnSignUp:          opts.EmailVerification.SendOnSignUp,
			sendOnSignIn:          opts.EmailVerification.SendOnSignIn,
			expiresIn:             verificationExpires,
		},
		user: userResolved{
			additionalFields:            opts.User.AdditionalFields,
			changeEmailEnabled:          changeEmailEnabled,
			updateEmailWithoutVerify:    opts.User.ChangeEmail.UpdateEmailWithoutVerification,
			sendChangeEmailConfirmation: opts.User.ChangeEmail.SendChangeEmailConfirmation,
			deleteUserEnabled:           deleteEnabled,
			deleteTokenExpires:          deleteExpires,
			sendDeleteAccount:           sendDelete,
			beforeDelete:                opts.User.DeleteUser.BeforeDelete,
			afterDelete:                 opts.User.DeleteUser.AfterDelete,
		},
		account: accountResolved{
			linkingEnabled:            accountLinkingEnabled(opts.Account.AccountLinking),
			trustedProviders:          toTrustedProviderSet(opts.Account.AccountLinking.TrustedProviders),
			allowDifferentEmails:      opts.Account.AccountLinking.AllowDifferentEmails,
			allowUnlinkingAll:         opts.Account.AccountLinking.AllowUnlinkingAll,
			updateUserInfoOnLink:      opts.Account.AccountLinking.UpdateUserInfoOnLink,
			disableImplicitLinking:    opts.Account.AccountLinking.DisableImplicitLinking,
			requireLocalEmailVerified: requireLocalEmailVerified,
		},
		socialProviders:     buildSocialProviders(opts),
		plugins:             opts.Plugins,
		passwordValidators:  collectPasswordValidators(opts.Plugins),
		advanced:            opts.Advanced,
		database:            opts.Database,
		rateLimit:           resolveRateLimit(opts.RateLimit),
		secondaryStorage:    opts.SecondaryStorage,
		hooks:               opts.Hooks,
		databaseHooks:       opts.DatabaseHooks,
		onAPIError:          onAPIError,
		disabledPaths:       disabled,
		generateID:          generateID,
		ipAddressHeaders:    opts.Advanced.IPAddressHeaders,
		disableIPTracking:   opts.Advanced.DisableIPTracking,
		skipTrailingSlashes: opts.Advanced.SkipTrailingSlashes,
		csrfDisabled:        opts.Advanced.DisableCSRFCheck,
	}
}

func collectPasswordValidators(plugins []Plugin) []func(string) error {
	var out []func(string) error
	for _, p := range plugins {
		if v, ok := p.(PasswordValidatorPlugin); ok {
			fn := v.ValidatePassword
			if fn != nil {
				out = append(out, fn)
			}
		}
	}
	return out
}

func buildSocialProviders(opts Config) map[string]provider.SocialProvider {
	providers := opts.SocialProviders
	if providers == nil {
		providers = make(map[string]provider.SocialProvider)
	}
	if opts.Google.ClientID != "" && opts.Google.ClientSecret != "" && !opts.Google.Disabled {
		providers[constants.ProviderGoogle] = google.New(google.Config{
			ClientID: opts.Google.ClientID, ClientSecret: opts.Google.ClientSecret, Scopes: opts.Google.Scopes,
			DisableImplicitSignUp: opts.Google.DisableImplicitSignUp, DisableSignUp: opts.Google.DisableSignUp,
		})
	}
	if opts.GitHub.ClientID != "" && opts.GitHub.ClientSecret != "" && !opts.GitHub.Disabled {
		providers[constants.ProviderGitHub] = github.New(github.Config{
			ClientID: opts.GitHub.ClientID, ClientSecret: opts.GitHub.ClientSecret, Scopes: opts.GitHub.Scopes,
			DisableImplicitSignUp: opts.GitHub.DisableImplicitSignUp, DisableSignUp: opts.GitHub.DisableSignUp,
		})
	}
	return providers
}

func accountLinkingEnabled(cfg AccountLinkingConfig) bool {
	if cfg.Enabled != nil {
		return *cfg.Enabled
	}
	return true
}

func toTrustedProviderSet(providers []string) map[string]bool {
	out := make(map[string]bool, len(providers))
	for _, p := range providers {
		out[p] = true
	}
	return out
}
