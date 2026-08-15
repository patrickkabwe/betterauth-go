package provider

import (
	"context"
	"time"
)

// OAuthUser is profile data returned by a social provider.
type OAuthUser struct {
	ID            string
	Name          string
	Email         string
	Image         *string
	EmailVerified bool
}

// UserInfo is the account-info payload from a provider.
type UserInfo struct {
	User OAuthUser
	Data map[string]any
}

// OAuthTokens holds OAuth token data for a linked account.
type OAuthTokens struct {
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	IDToken               string
	Scopes                []string
	User                  map[string]any
}

// AuthorizationURLOpts configures an OAuth authorization redirect.
type AuthorizationURLOpts struct {
	State        string
	CodeVerifier string
	RedirectURI  string
	Scopes       []string
	LoginHint    string
}

// SocialProvider implements OAuth/social account operations for a single provider.
type SocialProvider interface {
	ID() string
	CreateAuthorizationURL(ctx context.Context, opts AuthorizationURLOpts) (string, error)
	GetUserInfo(ctx context.Context, tokens OAuthTokens) (*UserInfo, error)
}

// SignUpPolicyProvider controls whether a social provider may create users.
type SignUpPolicyProvider interface {
	DisableImplicitSignUp() bool
	DisableSignUp() bool
}

// IDTokenLinker links accounts using a provider ID token.
type IDTokenLinker interface {
	VerifyIDToken(ctx context.Context, token, nonce string) (bool, error)
}

// TokenRefresher refreshes OAuth access tokens.
type TokenRefresher interface {
	RefreshAccessToken(ctx context.Context, refreshToken string) (*OAuthTokens, error)
}
