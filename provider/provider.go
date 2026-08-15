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

// OAuthUserMapping overrides selected OAuth user fields derived from a provider profile.
type OAuthUserMapping struct {
	ID            *string
	Name          *string
	Email         *string
	Image         *string
	EmailVerified *bool
}

// ApplyOAuthUserMapping applies optional user field overrides.
func ApplyOAuthUserMapping(user OAuthUser, mapping OAuthUserMapping) OAuthUser {
	if mapping.ID != nil {
		user.ID = *mapping.ID
	}
	if mapping.Name != nil {
		user.Name = *mapping.Name
	}
	if mapping.Email != nil {
		user.Email = *mapping.Email
	}
	if mapping.Image != nil {
		image := *mapping.Image
		user.Image = &image
	}
	if mapping.EmailVerified != nil {
		user.EmailVerified = *mapping.EmailVerified
	}
	return user
}

// UserInfo is the account-info payload from a provider.
type UserInfo struct {
	User OAuthUser
	Data map[string]any
}

// OAuthTokens holds OAuth token data for a linked account.
type OAuthTokens struct {
	TokenType             string
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	IDToken               string
	Scopes                []string
	User                  map[string]any
	Raw                   map[string]any
}

// AuthorizationURLOpts configures an OAuth authorization redirect.
type AuthorizationURLOpts struct {
	State        string
	CodeVerifier string
	RedirectURI  string
	Scopes       []string
	Display      string
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

// UserInfoOverrideProvider controls whether social sign-in refreshes user profile fields.
type UserInfoOverrideProvider interface {
	OverrideUserInfoOnSignIn() bool
}

// IDTokenLinker links accounts using a provider ID token.
type IDTokenLinker interface {
	VerifyIDToken(ctx context.Context, token, nonce string) (bool, error)
}

// TokenRefresher refreshes OAuth access tokens.
type TokenRefresher interface {
	RefreshAccessToken(ctx context.Context, refreshToken string) (*OAuthTokens, error)
}
