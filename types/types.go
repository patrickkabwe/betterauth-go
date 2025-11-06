package types

import "time"

// User matches the Better Auth user model returned to clients.
type User struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Email         string         `json:"email"`
	EmailVerified bool           `json:"emailVerified"`
	Image         *string        `json:"image"`
	CreatedAt     time.Time      `json:"createdAt"`
	UpdatedAt     time.Time      `json:"updatedAt"`
	Additional    map[string]any `json:"-"`
}

// Session matches the Better Auth session model returned to clients.
type Session struct {
	ID        string         `json:"id"`
	Token     string         `json:"token"`
	UserID    string         `json:"userId"`
	ExpiresAt time.Time      `json:"expiresAt"`
	IPAddress string         `json:"ipAddress,omitempty"`
	UserAgent string         `json:"userAgent,omitempty"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	Additional map[string]any `json:"-"`
}

// Account stores provider credentials (password hash for email/password).
type Account struct {
	ID                    string     `json:"id"`
	AccountID             string     `json:"accountId"`
	ProviderID            string     `json:"providerId"`
	UserID                string     `json:"userId"`
	Password              string     `json:"password,omitempty"`
	AccessToken           string     `json:"accessToken,omitempty"`
	RefreshToken          string     `json:"refreshToken,omitempty"`
	AccessTokenExpiresAt  *time.Time `json:"accessTokenExpiresAt,omitempty"`
	RefreshTokenExpiresAt *time.Time `json:"refreshTokenExpiresAt,omitempty"`
	IDToken               string     `json:"idToken,omitempty"`
	Scope                 string     `json:"scope,omitempty"`
	CreatedAt             time.Time  `json:"createdAt"`
	UpdatedAt             time.Time  `json:"updatedAt"`
}

// AccountResponse is the public account shape returned to clients.
type AccountResponse struct {
	ID         string    `json:"id"`
	AccountID  string    `json:"accountId"`
	ProviderID string    `json:"providerId"`
	UserID     string    `json:"userId"`
	Scopes     []string  `json:"scopes"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// Verification stores one-time tokens (password reset, etc.).
type Verification struct {
	ID         string    `json:"id"`
	Identifier string    `json:"identifier"`
	Value      string    `json:"value"`
	ExpiresAt  time.Time `json:"expiresAt"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// SessionResponse is returned by get-session.
type SessionResponse struct {
	Session      Session `json:"session"`
	User         User    `json:"user"`
	NeedsRefresh bool    `json:"needsRefresh,omitempty"`
}

// SignInResponse is returned by sign-in/email.
type SignInResponse struct {
	Redirect bool   `json:"redirect"`
	Token    string `json:"token"`
	URL      string `json:"url,omitempty"`
	User     User   `json:"user"`
}

// SignUpResponse is returned by sign-up/email.
type SignUpResponse struct {
	Token *string `json:"token"`
	User  User    `json:"user"`
}

// SignOutResponse is returned by sign-out.
type SignOutResponse struct {
	Success bool `json:"success"`
}

// StatusResponse is returned by revoke and verification endpoints.
type StatusResponse struct {
	Status bool `json:"status"`
}

// MessageStatusResponse is returned by password reset request.
type MessageStatusResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
}

// OKResponse is returned by /ok.
type OKResponse struct {
	OK bool `json:"ok"`
}

// VerifyEmailResponse is returned by verify-email.
type VerifyEmailResponse struct {
	Status bool `json:"status"`
	User   User `json:"user"`
}

// UpdateUserResponse is returned by update-user.
type UpdateUserResponse struct {
	Status bool `json:"status"`
}

// ChangePasswordResponse is returned by change-password.
type ChangePasswordResponse struct {
	Token *string `json:"token"`
	User  User    `json:"user"`
}

// DeleteUserResponse is returned by delete-user.
type DeleteUserResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// ChangeEmailData is passed to sendChangeEmailConfirmation callbacks.
type ChangeEmailData struct {
	User     User
	NewEmail string
	URL      string
	Token    string
}

// VerifyPasswordResponse is returned by verify-password.
type VerifyPasswordResponse struct {
	Status bool `json:"status"`
}

// SocialSignInResponse is returned by sign-in/social.
type SocialSignInResponse struct {
	Redirect bool   `json:"redirect"`
	URL      string `json:"url,omitempty"`
	Token    string `json:"token,omitempty"`
	User     User   `json:"user,omitempty"`
}

// LinkSocialResponse is returned by link-social.
type LinkSocialResponse struct {
	URL      string `json:"url"`
	Redirect bool   `json:"redirect"`
	Status   bool   `json:"status,omitempty"`
}

// AccessTokenResponse is returned by get-access-token.
type AccessTokenResponse struct {
	AccessToken          string     `json:"accessToken"`
	AccessTokenExpiresAt *time.Time `json:"accessTokenExpiresAt,omitempty"`
	IDToken              string     `json:"idToken,omitempty"`
}

// RefreshTokenResponse is returned by refresh-token.
type RefreshTokenResponse struct {
	AccessToken           string     `json:"accessToken"`
	RefreshToken          string     `json:"refreshToken,omitempty"`
	AccessTokenExpiresAt  *time.Time `json:"accessTokenExpiresAt,omitempty"`
	RefreshTokenExpiresAt *time.Time `json:"refreshTokenExpiresAt,omitempty"`
	Scope                 string     `json:"scope,omitempty"`
	IDToken               string     `json:"idToken,omitempty"`
	ProviderID            string     `json:"providerId"`
	AccountID             string     `json:"accountId"`
}

// AccountInfoResponse is returned by account-info.
type AccountInfoResponse struct {
	User OAuthUserInfo      `json:"user"`
	Data map[string]any     `json:"data"`
}

// OAuthUserInfo is the user portion of account-info.
type OAuthUserInfo struct {
	ID            string  `json:"id"`
	Name          string  `json:"name,omitempty"`
	Email         string  `json:"email,omitempty"`
	Image         *string `json:"image,omitempty"`
	EmailVerified bool    `json:"emailVerified"`
}

// Email verification callback data.
type VerificationEmailData struct {
	User  User
	URL   string
	Token string
}

// Password reset email callback data.
type ResetPasswordEmailData struct {
	User  User
	URL   string
	Token string
}
