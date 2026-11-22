package types

import (
	"time"

	"github.com/patrickkabwe/betterauth-go/constants"
)

// Plugin user field keys (aliases for constants).
const (
	FieldRole             = constants.FieldRole
	FieldBanned           = constants.FieldBanned
	FieldBanReason        = constants.FieldBanReason
	FieldBanExpires       = constants.FieldBanExpires
	FieldIsAnonymous      = constants.FieldIsAnonymous
	FieldUsername         = constants.FieldUsername
	FieldDisplayUsername  = constants.FieldDisplayUsername
	FieldPhoneNumber      = constants.FieldPhoneNumber
	FieldPhoneVerified    = constants.FieldPhoneVerified
	FieldTwoFactorEnabled = constants.FieldTwoFactorEnabled
	FieldLastLoginMethod  = constants.FieldLastLoginMethod
)

// Organization is a team/tenant container.
type Organization struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Slug      string     `json:"slug"`
	Logo      *string    `json:"logo,omitempty"`
	Metadata  string     `json:"metadata,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
}

// Member links a user to an organization.
type Member struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	UserID         string    `json:"userId"`
	Role           string    `json:"role"`
	CreatedAt      time.Time `json:"createdAt"`
}

// Invitation is a pending organization invite.
type Invitation struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	Status         string    `json:"status"`
	InviterID      string    `json:"inviterId"`
	TeamID         string    `json:"teamId,omitempty"`
	ExpiresAt      time.Time `json:"expiresAt"`
	CreatedAt      time.Time `json:"createdAt"`
}

// Team is a sub-group within an organization.
type Team struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	OrganizationID string    `json:"organizationId"`
	MemberCount    int       `json:"memberCount"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt,omitempty"`
}

// TeamMember links a user to a team.
type TeamMember struct {
	ID            string    `json:"id"`
	TeamID        string    `json:"teamId"`
	UserID        string    `json:"userId"`
	MembershipKey string    `json:"-"`
	CreatedAt     time.Time `json:"createdAt"`
}

// OrganizationRole stores a dynamic organization role definition.
type OrganizationRole struct {
	ID             string              `json:"id"`
	OrganizationID string              `json:"organizationId"`
	Role           string              `json:"role"`
	Permission     map[string][]string `json:"permission"`
	CreatedAt      time.Time           `json:"createdAt"`
	UpdatedAt      *time.Time          `json:"updatedAt,omitempty"`
}

// TwoFactorRecord stores 2FA secrets for a user.
type TwoFactorRecord struct {
	ID                      string     `json:"id"`
	UserID                  string     `json:"userId"`
	Secret                  string     `json:"secret"`
	BackupCodes             string     `json:"backupCodes"`
	Verified                bool       `json:"verified"`
	FailedVerificationCount int        `json:"failedVerificationCount"`
	LockedUntil             *time.Time `json:"lockedUntil,omitempty"`
	CreatedAt               time.Time  `json:"createdAt"`
	UpdatedAt               time.Time  `json:"updatedAt"`
}

// DeviceCode is an OAuth2 device authorization code.
type DeviceCode struct {
	ID           string     `json:"id"`
	DeviceCode   string     `json:"deviceCode"`
	UserCode     string     `json:"userCode"`
	UserID       string     `json:"userId,omitempty"`
	Status       string     `json:"status"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	LastPolledAt *time.Time `json:"lastPolledAt,omitempty"`
	Interval     int        `json:"interval"`
	ClientID     string     `json:"clientId,omitempty"`
	Scope        string     `json:"scope,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
}

// JWKSRecord stores a JSON Web Key Set entry.
type JWKSRecord struct {
	ID         string     `json:"id"`
	PublicKey  string     `json:"publicKey"`
	PrivateKey string     `json:"privateKey,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	Alg        *string    `json:"alg,omitempty"`
	Crv        *string    `json:"crv,omitempty"`
}

// OAuthClient is a registered OAuth client, mirroring Better Auth's
// oauth-provider `oauthClient` table. List-typed columns (redirectUris, scopes,
// …) are stored as JSON TEXT and metadata as a JSON object.
type OAuthClient struct {
	ID                               string         `json:"id"`
	ClientID                         string         `json:"clientId"`
	ClientSecret                     string         `json:"clientSecret,omitempty"`
	ClientDiscoveryID                string         `json:"clientDiscoveryId,omitempty"`
	Disabled                         bool           `json:"disabled,omitempty"`
	SkipConsent                      *bool          `json:"skipConsent,omitempty"`
	EnableEndSession                 *bool          `json:"enableEndSession,omitempty"`
	SubjectType                      string         `json:"subjectType,omitempty"`
	Scopes                           []string       `json:"scopes,omitempty"`
	ClientCredentialsScopes          []string       `json:"clientCredentialsScopes,omitempty"`
	UserID                           string         `json:"userId,omitempty"`
	CreatedAt                        time.Time      `json:"createdAt"`
	UpdatedAt                        time.Time      `json:"updatedAt"`
	Name                             string         `json:"name,omitempty"`
	URI                              string         `json:"uri,omitempty"`
	Icon                             string         `json:"icon,omitempty"`
	Contacts                         []string       `json:"contacts,omitempty"`
	TOS                              string         `json:"tos,omitempty"`
	Policy                           string         `json:"policy,omitempty"`
	SoftwareID                       string         `json:"softwareId,omitempty"`
	SoftwareVersion                  string         `json:"softwareVersion,omitempty"`
	SoftwareStatement                string         `json:"softwareStatement,omitempty"`
	RedirectURIs                     []string       `json:"redirectUris"`
	PostLogoutRedirectURIs           []string       `json:"postLogoutRedirectUris,omitempty"`
	BackchannelLogoutURI             string         `json:"backchannelLogoutUri,omitempty"`
	BackchannelLogoutSessionRequired *bool          `json:"backchannelLogoutSessionRequired,omitempty"`
	TokenEndpointAuthMethod          string         `json:"tokenEndpointAuthMethod,omitempty"`
	ApplicationType                  string         `json:"applicationType,omitempty"`
	JWKS                             string         `json:"jwks,omitempty"`
	JWKSURI                          string         `json:"jwksUri,omitempty"`
	GrantTypes                       []string       `json:"grantTypes,omitempty"`
	ResponseTypes                    []string       `json:"responseTypes,omitempty"`
	RequirePKCE                      *bool          `json:"requirePKCE,omitempty"`
	DPoPBoundAccessTokens            bool           `json:"dpopBoundAccessTokens,omitempty"`
	ReferenceID                      string         `json:"referenceId,omitempty"`
	Metadata                         map[string]any `json:"metadata,omitempty"`
}

// OAuthAccessToken is an opaque access token issued by the OAuth provider,
// mirroring Better Auth's oauth-provider `oauthAccessToken` table. Access
// tokens are linked to a session and (for refresh-issued tokens) a refresh row.
type OAuthAccessToken struct {
	ID                      string         `json:"id"`
	Token                   string         `json:"token"`
	ClientID                string         `json:"clientId"`
	SessionID               string         `json:"sessionId,omitempty"`
	UserID                  string         `json:"userId,omitempty"`
	ReferenceID             string         `json:"referenceId,omitempty"`
	AuthorizationCodeID     string         `json:"authorizationCodeId,omitempty"`
	Resources               []string       `json:"resources,omitempty"`
	RequestedUserInfoClaims []string       `json:"requestedUserInfoClaims,omitempty"`
	RefreshID               string         `json:"refreshId,omitempty"`
	ExpiresAt               time.Time      `json:"expiresAt"`
	CreatedAt               time.Time      `json:"createdAt"`
	Revoked                 *time.Time     `json:"revoked,omitempty"`
	Confirmation            map[string]any `json:"confirmation,omitempty"`
	Scopes                  []string       `json:"scopes"`
}

// OAuthRefreshToken is an opaque refresh token issued with the offline_access
// scope, mirroring Better Auth's oauth-provider `oauthRefreshToken` table. It
// supports single-use rotation with a short replay window and family
// invalidation on reuse (RFC 9700 §4.14).
type OAuthRefreshToken struct {
	ID                      string         `json:"id"`
	Token                   string         `json:"token"`
	ClientID                string         `json:"clientId"`
	SessionID               string         `json:"sessionId,omitempty"`
	UserID                  string         `json:"userId"`
	ReferenceID             string         `json:"referenceId,omitempty"`
	AuthorizationCodeID     string         `json:"authorizationCodeId,omitempty"`
	Resources               []string       `json:"resources,omitempty"`
	RequestedUserInfoClaims []string       `json:"requestedUserInfoClaims,omitempty"`
	ExpiresAt               time.Time      `json:"expiresAt"`
	CreatedAt               time.Time      `json:"createdAt"`
	Revoked                 *time.Time     `json:"revoked,omitempty"`
	RotatedAt               *time.Time     `json:"rotatedAt,omitempty"`
	RotationReplayResponse  string         `json:"rotationReplayResponse,omitempty"`
	RotationReplayExpiresAt *time.Time     `json:"rotationReplayExpiresAt,omitempty"`
	AuthTime                *time.Time     `json:"authTime,omitempty"`
	Confirmation            map[string]any `json:"confirmation,omitempty"`
	Scopes                  []string       `json:"scopes"`
}

// OAuthConsent records a user's consent for a client to access a set of
// scopes, mirroring Better Auth's oauth-provider `oauthConsent` table.
type OAuthConsent struct {
	ID                      string    `json:"id"`
	ClientID                string    `json:"clientId"`
	UserID                  string    `json:"userId,omitempty"`
	ReferenceID             string    `json:"referenceId,omitempty"`
	Resources               []string  `json:"resources,omitempty"`
	RequestedUserInfoClaims []string  `json:"requestedUserInfoClaims,omitempty"`
	Scopes                  []string  `json:"scopes"`
	CreatedAt               time.Time `json:"createdAt"`
	UpdatedAt               time.Time `json:"updatedAt"`
}

// WalletAddress links a blockchain wallet to a user.
type WalletAddress struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	Address   string    `json:"address"`
	ChainID   int       `json:"chainId"`
	IsPrimary bool      `json:"isPrimary"`
	CreatedAt time.Time `json:"createdAt"`
}

// APIKey stores a hashed API key credential.
type APIKey struct {
	ID                  string     `json:"id"`
	ConfigID            string     `json:"configId"`
	Name                string     `json:"name,omitempty"`
	Start               string     `json:"start,omitempty"`
	ReferenceID         string     `json:"referenceId"`
	Prefix              string     `json:"prefix,omitempty"`
	Key                 string     `json:"-"`
	RefillInterval      int64      `json:"refillInterval,omitempty"`
	RefillAmount        int        `json:"refillAmount,omitempty"`
	LastRefillAt        *time.Time `json:"lastRefillAt,omitempty"`
	Enabled             bool       `json:"enabled"`
	RateLimitEnabled    bool       `json:"rateLimitEnabled"`
	RateLimitTimeWindow int64      `json:"rateLimitTimeWindow"`
	RateLimitMax        int        `json:"rateLimitMax"`
	RequestCount        int        `json:"requestCount"`
	Remaining           *int       `json:"remaining,omitempty"`
	LastRequest         *time.Time `json:"lastRequest,omitempty"`
	ExpiresAt           *time.Time `json:"expiresAt,omitempty"`
	CreatedAt           time.Time  `json:"createdAt"`
	UpdatedAt           time.Time  `json:"updatedAt"`
	Permissions         string     `json:"permissions,omitempty"`
	Metadata            string     `json:"metadata,omitempty"`
}

// SSOProvider stores enterprise SSO provider metadata.
type SSOProvider struct {
	ID             string `json:"id"`
	ProviderID     string `json:"providerId"`
	Issuer         string `json:"issuer"`
	Domain         string `json:"domain"`
	OrganizationID string `json:"organizationId,omitempty"`
	UserID         string `json:"userId"`
	OIDCConfig     string `json:"oidcConfig,omitempty"`
	SAMLConfig     string `json:"samlConfig,omitempty"`
	DomainVerified bool   `json:"domainVerified"`
}

// Passkey stores a WebAuthn credential for a user.
type Passkey struct {
	ID           string    `json:"id"`
	Name         string    `json:"name,omitempty"`
	PublicKey    string    `json:"publicKey"`
	UserID       string    `json:"userId"`
	CredentialID string    `json:"credentialID"`
	Counter      uint32    `json:"counter"`
	DeviceType   string    `json:"deviceType"`
	BackedUp     bool      `json:"backedUp"`
	Transports   string    `json:"transports,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
	AAGUID       string    `json:"aaguid,omitempty"`
}
