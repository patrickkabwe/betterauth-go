package store

import (
	"context"
	"time"

	"github.com/patrickkabwe/betterauth-go/types"
)

// ExtStore provides persistence for plugin-specific entities.
type ExtStore interface {
	// Organization
	CreateOrganization(ctx context.Context, o *types.Organization) error
	FindOrganizationByID(ctx context.Context, id string) (*types.Organization, error)
	FindOrganizationBySlug(ctx context.Context, slug string) (*types.Organization, error)
	UpdateOrganization(ctx context.Context, id string, name, slug string, logo *string, metadata *string) (*types.Organization, error)
	DeleteOrganization(ctx context.Context, id string) error
	ListOrganizations(ctx context.Context) ([]types.Organization, error)

	// Member
	CreateMember(ctx context.Context, m *types.Member) error
	DeleteMember(ctx context.Context, id string) error
	FindMemberByID(ctx context.Context, id string) (*types.Member, error)
	FindMemberByOrgAndUser(ctx context.Context, orgID, userID string) (*types.Member, error)
	UpdateMemberRole(ctx context.Context, id string, role string) (*types.Member, error)
	ListMembersByOrg(ctx context.Context, orgID string) ([]types.Member, error)
	ListMembersByUser(ctx context.Context, userID string) ([]types.Member, error)

	// Invitation
	CreateInvitation(ctx context.Context, inv *types.Invitation) error
	FindInvitationByID(ctx context.Context, id string) (*types.Invitation, error)
	UpdateInvitationStatus(ctx context.Context, id, status string) error
	UpdateInvitationExpiresAt(ctx context.Context, id string, expiresAt time.Time) error
	ListInvitationsByOrg(ctx context.Context, orgID string) ([]types.Invitation, error)
	ListInvitationsByEmail(ctx context.Context, email string) ([]types.Invitation, error)

	// Team
	CreateTeam(ctx context.Context, t *types.Team) error
	DeleteTeam(ctx context.Context, id string) error
	FindTeamByID(ctx context.Context, id string) (*types.Team, error)
	UpdateTeam(ctx context.Context, id string, name string) (*types.Team, error)
	ListTeamsByOrg(ctx context.Context, orgID string) ([]types.Team, error)
	ListTeamsByUser(ctx context.Context, userID string) ([]types.Team, error)

	// TeamMember
	CreateTeamMember(ctx context.Context, tm *types.TeamMember) error
	DeleteTeamMember(ctx context.Context, id string) error
	DeleteTeamMemberByTeamAndUser(ctx context.Context, teamID string, userID string) error
	FindTeamMember(ctx context.Context, teamID string, userID string) (*types.TeamMember, error)
	ListTeamMembers(ctx context.Context, teamID string) ([]types.TeamMember, error)

	// OrganizationRole
	CreateOrganizationRole(ctx context.Context, role *types.OrganizationRole) error
	FindOrganizationRoleByID(ctx context.Context, id string) (*types.OrganizationRole, error)
	FindOrganizationRoleByOrgAndRole(ctx context.Context, organizationID string, role string) (*types.OrganizationRole, error)
	UpdateOrganizationRole(ctx context.Context, id string, role string, permission map[string][]string) (*types.OrganizationRole, error)
	DeleteOrganizationRole(ctx context.Context, id string) error
	ListOrganizationRolesByOrg(ctx context.Context, organizationID string) ([]types.OrganizationRole, error)

	// TwoFactor
	CreateTwoFactor(ctx context.Context, rec *types.TwoFactorRecord) error
	FindTwoFactorByUserID(ctx context.Context, userID string) (*types.TwoFactorRecord, error)
	UpdateTwoFactor(ctx context.Context, userID string, secret, backupCodes string, verified bool) error
	UpdateTwoFactorLockout(ctx context.Context, userID string, failedVerificationCount int, lockedUntil *time.Time) error
	DeleteTwoFactor(ctx context.Context, userID string) error

	// DeviceCode
	CreateDeviceCode(ctx context.Context, dc *types.DeviceCode) error
	FindDeviceCodeByDeviceCode(ctx context.Context, code string) (*types.DeviceCode, error)
	FindDeviceCodeByUserCode(ctx context.Context, code string) (*types.DeviceCode, error)
	UpdateDeviceCode(ctx context.Context, id string, userID, status string) error
	SetDeviceCodePolled(ctx context.Context, id string, t time.Time) error
	DeleteDeviceCode(ctx context.Context, id string) error

	// JWKS
	CreateJWKS(ctx context.Context, rec *types.JWKSRecord) error
	ListJWKS(ctx context.Context) ([]types.JWKSRecord, error)

	// OAuthClient (oauth-provider)
	CreateOAuthClient(ctx context.Context, client *types.OAuthClient) error
	FindOAuthClientByClientID(ctx context.Context, clientID string) (*types.OAuthClient, error)

	// OAuth tokens (oauth-provider)
	CreateOAuthAccessToken(ctx context.Context, token *types.OAuthAccessToken) error
	FindOAuthAccessToken(ctx context.Context, token string) (*types.OAuthAccessToken, error)
	CreateOAuthRefreshToken(ctx context.Context, token *types.OAuthRefreshToken) error
	FindOAuthRefreshToken(ctx context.Context, token string) (*types.OAuthRefreshToken, error)
	// RevokeOAuthAccessToken marks an access token revoked (RFC 7009).
	RevokeOAuthAccessToken(ctx context.Context, token string) error
	// RotateOAuthRefreshToken marks a refresh row rotated: sets revoked and
	// rotatedAt and stores a short-lived replay response for retry races.
	RotateOAuthRefreshToken(ctx context.Context, id string, replayResponse string, replayExpiresAt time.Time) error
	// InvalidateOAuthRefreshFamily revokes every refresh token for a
	// (clientID, userID) pair and the access tokens linked to them, on refresh
	// token reuse detection (RFC 9700 §4.14).
	InvalidateOAuthRefreshFamily(ctx context.Context, clientID, userID string) error

	// OAuth consent (oauth-provider)
	CreateOAuthConsent(ctx context.Context, consent *types.OAuthConsent) error
	FindOAuthConsent(ctx context.Context, clientID, userID string) (*types.OAuthConsent, error)
	FindOAuthConsentByID(ctx context.Context, id string) (*types.OAuthConsent, error)
	UpdateOAuthConsent(ctx context.Context, id string, scopes, resources, claims []string) error
	ListOAuthConsentsByUser(ctx context.Context, userID string) ([]types.OAuthConsent, error)
	DeleteOAuthConsent(ctx context.Context, id string) error

	// OAuth client assertions (oauth-provider, RFC 7523 private_key_jwt replay)
	// CreateOAuthClientAssertion records a consumed client-assertion jti. The id
	// is the primary key, so a replay returns errors.ErrAlreadyExists.
	CreateOAuthClientAssertion(ctx context.Context, assertion *types.OAuthClientAssertion) error
	FindOAuthClientAssertion(ctx context.Context, id string) (*types.OAuthClientAssertion, error)

	// OAuth resources (oauth-provider, RFC 8707)
	CreateOAuthResource(ctx context.Context, resource *types.OAuthResource) error
	FindOAuthResource(ctx context.Context, identifier string) (*types.OAuthResource, error)
	ListOAuthResources(ctx context.Context) ([]types.OAuthResource, error)
	UpdateOAuthResource(ctx context.Context, resource *types.OAuthResource) error
	DeleteOAuthResource(ctx context.Context, identifier string) error
	// Client-resource linkage
	LinkOAuthClientResource(ctx context.Context, link *types.OAuthClientResource) error
	UnlinkOAuthClientResource(ctx context.Context, clientID, resourceID string) error
	IsOAuthClientLinkedToResource(ctx context.Context, clientID, resourceID string) (bool, error)
	ListOAuthClientResources(ctx context.Context, clientID string) ([]types.OAuthClientResource, error)

	// Wallet
	CreateWallet(ctx context.Context, w *types.WalletAddress) error
	FindWalletByAddress(ctx context.Context, address string, chainID int) (*types.WalletAddress, error)
	ListWalletsByUser(ctx context.Context, userID string) ([]types.WalletAddress, error)

	// APIKey
	CreateAPIKey(ctx context.Context, key *types.APIKey) error
	FindAPIKeyByID(ctx context.Context, id string) (*types.APIKey, error)
	FindAPIKeyByKey(ctx context.Context, hashedKey string) (*types.APIKey, error)
	ListAPIKeysByReference(ctx context.Context, referenceID string) ([]types.APIKey, error)
	UpdateAPIKey(ctx context.Context, id string, update APIKeyUpdate) (*types.APIKey, error)
	DeleteAPIKey(ctx context.Context, id string) error
	DeleteExpiredAPIKeys(ctx context.Context, now time.Time) error

	// SSOProvider
	CreateSSOProvider(ctx context.Context, provider *types.SSOProvider) error
	FindSSOProviderByProviderID(ctx context.Context, providerID string) (*types.SSOProvider, error)
	FindSSOProviderByDomain(ctx context.Context, domain string) (*types.SSOProvider, error)
	ListSSOProvidersByUserID(ctx context.Context, userID string) ([]types.SSOProvider, error)
	UpdateSSOProvider(ctx context.Context, providerID string, update SSOProviderUpdate) (*types.SSOProvider, error)
	DeleteSSOProvider(ctx context.Context, providerID string) error

	// Passkey
	CreatePasskey(ctx context.Context, passkey *types.Passkey) error
	FindPasskeyByCredentialID(ctx context.Context, credentialID string) (*types.Passkey, error)
	ListPasskeysByUserID(ctx context.Context, userID string) ([]types.Passkey, error)
	UpdatePasskey(ctx context.Context, id string, update PasskeyUpdate) (*types.Passkey, error)
	DeletePasskey(ctx context.Context, id string, userID string) error
}

// APIKeyUpdate describes mutable API key fields.
type APIKeyUpdate struct {
	Name         *string
	Enabled      *bool
	ExpiresAt    *time.Time
	Permissions  *string
	Metadata     *string
	RequestCount *int
	Remaining    *int
	LastRequest  *time.Time
	UpdatedAt    *time.Time
}

// SSOProviderUpdate describes mutable SSO provider fields.
type SSOProviderUpdate struct {
	Issuer         *string
	Domain         *string
	OrganizationID *string
	OIDCConfig     *string
	SAMLConfig     *string
	DomainVerified *bool
}

// PasskeyUpdate describes mutable passkey fields.
type PasskeyUpdate struct {
	Name       *string
	Counter    *uint32
	BackedUp   *bool
	Transports *string
}
