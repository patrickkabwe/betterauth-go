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

	// JWKS
	CreateJWKS(ctx context.Context, rec *types.JWKSRecord) error
	ListJWKS(ctx context.Context) ([]types.JWKSRecord, error)

	// OAuthApplication
	CreateOAuthApp(ctx context.Context, app *types.OAuthApplication) error
	FindOAuthAppByClientID(ctx context.Context, clientID string) (*types.OAuthApplication, error)

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
	UpdatedAt      *time.Time
}
