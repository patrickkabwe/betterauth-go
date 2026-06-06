package store

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/types"
)

// ExtStore provides persistence for plugin-specific entities.
type ExtStore interface {
	// Organization
	CreateOrganization(ctx context.Context, o *types.Organization) error
	FindOrganizationByID(ctx context.Context, id string) (*types.Organization, error)
	FindOrganizationBySlug(ctx context.Context, slug string) (*types.Organization, error)
	UpdateOrganization(ctx context.Context, id string, name, slug string, logo *string) (*types.Organization, error)
	DeleteOrganization(ctx context.Context, id string) error
	ListOrganizations(ctx context.Context) ([]types.Organization, error)

	// Member
	CreateMember(ctx context.Context, m *types.Member) error
	DeleteMember(ctx context.Context, id string) error
	FindMemberByOrgAndUser(ctx context.Context, orgID, userID string) (*types.Member, error)
	ListMembersByOrg(ctx context.Context, orgID string) ([]types.Member, error)
	ListMembersByUser(ctx context.Context, userID string) ([]types.Member, error)

	// Invitation
	CreateInvitation(ctx context.Context, inv *types.Invitation) error
	FindInvitationByID(ctx context.Context, id string) (*types.Invitation, error)
	UpdateInvitationStatus(ctx context.Context, id, status string) error
	ListInvitationsByOrg(ctx context.Context, orgID string) ([]types.Invitation, error)
	ListInvitationsByEmail(ctx context.Context, email string) ([]types.Invitation, error)

	// Team
	CreateTeam(ctx context.Context, t *types.Team) error
	DeleteTeam(ctx context.Context, id string) error
	FindTeamByID(ctx context.Context, id string) (*types.Team, error)
	ListTeamsByOrg(ctx context.Context, orgID string) ([]types.Team, error)

	// TeamMember
	CreateTeamMember(ctx context.Context, tm *types.TeamMember) error
	DeleteTeamMember(ctx context.Context, id string) error
	ListTeamMembers(ctx context.Context, teamID string) ([]types.TeamMember, error)

	// TwoFactor
	CreateTwoFactor(ctx context.Context, rec *types.TwoFactorRecord) error
	FindTwoFactorByUserID(ctx context.Context, userID string) (*types.TwoFactorRecord, error)
	UpdateTwoFactor(ctx context.Context, userID string, secret, backupCodes string, verified bool) error
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
}
