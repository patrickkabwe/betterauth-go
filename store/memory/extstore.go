package memory

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/patrickkabwe/betterauth-go/types"
)

func (s *Store) CreateOrganization(_ context.Context, o *types.Organization) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.orgs == nil {
		s.orgs = make(map[string]*types.Organization)
		s.orgsBySlug = make(map[string]string)
	}
	if _, ok := s.orgsBySlug[o.Slug]; ok {
		return ErrAlreadyExists
	}
	cp := *o
	s.orgs[o.ID] = &cp
	s.orgsBySlug[o.Slug] = o.ID
	return nil
}

func (s *Store) FindOrganizationByID(_ context.Context, id string) (*types.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.orgs[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *o
	return &cp, nil
}

func (s *Store) FindOrganizationBySlug(_ context.Context, slug string) (*types.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.orgsBySlug[slug]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *s.orgs[id]
	return &cp, nil
}

func (s *Store) UpdateOrganization(_ context.Context, id string, name, slug string, logo *string, metadata *string) (*types.Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orgs[id]
	if !ok {
		return nil, ErrNotFound
	}
	if slug != o.Slug {
		if _, exists := s.orgsBySlug[slug]; exists {
			return nil, ErrAlreadyExists
		}
		delete(s.orgsBySlug, o.Slug)
		s.orgsBySlug[slug] = id
		o.Slug = slug
	}
	if name != "" {
		o.Name = name
	}
	if logo != nil {
		o.Logo = logo
	}
	if metadata != nil {
		o.Metadata = *metadata
	}
	now := time.Now().UTC()
	o.UpdatedAt = &now
	cp := *o
	return &cp, nil
}

func (s *Store) DeleteOrganization(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orgs[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.orgsBySlug, o.Slug)
	delete(s.orgs, id)
	for mid, m := range s.members {
		if m.OrganizationID == id {
			delete(s.members, mid)
		}
	}
	for iid, inv := range s.invitations {
		if inv.OrganizationID == id {
			delete(s.invitations, iid)
		}
	}
	for tid, t := range s.teams {
		if t.OrganizationID == id {
			delete(s.teams, tid)
		}
	}
	for roleID, role := range s.organizationRoles {
		if role.OrganizationID == id {
			delete(s.organizationRoles, roleID)
		}
	}
	return nil
}

func (s *Store) ListOrganizations(_ context.Context) ([]types.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.Organization, 0, len(s.orgs))
	for _, o := range s.orgs {
		out = append(out, *o)
	}
	return out, nil
}

func (s *Store) CreateMember(_ context.Context, m *types.Member) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *m
	s.members[m.ID] = &cp
	return nil
}

func (s *Store) DeleteMember(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.members, id)
	return nil
}

func (s *Store) FindMemberByID(_ context.Context, id string) (*types.Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.members[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *m
	return &cp, nil
}

func (s *Store) FindMemberByOrgAndUser(_ context.Context, orgID, userID string) (*types.Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.members {
		if m.OrganizationID == orgID && m.UserID == userID {
			cp := *m
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) UpdateMemberRole(_ context.Context, id string, role string) (*types.Member, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.members[id]
	if !ok {
		return nil, ErrNotFound
	}
	m.Role = role
	cp := *m
	return &cp, nil
}

func (s *Store) ListMembersByOrg(_ context.Context, orgID string) ([]types.Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []types.Member
	for _, m := range s.members {
		if m.OrganizationID == orgID {
			out = append(out, *m)
		}
	}
	return out, nil
}

func (s *Store) ListMembersByUser(_ context.Context, userID string) ([]types.Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []types.Member
	for _, m := range s.members {
		if m.UserID == userID {
			out = append(out, *m)
		}
	}
	return out, nil
}

func (s *Store) CreateInvitation(_ context.Context, inv *types.Invitation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *inv
	s.invitations[inv.ID] = &cp
	return nil
}

func (s *Store) FindInvitationByID(_ context.Context, id string) (*types.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inv, ok := s.invitations[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *inv
	return &cp, nil
}

func (s *Store) UpdateInvitationStatus(_ context.Context, id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invitations[id]
	if !ok {
		return ErrNotFound
	}
	inv.Status = status
	return nil
}

func (s *Store) UpdateInvitationExpiresAt(_ context.Context, id string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invitations[id]
	if !ok {
		return ErrNotFound
	}
	inv.ExpiresAt = expiresAt
	return nil
}

func (s *Store) ListInvitationsByOrg(_ context.Context, orgID string) ([]types.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []types.Invitation
	for _, inv := range s.invitations {
		if inv.OrganizationID == orgID {
			out = append(out, *inv)
		}
	}
	return out, nil
}

func (s *Store) ListInvitationsByEmail(_ context.Context, email string) ([]types.Invitation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	email = strings.ToLower(email)
	var out []types.Invitation
	for _, inv := range s.invitations {
		if strings.ToLower(inv.Email) == email {
			out = append(out, *inv)
		}
	}
	return out, nil
}

func (s *Store) CreateTeam(_ context.Context, t *types.Team) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *t
	s.teams[t.ID] = &cp
	return nil
}

func (s *Store) DeleteTeam(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.teams, id)
	for tid, tm := range s.teamMembers {
		if tm.TeamID == id {
			delete(s.teamMembers, tid)
		}
	}
	return nil
}

func (s *Store) FindTeamByID(_ context.Context, id string) (*types.Team, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.teams[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (s *Store) UpdateTeam(_ context.Context, id string, name string) (*types.Team, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.teams[id]
	if !ok {
		return nil, ErrNotFound
	}
	if name != "" {
		t.Name = name
	}
	t.UpdatedAt = time.Now()
	cp := *t
	return &cp, nil
}

func (s *Store) ListTeamsByOrg(_ context.Context, orgID string) ([]types.Team, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []types.Team
	for _, t := range s.teams {
		if t.OrganizationID == orgID {
			out = append(out, *t)
		}
	}
	return out, nil
}

func (s *Store) ListTeamsByUser(_ context.Context, userID string) ([]types.Team, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	teamIDs := make(map[string]struct{})
	for _, tm := range s.teamMembers {
		if tm.UserID == userID {
			teamIDs[tm.TeamID] = struct{}{}
		}
	}
	out := make([]types.Team, 0, len(teamIDs))
	for teamID := range teamIDs {
		if team, ok := s.teams[teamID]; ok {
			out = append(out, *team)
		}
	}
	return out, nil
}

func (s *Store) CreateTeamMember(_ context.Context, tm *types.TeamMember) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *tm
	s.teamMembers[tm.ID] = &cp
	return nil
}

func (s *Store) DeleteTeamMember(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.teamMembers, id)
	return nil
}

func (s *Store) DeleteTeamMemberByTeamAndUser(_ context.Context, teamID string, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, tm := range s.teamMembers {
		if tm.TeamID == teamID && tm.UserID == userID {
			delete(s.teamMembers, id)
			return nil
		}
	}
	return ErrNotFound
}

func (s *Store) FindTeamMember(_ context.Context, teamID string, userID string) (*types.TeamMember, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, tm := range s.teamMembers {
		if tm.TeamID == teamID && tm.UserID == userID {
			cp := *tm
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) ListTeamMembers(_ context.Context, teamID string) ([]types.TeamMember, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []types.TeamMember
	for _, tm := range s.teamMembers {
		if tm.TeamID == teamID {
			out = append(out, *tm)
		}
	}
	return out, nil
}

func cloneOrganizationRolePermission(permission map[string][]string) map[string][]string {
	out := make(map[string][]string, len(permission))
	for resource, actions := range permission {
		out[resource] = append([]string(nil), actions...)
	}
	return out
}

func cloneOrganizationRole(role *types.OrganizationRole) *types.OrganizationRole {
	cp := *role
	cp.Permission = cloneOrganizationRolePermission(role.Permission)
	return &cp
}

func (s *Store) CreateOrganizationRole(_ context.Context, role *types.OrganizationRole) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.organizationRoles {
		if existing.OrganizationID == role.OrganizationID && existing.Role == role.Role {
			return ErrAlreadyExists
		}
	}
	s.organizationRoles[role.ID] = cloneOrganizationRole(role)
	return nil
}

func (s *Store) FindOrganizationRoleByID(_ context.Context, roleID string) (*types.OrganizationRole, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	role, ok := s.organizationRoles[roleID]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneOrganizationRole(role), nil
}

func (s *Store) FindOrganizationRoleByOrgAndRole(_ context.Context, organizationID string, roleName string) (*types.OrganizationRole, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, role := range s.organizationRoles {
		if role.OrganizationID == organizationID && role.Role == roleName {
			return cloneOrganizationRole(role), nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) UpdateOrganizationRole(_ context.Context, roleID string, roleName string, permission map[string][]string) (*types.OrganizationRole, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	role, ok := s.organizationRoles[roleID]
	if !ok {
		return nil, ErrNotFound
	}
	if roleName != role.Role {
		for _, existing := range s.organizationRoles {
			if existing.ID != roleID && existing.OrganizationID == role.OrganizationID && existing.Role == roleName {
				return nil, ErrAlreadyExists
			}
		}
		role.Role = roleName
	}
	role.Permission = cloneOrganizationRolePermission(permission)
	now := time.Now().UTC()
	role.UpdatedAt = &now
	return cloneOrganizationRole(role), nil
}

func (s *Store) DeleteOrganizationRole(_ context.Context, roleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.organizationRoles[roleID]; !ok {
		return ErrNotFound
	}
	delete(s.organizationRoles, roleID)
	return nil
}

func (s *Store) ListOrganizationRolesByOrg(_ context.Context, organizationID string) ([]types.OrganizationRole, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []types.OrganizationRole{}
	for _, role := range s.organizationRoles {
		if role.OrganizationID == organizationID {
			out = append(out, *cloneOrganizationRole(role))
		}
	}
	return out, nil
}

func (s *Store) CreateTwoFactor(_ context.Context, rec *types.TwoFactorRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *rec
	s.twoFactor[rec.UserID] = &cp
	return nil
}

func (s *Store) FindTwoFactorByUserID(_ context.Context, userID string) (*types.TwoFactorRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.twoFactor[userID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *rec
	return &cp, nil
}

func (s *Store) UpdateTwoFactor(_ context.Context, userID string, secret, backupCodes string, verified bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.twoFactor[userID]
	if !ok {
		return ErrNotFound
	}
	rec.Secret = secret
	rec.BackupCodes = backupCodes
	rec.Verified = verified
	return nil
}

func (s *Store) UpdateTwoFactorLockout(_ context.Context, userID string, failedVerificationCount int, lockedUntil *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.twoFactor[userID]
	if !ok {
		return ErrNotFound
	}
	rec.FailedVerificationCount = failedVerificationCount
	rec.LockedUntil = lockedUntil
	return nil
}

func (s *Store) DeleteTwoFactor(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.twoFactor, userID)
	return nil
}

func (s *Store) CreateDeviceCode(_ context.Context, dc *types.DeviceCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *dc
	s.deviceCodes[dc.DeviceCode] = &cp
	s.deviceCodesByUser[dc.UserCode] = dc.DeviceCode
	return nil
}

func (s *Store) FindDeviceCodeByDeviceCode(_ context.Context, code string) (*types.DeviceCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	dc, ok := s.deviceCodes[code]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *dc
	return &cp, nil
}

func (s *Store) FindDeviceCodeByUserCode(_ context.Context, code string) (*types.DeviceCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.deviceCodesByUser[code]
	if !ok {
		return nil, ErrNotFound
	}
	dc := s.deviceCodes[key]
	cp := *dc
	return &cp, nil
}

func (s *Store) UpdateDeviceCode(_ context.Context, id string, userID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, dc := range s.deviceCodes {
		if dc.ID == id {
			dc.UserID = userID
			dc.Status = status
			return nil
		}
	}
	return ErrNotFound
}

func (s *Store) CreateJWKS(_ context.Context, rec *types.JWKSRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *rec
	s.jwks[rec.ID] = &cp
	return nil
}

func (s *Store) ListJWKS(_ context.Context) ([]types.JWKSRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.JWKSRecord, 0, len(s.jwks))
	for _, j := range s.jwks {
		out = append(out, *j)
	}
	return out, nil
}

func (s *Store) CreateOAuthApp(_ context.Context, app *types.OAuthApplication) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *app
	s.oauthApps[app.ClientID] = &cp
	return nil
}

func (s *Store) FindOAuthAppByClientID(_ context.Context, clientID string) (*types.OAuthApplication, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	app, ok := s.oauthApps[clientID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *app
	return &cp, nil
}

func (s *Store) CreateWallet(_ context.Context, w *types.WalletAddress) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *w
	key := walletKey(w.Address, w.ChainID)
	s.wallets[key] = &cp
	return nil
}

func (s *Store) FindWalletByAddress(_ context.Context, address string, chainID int) (*types.WalletAddress, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w, ok := s.wallets[walletKey(address, chainID)]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *w
	return &cp, nil
}

func (s *Store) ListWalletsByUser(_ context.Context, userID string) ([]types.WalletAddress, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []types.WalletAddress
	for _, w := range s.wallets {
		if w.UserID == userID {
			out = append(out, *w)
		}
	}
	return out, nil
}

func walletKey(address string, chainID int) string {
	return strings.ToLower(address) + ":" + strconv.Itoa(chainID)
}
