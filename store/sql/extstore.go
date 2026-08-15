package sql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

// =========================================================================
// Organization
// =========================================================================

func (s *Store) CreateOrganization(ctx context.Context, o *types.Organization) error {
	var existing string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id FROM `+s.table("organization")+` WHERE slug = ?`), o.Slug).Scan(&existing)
	if err == nil {
		return berrors.ErrAlreadyExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.q(`
		INSERT INTO `+s.table("organization")+` (id, name, slug, logo, metadata, `+s.table("createdAt")+`, `+s.table("updatedAt")+`)
		VALUES (?, ?, ?, ?, ?, ?, ?)`),
		o.ID, o.Name, o.Slug, strOrNil(o.Logo), nullStr(o.Metadata), toMillis(o.CreatedAt), nullMillis(o.UpdatedAt))
	return err
}

func (s *Store) scanOrg(row interface{ Scan(...any) error }) (*types.Organization, error) {
	var (
		o         types.Organization
		logo      sql.NullString
		metadata  sql.NullString
		createdAt int64
		updatedAt sql.NullInt64
	)
	if err := row.Scan(&o.ID, &o.Name, &o.Slug, &logo, &metadata, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	if logo.Valid {
		v := logo.String
		o.Logo = &v
	}
	o.Metadata = metadata.String
	o.CreatedAt = fromMillis(createdAt)
	o.UpdatedAt = scanNullMillis(updatedAt)
	return &o, nil
}

var orgColNames = []string{"id", "name", "slug", "logo", "metadata", "createdAt", "updatedAt"}

func (s *Store) FindOrganizationByID(ctx context.Context, id string) (*types.Organization, error) {
	return s.scanOrg(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(orgColNames...)+` FROM `+s.table("organization")+` WHERE id = ?`), id))
}

func (s *Store) FindOrganizationBySlug(ctx context.Context, slug string) (*types.Organization, error) {
	return s.scanOrg(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(orgColNames...)+` FROM `+s.table("organization")+` WHERE slug = ?`), slug))
}

func (s *Store) UpdateOrganization(ctx context.Context, id string, name, slug string, logo *string, metadata *string) (*types.Organization, error) {
	o, err := s.FindOrganizationByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if slug != "" && slug != o.Slug {
		var existing string
		err := s.db.QueryRowContext(ctx, s.q(`SELECT id FROM `+s.table("organization")+` WHERE slug = ?`), slug).Scan(&existing)
		if err == nil {
			return nil, berrors.ErrAlreadyExists
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
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
	_, err = s.db.ExecContext(ctx, s.q(`UPDATE `+s.table("organization")+` SET name = ?, slug = ?, logo = ?, metadata = ?, `+s.table("updatedAt")+` = ? WHERE id = ?`),
		o.Name, o.Slug, strOrNil(o.Logo), nullStr(o.Metadata), toMillis(now), id)
	if err != nil {
		return nil, err
	}
	return o, nil
}

func (s *Store) DeleteOrganization(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("organization")+` WHERE id = ?`), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	_, _ = s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("member")+` WHERE `+s.table("organizationId")+` = ?`), id)
	_, _ = s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("invitation")+` WHERE `+s.table("organizationId")+` = ?`), id)
	_, _ = s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("team")+` WHERE `+s.table("organizationId")+` = ?`), id)
	_, _ = s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("organizationRole")+` WHERE `+s.table("organizationId")+` = ?`), id)
	return nil
}

func (s *Store) ListOrganizations(ctx context.Context) ([]types.Organization, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+s.cols(orgColNames...)+` FROM `+s.table("organization")))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []types.Organization{}
	for rows.Next() {
		o, err := s.scanOrg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *o)
	}
	return out, rows.Err()
}

// =========================================================================
// Member
// =========================================================================

var memberColNames = []string{"id", "organizationId", "userId", "role", "createdAt"}

func (s *Store) scanMember(row interface{ Scan(...any) error }) (*types.Member, error) {
	var (
		m         types.Member
		createdAt int64
	)
	if err := row.Scan(&m.ID, &m.OrganizationID, &m.UserID, &m.Role, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	m.CreatedAt = fromMillis(createdAt)
	return &m, nil
}

func (s *Store) CreateMember(ctx context.Context, m *types.Member) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO `+s.table("member")+` (`+s.cols(memberColNames...)+`) VALUES (?, ?, ?, ?, ?)`),
		m.ID, m.OrganizationID, m.UserID, m.Role, toMillis(m.CreatedAt))
	return err
}

func (s *Store) DeleteMember(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("member")+` WHERE id = ?`), id)
	return err
}

func (s *Store) FindMemberByID(ctx context.Context, id string) (*types.Member, error) {
	return s.scanMember(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(memberColNames...)+` FROM `+s.table("member")+` WHERE id = ?`), id))
}

func (s *Store) FindMemberByOrgAndUser(ctx context.Context, orgID, userID string) (*types.Member, error) {
	return s.scanMember(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(memberColNames...)+` FROM `+s.table("member")+` WHERE `+s.table("organizationId")+` = ? AND `+s.table("userId")+` = ?`), orgID, userID))
}

func (s *Store) UpdateMemberRole(ctx context.Context, id string, role string) (*types.Member, error) {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE `+s.table("member")+` SET role = ? WHERE id = ?`), role, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, berrors.ErrNotFound
	}
	return s.FindMemberByID(ctx, id)
}

func (s *Store) listMembers(ctx context.Context, where string, arg string) ([]types.Member, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+s.cols(memberColNames...)+` FROM `+s.table("member")+` WHERE `+where), arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Member
	for rows.Next() {
		m, err := s.scanMember(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

func (s *Store) ListMembersByOrg(ctx context.Context, orgID string) ([]types.Member, error) {
	return s.listMembers(ctx, s.table("organizationId")+" = ?", orgID)
}

func (s *Store) ListMembersByUser(ctx context.Context, userID string) ([]types.Member, error) {
	return s.listMembers(ctx, s.table("userId")+" = ?", userID)
}

// =========================================================================
// Invitation
// =========================================================================

const invitationTeamIDColName = "teamId"

var invitationBaseColNames = []string{"id", "organizationId", "email", "role", "status", "inviterId", "expiresAt", "createdAt"}

func invitationColNames(includeTeamID bool) []string {
	cols := make([]string, 0, len(invitationBaseColNames)+1)
	cols = append(cols, invitationBaseColNames[:6]...)
	if includeTeamID {
		cols = append(cols, invitationTeamIDColName)
	}
	cols = append(cols, invitationBaseColNames[6:]...)
	return cols
}

func (s *Store) invitationTeamIDColumnPresent(ctx context.Context) (bool, error) {
	cols, err := s.columnsPresent(ctx, "invitation", []string{invitationTeamIDColName})
	if err != nil {
		return false, err
	}
	return len(cols) > 0, nil
}

func (s *Store) scanInvitation(row interface{ Scan(...any) error }, includeTeamID bool) (*types.Invitation, error) {
	var (
		inv       types.Invitation
		teamID    sql.NullString
		expiresAt int64
		createdAt int64
	)
	var err error
	if includeTeamID {
		err = row.Scan(&inv.ID, &inv.OrganizationID, &inv.Email, &inv.Role, &inv.Status, &inv.InviterID, &teamID, &expiresAt, &createdAt)
	} else {
		err = row.Scan(&inv.ID, &inv.OrganizationID, &inv.Email, &inv.Role, &inv.Status, &inv.InviterID, &expiresAt, &createdAt)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	inv.TeamID = teamID.String
	inv.ExpiresAt = fromMillis(expiresAt)
	inv.CreatedAt = fromMillis(createdAt)
	return &inv, nil
}

func (s *Store) CreateInvitation(ctx context.Context, inv *types.Invitation) error {
	includeTeamID, err := s.invitationTeamIDColumnPresent(ctx)
	if err != nil {
		return err
	}
	if !includeTeamID {
		if inv.TeamID != "" {
			return fmt.Errorf("invitation teamId requires organization teams schema: table=%q column=%q invitationId=%q organizationId=%q", "invitation", invitationTeamIDColName, inv.ID, inv.OrganizationID)
		}
		_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO `+s.table("invitation")+` (`+s.cols(invitationColNames(false)...)+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
			inv.ID, inv.OrganizationID, inv.Email, inv.Role, inv.Status, inv.InviterID, toMillis(inv.ExpiresAt), toMillis(inv.CreatedAt))
		return err
	}
	_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO `+s.table("invitation")+` (`+s.cols(invitationColNames(true)...)+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		inv.ID, inv.OrganizationID, inv.Email, inv.Role, inv.Status, inv.InviterID, nullStr(inv.TeamID), toMillis(inv.ExpiresAt), toMillis(inv.CreatedAt))
	return err
}

func (s *Store) FindInvitationByID(ctx context.Context, id string) (*types.Invitation, error) {
	includeTeamID, err := s.invitationTeamIDColumnPresent(ctx)
	if err != nil {
		return nil, err
	}
	return s.scanInvitation(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(invitationColNames(includeTeamID)...)+` FROM `+s.table("invitation")+` WHERE id = ?`), id), includeTeamID)
}

func (s *Store) UpdateInvitationStatus(ctx context.Context, id, status string) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE `+s.table("invitation")+` SET status = ? WHERE id = ?`), status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

func (s *Store) UpdateInvitationExpiresAt(ctx context.Context, id string, expiresAt time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE `+s.table("invitation")+` SET `+s.table("expiresAt")+` = ? WHERE id = ?`), toMillis(expiresAt), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

func (s *Store) listInvitations(ctx context.Context, where, arg string) ([]types.Invitation, error) {
	includeTeamID, err := s.invitationTeamIDColumnPresent(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+s.cols(invitationColNames(includeTeamID)...)+` FROM `+s.table("invitation")+` WHERE `+where), arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Invitation
	for rows.Next() {
		inv, err := s.scanInvitation(rows, includeTeamID)
		if err != nil {
			return nil, err
		}
		out = append(out, *inv)
	}
	return out, rows.Err()
}

func (s *Store) ListInvitationsByOrg(ctx context.Context, orgID string) ([]types.Invitation, error) {
	return s.listInvitations(ctx, s.table("organizationId")+" = ?", orgID)
}

func (s *Store) ListInvitationsByEmail(ctx context.Context, email string) ([]types.Invitation, error) {
	return s.listInvitations(ctx, "LOWER(email) = ?", lowerLike(email))
}

// =========================================================================
// Team
// =========================================================================

var teamColNames = []string{"id", "name", "organizationId", "createdAt", "updatedAt"}

func (s *Store) scanTeam(row interface{ Scan(...any) error }) (*types.Team, error) {
	var (
		t         types.Team
		createdAt int64
		updatedAt sql.NullInt64
	)
	if err := row.Scan(&t.ID, &t.Name, &t.OrganizationID, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	t.CreatedAt = fromMillis(createdAt)
	if updatedAt.Valid {
		t.UpdatedAt = fromMillis(updatedAt.Int64)
	}
	return &t, nil
}

func (s *Store) CreateTeam(ctx context.Context, t *types.Team) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO `+s.table("team")+` (`+s.cols(teamColNames...)+`) VALUES (?, ?, ?, ?, ?)`),
		t.ID, t.Name, t.OrganizationID, toMillis(t.CreatedAt), nullTimeMillis(t.UpdatedAt))
	return err
}

func (s *Store) DeleteTeam(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("team")+` WHERE id = ?`), id)
	if err != nil {
		return err
	}
	_, _ = s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("teamMember")+` WHERE `+s.table("teamId")+` = ?`), id)
	return nil
}

func (s *Store) FindTeamByID(ctx context.Context, id string) (*types.Team, error) {
	return s.scanTeam(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(teamColNames...)+` FROM `+s.table("team")+` WHERE id = ?`), id))
}

func (s *Store) UpdateTeam(ctx context.Context, id string, name string) (*types.Team, error) {
	t, err := s.FindTeamByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if name != "" {
		t.Name = name
	}
	now := time.Now()
	t.UpdatedAt = now
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE `+s.table("team")+` SET name = ?, `+s.table("updatedAt")+` = ? WHERE id = ?`), t.Name, toMillis(now), id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, berrors.ErrNotFound
	}
	return t, nil
}

func (s *Store) ListTeamsByOrg(ctx context.Context, orgID string) ([]types.Team, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+s.cols(teamColNames...)+` FROM `+s.table("team")+` WHERE `+s.table("organizationId")+` = ?`), orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Team
	for rows.Next() {
		t, err := s.scanTeam(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (s *Store) ListTeamsByUser(ctx context.Context, userID string) ([]types.Team, error) {
	teamCols := `t.` + s.table("id") + `, t.` + s.table("name") + `, t.` + s.table("organizationId") + `, t.` + s.table("createdAt") + `, t.` + s.table("updatedAt")
	rows, err := s.db.QueryContext(ctx, s.q(`
		SELECT `+teamCols+`
		FROM `+s.table("team")+` t
		INNER JOIN `+s.table("teamMember")+` tm ON tm.`+s.table("teamId")+` = t.`+s.table("id")+`
		WHERE tm.`+s.table("userId")+` = ?`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Team
	for rows.Next() {
		t, err := s.scanTeam(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// =========================================================================
// TeamMember
// =========================================================================

func (s *Store) CreateTeamMember(ctx context.Context, tm *types.TeamMember) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO `+s.table("teamMember")+` (id, `+s.table("teamId")+`, `+s.table("userId")+`, `+s.table("createdAt")+`) VALUES (?, ?, ?, ?)`),
		tm.ID, tm.TeamID, tm.UserID, toMillis(tm.CreatedAt))
	return err
}

func (s *Store) DeleteTeamMember(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("teamMember")+` WHERE id = ?`), id)
	return err
}

func (s *Store) DeleteTeamMemberByTeamAndUser(ctx context.Context, teamID string, userID string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("teamMember")+` WHERE `+s.table("teamId")+` = ? AND `+s.table("userId")+` = ?`), teamID, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

func (s *Store) FindTeamMember(ctx context.Context, teamID string, userID string) (*types.TeamMember, error) {
	var (
		tm        types.TeamMember
		createdAt int64
	)
	row := s.db.QueryRowContext(ctx, s.q(`SELECT id, `+s.table("teamId")+`, `+s.table("userId")+`, `+s.table("createdAt")+` FROM `+s.table("teamMember")+` WHERE `+s.table("teamId")+` = ? AND `+s.table("userId")+` = ?`), teamID, userID)
	if err := row.Scan(&tm.ID, &tm.TeamID, &tm.UserID, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	tm.CreatedAt = fromMillis(createdAt)
	return &tm, nil
}

func (s *Store) ListTeamMembers(ctx context.Context, teamID string) ([]types.TeamMember, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT id, `+s.table("teamId")+`, `+s.table("userId")+`, `+s.table("createdAt")+` FROM `+s.table("teamMember")+` WHERE `+s.table("teamId")+` = ?`), teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.TeamMember
	for rows.Next() {
		var (
			tm        types.TeamMember
			createdAt int64
		)
		if err := rows.Scan(&tm.ID, &tm.TeamID, &tm.UserID, &createdAt); err != nil {
			return nil, err
		}
		tm.CreatedAt = fromMillis(createdAt)
		out = append(out, tm)
	}
	return out, rows.Err()
}

// =========================================================================
// OrganizationRole
// =========================================================================

var organizationRoleColNames = []string{"id", "organizationId", "role", "permission", "createdAt", "updatedAt"}

func encodeOrganizationRolePermission(permission map[string][]string) (string, error) {
	data, err := json.Marshal(permission)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decodeOrganizationRolePermission(raw string) (map[string][]string, error) {
	permission := map[string][]string{}
	if raw == "" {
		return permission, nil
	}
	if err := json.Unmarshal([]byte(raw), &permission); err != nil {
		return nil, err
	}
	return permission, nil
}

func (s *Store) scanOrganizationRole(row interface{ Scan(...any) error }) (*types.OrganizationRole, error) {
	var (
		role       types.OrganizationRole
		permission string
		createdAt  int64
		updatedAt  sql.NullInt64
	)
	if err := row.Scan(&role.ID, &role.OrganizationID, &role.Role, &permission, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	decoded, err := decodeOrganizationRolePermission(permission)
	if err != nil {
		return nil, err
	}
	role.Permission = decoded
	role.CreatedAt = fromMillis(createdAt)
	role.UpdatedAt = scanNullMillis(updatedAt)
	return &role, nil
}

func (s *Store) CreateOrganizationRole(ctx context.Context, role *types.OrganizationRole) error {
	if _, err := s.FindOrganizationRoleByOrgAndRole(ctx, role.OrganizationID, role.Role); err == nil {
		return berrors.ErrAlreadyExists
	} else if !errors.Is(err, berrors.ErrNotFound) {
		return err
	}
	permission, err := encodeOrganizationRolePermission(role.Permission)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.q(`INSERT INTO `+s.table("organizationRole")+` (`+s.cols(organizationRoleColNames...)+`) VALUES (?, ?, ?, ?, ?, ?)`),
		role.ID, role.OrganizationID, role.Role, permission, toMillis(role.CreatedAt), nullMillis(role.UpdatedAt))
	return err
}

func (s *Store) FindOrganizationRoleByID(ctx context.Context, id string) (*types.OrganizationRole, error) {
	return s.scanOrganizationRole(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(organizationRoleColNames...)+` FROM `+s.table("organizationRole")+` WHERE id = ?`), id))
}

func (s *Store) FindOrganizationRoleByOrgAndRole(ctx context.Context, organizationID string, role string) (*types.OrganizationRole, error) {
	return s.scanOrganizationRole(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(organizationRoleColNames...)+` FROM `+s.table("organizationRole")+` WHERE `+s.table("organizationId")+` = ? AND role = ?`), organizationID, role))
}

func (s *Store) UpdateOrganizationRole(ctx context.Context, id string, role string, permission map[string][]string) (*types.OrganizationRole, error) {
	existing, err := s.FindOrganizationRoleByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if role != existing.Role {
		if _, err := s.FindOrganizationRoleByOrgAndRole(ctx, existing.OrganizationID, role); err == nil {
			return nil, berrors.ErrAlreadyExists
		} else if !errors.Is(err, berrors.ErrNotFound) {
			return nil, err
		}
	}
	encoded, err := encodeOrganizationRolePermission(permission)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE `+s.table("organizationRole")+` SET role = ?, permission = ?, `+s.table("updatedAt")+` = ? WHERE id = ?`),
		role, encoded, toMillis(now), id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, berrors.ErrNotFound
	}
	return s.FindOrganizationRoleByID(ctx, id)
}

func (s *Store) DeleteOrganizationRole(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("organizationRole")+` WHERE id = ?`), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

func (s *Store) ListOrganizationRolesByOrg(ctx context.Context, organizationID string) ([]types.OrganizationRole, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+s.cols(organizationRoleColNames...)+` FROM `+s.table("organizationRole")+` WHERE `+s.table("organizationId")+` = ?`), organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []types.OrganizationRole{}
	for rows.Next() {
		role, err := s.scanOrganizationRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *role)
	}
	return out, rows.Err()
}

// =========================================================================
// TwoFactor
// =========================================================================

func (s *Store) CreateTwoFactor(ctx context.Context, rec *types.TwoFactorRecord) error {
	_, _ = s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("twoFactor")+` WHERE `+s.table("userId")+` = ?`), rec.UserID)
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO `+s.table("twoFactor")+` (id, `+s.table("userId")+`, secret, `+s.table("backupCodes")+`, verified, `+s.table("failedVerificationCount")+`, `+s.table("lockedUntil")+`)
		VALUES (?, ?, ?, ?, ?, ?, ?)`),
		rec.ID, rec.UserID, rec.Secret, rec.BackupCodes, boolToInt(rec.Verified), rec.FailedVerificationCount, nullMillis(rec.LockedUntil))
	return err
}

func (s *Store) FindTwoFactorByUserID(ctx context.Context, userID string) (*types.TwoFactorRecord, error) {
	var (
		rec                     types.TwoFactorRecord
		verified                int
		failedVerificationCount int
		lockedUntil             sql.NullInt64
	)
	row := s.db.QueryRowContext(ctx, s.q(`
		SELECT id, `+s.table("userId")+`, secret, `+s.table("backupCodes")+`, verified, `+s.table("failedVerificationCount")+`, `+s.table("lockedUntil")+` FROM `+s.table("twoFactor")+` WHERE `+s.table("userId")+` = ?`), userID)
	if err := row.Scan(&rec.ID, &rec.UserID, &rec.Secret, &rec.BackupCodes, &verified, &failedVerificationCount, &lockedUntil); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	rec.Verified = verified != 0
	rec.FailedVerificationCount = failedVerificationCount
	rec.LockedUntil = scanNullMillis(lockedUntil)
	return &rec, nil
}

func (s *Store) UpdateTwoFactor(ctx context.Context, userID string, secret, backupCodes string, verified bool) error {
	res, err := s.db.ExecContext(ctx, s.q(`
		UPDATE `+s.table("twoFactor")+` SET secret = ?, `+s.table("backupCodes")+` = ?, verified = ? WHERE `+s.table("userId")+` = ?`),
		secret, backupCodes, boolToInt(verified), userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

func (s *Store) UpdateTwoFactorLockout(ctx context.Context, userID string, failedVerificationCount int, lockedUntil *time.Time) error {
	res, err := s.db.ExecContext(ctx, s.q(`
		UPDATE `+s.table("twoFactor")+` SET `+s.table("failedVerificationCount")+` = ?, `+s.table("lockedUntil")+` = ? WHERE `+s.table("userId")+` = ?`),
		failedVerificationCount, nullMillis(lockedUntil), userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteTwoFactor(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("twoFactor")+` WHERE `+s.table("userId")+` = ?`), userID)
	return err
}

// =========================================================================
// DeviceCode
// =========================================================================

var deviceColNames = []string{"id", "deviceCode", "userCode", "userId", "status", "expiresAt", "lastPolledAt", "pollingInterval", "clientId", "scope"}

func (s *Store) scanDeviceCode(row interface{ Scan(...any) error }) (*types.DeviceCode, error) {
	var (
		dc        types.DeviceCode
		userID    sql.NullString
		lastPoll  sql.NullInt64
		clientID  sql.NullString
		scope     sql.NullString
		expiresAt int64
	)
	if err := row.Scan(&dc.ID, &dc.DeviceCode, &dc.UserCode, &userID, &dc.Status, &expiresAt, &lastPoll, &dc.Interval, &clientID, &scope); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	dc.UserID = userID.String
	dc.LastPolledAt = scanNullMillis(lastPoll)
	dc.ClientID = clientID.String
	dc.Scope = scope.String
	dc.ExpiresAt = fromMillis(expiresAt)
	return &dc, nil
}

func (s *Store) CreateDeviceCode(ctx context.Context, dc *types.DeviceCode) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO `+s.table("deviceCode")+` (`+s.cols(deviceColNames...)+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		dc.ID, dc.DeviceCode, dc.UserCode, nullStr(dc.UserID), dc.Status, toMillis(dc.ExpiresAt), nullMillis(dc.LastPolledAt), dc.Interval,
		nullStr(dc.ClientID), nullStr(dc.Scope))
	return err
}

func (s *Store) FindDeviceCodeByDeviceCode(ctx context.Context, code string) (*types.DeviceCode, error) {
	return s.scanDeviceCode(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(deviceColNames...)+` FROM `+s.table("deviceCode")+` WHERE `+s.table("deviceCode")+` = ?`), code))
}

func (s *Store) FindDeviceCodeByUserCode(ctx context.Context, code string) (*types.DeviceCode, error) {
	return s.scanDeviceCode(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(deviceColNames...)+` FROM `+s.table("deviceCode")+` WHERE `+s.table("userCode")+` = ?`), code))
}

func (s *Store) UpdateDeviceCode(ctx context.Context, id string, userID, status string) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE `+s.table("deviceCode")+` SET `+s.table("userId")+` = ?, status = ? WHERE id = ?`),
		nullStr(userID), status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

// =========================================================================
// JWKS
// =========================================================================

func (s *Store) CreateJWKS(ctx context.Context, rec *types.JWKSRecord) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO `+s.table("jwks")+` (id, `+s.table("publicKey")+`, `+s.table("privateKey")+`, `+s.table("createdAt")+`, `+s.table("expiresAt")+`) VALUES (?, ?, ?, ?, ?)`),
		rec.ID, rec.PublicKey, nullStr(rec.PrivateKey), toMillis(rec.CreatedAt), nullMillis(rec.ExpiresAt))
	return err
}

func (s *Store) ListJWKS(ctx context.Context) ([]types.JWKSRecord, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT id, `+s.table("publicKey")+`, `+s.table("privateKey")+`, `+s.table("createdAt")+`, `+s.table("expiresAt")+` FROM `+s.table("jwks")))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []types.JWKSRecord{}
	for rows.Next() {
		var (
			rec        types.JWKSRecord
			privateKey sql.NullString
			createdAt  int64
			expiresAt  sql.NullInt64
		)
		if err := rows.Scan(&rec.ID, &rec.PublicKey, &privateKey, &createdAt, &expiresAt); err != nil {
			return nil, err
		}
		rec.PrivateKey = privateKey.String
		rec.CreatedAt = fromMillis(createdAt)
		rec.ExpiresAt = scanNullMillis(expiresAt)
		out = append(out, rec)
	}
	return out, rows.Err()
}

// =========================================================================
// OAuthApplication
// =========================================================================

func (s *Store) CreateOAuthApp(ctx context.Context, app *types.OAuthApplication) error {
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO `+s.table("oauthApplication")+` (id, `+s.table("clientId")+`, `+s.table("clientSecret")+`, name, icon, metadata, `+s.table("redirectUrls")+`, type, disabled, `+s.table("userId")+`, `+s.table("createdAt")+`, `+s.table("updatedAt")+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		app.ID, app.ClientID, nullStr(app.ClientSecret), app.Name, nullStr(app.Icon), nullStr(app.Metadata),
		app.RedirectURLs, app.Type, boolToInt(app.Disabled), nullStr(app.UserID), toMillis(app.CreatedAt), toMillis(app.UpdatedAt))
	return err
}

func (s *Store) FindOAuthAppByClientID(ctx context.Context, clientID string) (*types.OAuthApplication, error) {
	var (
		app          types.OAuthApplication
		clientSecret sql.NullString
		icon         sql.NullString
		metadata     sql.NullString
		userID       sql.NullString
		disabled     int
		createdAt    int64
		updatedAt    int64
	)
	row := s.db.QueryRowContext(ctx, s.q(`
		SELECT id, `+s.table("clientId")+`, `+s.table("clientSecret")+`, name, icon, metadata, `+s.table("redirectUrls")+`, type, disabled, `+s.table("userId")+`, `+s.table("createdAt")+`, `+s.table("updatedAt")+` FROM `+s.table("oauthApplication")+` WHERE `+s.table("clientId")+` = ?`), clientID)
	if err := row.Scan(&app.ID, &app.ClientID, &clientSecret, &app.Name, &icon, &metadata, &app.RedirectURLs, &app.Type, &disabled, &userID, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	app.ClientSecret = clientSecret.String
	app.Icon = icon.String
	app.Metadata = metadata.String
	app.Disabled = disabled != 0
	app.UserID = userID.String
	app.CreatedAt = fromMillis(createdAt)
	app.UpdatedAt = fromMillis(updatedAt)
	return &app, nil
}

// =========================================================================
// Wallet
// =========================================================================

func (s *Store) scanWallet(row interface{ Scan(...any) error }) (*types.WalletAddress, error) {
	var (
		w         types.WalletAddress
		isPrimary int
		createdAt int64
	)
	if err := row.Scan(&w.ID, &w.UserID, &w.Address, &w.ChainID, &isPrimary, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	w.IsPrimary = isPrimary != 0
	w.CreatedAt = fromMillis(createdAt)
	return &w, nil
}

func (s *Store) CreateWallet(ctx context.Context, w *types.WalletAddress) error {
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO `+s.table("walletAddress")+` (id, `+s.table("userId")+`, address, `+s.table("chainId")+`, `+s.table("isPrimary")+`, `+s.table("createdAt")+`) VALUES (?, ?, ?, ?, ?, ?)`),
		w.ID, w.UserID, w.Address, w.ChainID, boolToInt(w.IsPrimary), toMillis(w.CreatedAt))
	return err
}

func (s *Store) FindWalletByAddress(ctx context.Context, address string, chainID int) (*types.WalletAddress, error) {
	return s.scanWallet(s.db.QueryRowContext(ctx, s.q(`
		SELECT id, `+s.table("userId")+`, address, `+s.table("chainId")+`, `+s.table("isPrimary")+`, `+s.table("createdAt")+` FROM `+s.table("walletAddress")+` WHERE LOWER(address) = ? AND `+s.table("chainId")+` = ?`),
		lowerLike(address), chainID))
}

func (s *Store) ListWalletsByUser(ctx context.Context, userID string) ([]types.WalletAddress, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`
		SELECT id, `+s.table("userId")+`, address, `+s.table("chainId")+`, `+s.table("isPrimary")+`, `+s.table("createdAt")+` FROM `+s.table("walletAddress")+` WHERE `+s.table("userId")+` = ?`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.WalletAddress
	for rows.Next() {
		w, err := s.scanWallet(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *w)
	}
	return out, rows.Err()
}

// =========================================================================
// APIKey
// =========================================================================

var apiKeyColNames = []string{
	"id", "configId", "name", "start", "referenceId", "prefix", "key",
	"refillInterval", "refillAmount", "lastRefillAt", "enabled",
	"rateLimitEnabled", "rateLimitTimeWindow", "rateLimitMax", "requestCount",
	"remaining", "lastRequest", "expiresAt", "createdAt", "updatedAt",
	"permissions", "metadata",
}

func (s *Store) CreateAPIKey(ctx context.Context, key *types.APIKey) error {
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO `+s.table("apikey")+` (`+s.cols(apiKeyColNames...)+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		key.ID, key.ConfigID, nullStr(key.Name), nullStr(key.Start), key.ReferenceID, nullStr(key.Prefix), key.Key,
		nullZeroInt64(key.RefillInterval), nullZeroInt(key.RefillAmount), nullMillis(key.LastRefillAt), boolToInt(key.Enabled),
		boolToInt(key.RateLimitEnabled), key.RateLimitTimeWindow, key.RateLimitMax, key.RequestCount,
		nullInt(key.Remaining), nullMillis(key.LastRequest), nullMillis(key.ExpiresAt), toMillis(key.CreatedAt), toMillis(key.UpdatedAt),
		nullStr(key.Permissions), nullStr(key.Metadata))
	return err
}

func (s *Store) FindAPIKeyByID(ctx context.Context, id string) (*types.APIKey, error) {
	return s.scanAPIKey(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(apiKeyColNames...)+` FROM `+s.table("apikey")+` WHERE id = ?`), id))
}

func (s *Store) FindAPIKeyByKey(ctx context.Context, hashedKey string) (*types.APIKey, error) {
	return s.scanAPIKey(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(apiKeyColNames...)+` FROM `+s.table("apikey")+` WHERE key = ?`), hashedKey))
}

func (s *Store) ListAPIKeysByReference(ctx context.Context, referenceID string) ([]types.APIKey, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+s.cols(apiKeyColNames...)+` FROM `+s.table("apikey")+` WHERE `+s.table("referenceId")+` = ?`), referenceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]types.APIKey, 0)
	for rows.Next() {
		key, err := s.scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *key)
	}
	return out, rows.Err()
}

func (s *Store) UpdateAPIKey(ctx context.Context, id string, update store.APIKeyUpdate) (*types.APIKey, error) {
	key, err := s.FindAPIKeyByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if update.Name != nil {
		key.Name = *update.Name
	}
	if update.Enabled != nil {
		key.Enabled = *update.Enabled
	}
	if update.ExpiresAt != nil {
		key.ExpiresAt = update.ExpiresAt
	}
	if update.Permissions != nil {
		key.Permissions = *update.Permissions
	}
	if update.Metadata != nil {
		key.Metadata = *update.Metadata
	}
	if update.RequestCount != nil {
		key.RequestCount = *update.RequestCount
	}
	if update.Remaining != nil {
		key.Remaining = update.Remaining
	}
	if update.LastRequest != nil {
		key.LastRequest = update.LastRequest
	}
	if update.UpdatedAt != nil {
		key.UpdatedAt = *update.UpdatedAt
	} else {
		key.UpdatedAt = time.Now().UTC()
	}
	_, err = s.db.ExecContext(ctx, s.q(`
		UPDATE `+s.table("apikey")+` SET name = ?, enabled = ?, `+s.table("expiresAt")+` = ?, permissions = ?, metadata = ?,
		`+s.table("requestCount")+` = ?, remaining = ?, `+s.table("lastRequest")+` = ?, `+s.table("updatedAt")+` = ? WHERE id = ?`),
		nullStr(key.Name), boolToInt(key.Enabled), nullMillis(key.ExpiresAt), nullStr(key.Permissions), nullStr(key.Metadata),
		key.RequestCount, nullInt(key.Remaining), nullMillis(key.LastRequest), toMillis(key.UpdatedAt), id)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (s *Store) DeleteAPIKey(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("apikey")+` WHERE id = ?`), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteExpiredAPIKeys(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("apikey")+` WHERE `+s.table("expiresAt")+` IS NOT NULL AND `+s.table("expiresAt")+` < ?`), toMillis(now))
	return err
}

func (s *Store) scanAPIKey(row interface{ Scan(...any) error }) (*types.APIKey, error) {
	var (
		key              types.APIKey
		name             sql.NullString
		start            sql.NullString
		prefix           sql.NullString
		refillInterval   sql.NullInt64
		refillAmount     sql.NullInt64
		lastRefillAt     sql.NullInt64
		enabled          int
		rateLimitEnabled int
		remaining        sql.NullInt64
		lastRequest      sql.NullInt64
		expiresAt        sql.NullInt64
		createdAt        int64
		updatedAt        int64
		permissions      sql.NullString
		metadata         sql.NullString
	)
	err := row.Scan(
		&key.ID, &key.ConfigID, &name, &start, &key.ReferenceID, &prefix, &key.Key,
		&refillInterval, &refillAmount, &lastRefillAt, &enabled,
		&rateLimitEnabled, &key.RateLimitTimeWindow, &key.RateLimitMax, &key.RequestCount,
		&remaining, &lastRequest, &expiresAt, &createdAt, &updatedAt,
		&permissions, &metadata,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	key.Name = name.String
	key.Start = start.String
	key.Prefix = prefix.String
	key.RefillInterval = refillInterval.Int64
	key.RefillAmount = int(refillAmount.Int64)
	key.LastRefillAt = scanNullMillis(lastRefillAt)
	key.Enabled = enabled != 0
	key.RateLimitEnabled = rateLimitEnabled != 0
	key.Remaining = scanNullInt(remaining)
	key.LastRequest = scanNullMillis(lastRequest)
	key.ExpiresAt = scanNullMillis(expiresAt)
	key.CreatedAt = fromMillis(createdAt)
	key.UpdatedAt = fromMillis(updatedAt)
	key.Permissions = permissions.String
	key.Metadata = metadata.String
	return &key, nil
}

// =========================================================================
// SSOProvider
// =========================================================================

var ssoProviderColNames = []string{
	"id", "providerId", "issuer", "domain", "organizationId", "userId",
	"oidcConfig", "samlConfig", "domainVerified", "createdAt", "updatedAt",
}

func (s *Store) CreateSSOProvider(ctx context.Context, provider *types.SSOProvider) error {
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO `+s.table("ssoProvider")+` (`+s.cols(ssoProviderColNames...)+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		provider.ID, provider.ProviderID, provider.Issuer, provider.Domain, nullStr(provider.OrganizationID), provider.UserID,
		nullStr(provider.OIDCConfig), nullStr(provider.SAMLConfig), boolToInt(provider.DomainVerified),
		toMillis(provider.CreatedAt), toMillis(provider.UpdatedAt))
	return err
}

func (s *Store) FindSSOProviderByProviderID(ctx context.Context, providerID string) (*types.SSOProvider, error) {
	return s.scanSSOProvider(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(ssoProviderColNames...)+` FROM `+s.table("ssoProvider")+` WHERE `+s.table("providerId")+` = ?`), providerID))
}

func (s *Store) FindSSOProviderByDomain(ctx context.Context, domain string) (*types.SSOProvider, error) {
	return s.scanSSOProvider(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(ssoProviderColNames...)+` FROM `+s.table("ssoProvider")+` WHERE LOWER(domain) = ?`), lowerLike(domain)))
}

func (s *Store) ListSSOProvidersByUserID(ctx context.Context, userID string) ([]types.SSOProvider, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+s.cols(ssoProviderColNames...)+` FROM `+s.table("ssoProvider")+` WHERE `+s.table("userId")+` = ?`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]types.SSOProvider, 0)
	for rows.Next() {
		provider, err := s.scanSSOProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *provider)
	}
	return out, rows.Err()
}

func (s *Store) UpdateSSOProvider(ctx context.Context, providerID string, update store.SSOProviderUpdate) (*types.SSOProvider, error) {
	provider, err := s.FindSSOProviderByProviderID(ctx, providerID)
	if err != nil {
		return nil, err
	}
	if update.Issuer != nil {
		provider.Issuer = *update.Issuer
	}
	if update.Domain != nil {
		provider.Domain = *update.Domain
	}
	if update.OrganizationID != nil {
		provider.OrganizationID = *update.OrganizationID
	}
	if update.OIDCConfig != nil {
		provider.OIDCConfig = *update.OIDCConfig
	}
	if update.SAMLConfig != nil {
		provider.SAMLConfig = *update.SAMLConfig
	}
	if update.DomainVerified != nil {
		provider.DomainVerified = *update.DomainVerified
	}
	if update.UpdatedAt != nil {
		provider.UpdatedAt = *update.UpdatedAt
	} else {
		provider.UpdatedAt = time.Now().UTC()
	}
	_, err = s.db.ExecContext(ctx, s.q(`
		UPDATE `+s.table("ssoProvider")+` SET issuer = ?, domain = ?, `+s.table("organizationId")+` = ?,
		`+s.table("oidcConfig")+` = ?, `+s.table("samlConfig")+` = ?, `+s.table("domainVerified")+` = ?,
		`+s.table("updatedAt")+` = ? WHERE `+s.table("providerId")+` = ?`),
		provider.Issuer, provider.Domain, nullStr(provider.OrganizationID), nullStr(provider.OIDCConfig),
		nullStr(provider.SAMLConfig), boolToInt(provider.DomainVerified), toMillis(provider.UpdatedAt), providerID)
	if err != nil {
		return nil, err
	}
	return provider, nil
}

func (s *Store) DeleteSSOProvider(ctx context.Context, providerID string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("ssoProvider")+` WHERE `+s.table("providerId")+` = ?`), providerID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

func (s *Store) scanSSOProvider(row interface{ Scan(...any) error }) (*types.SSOProvider, error) {
	var (
		provider       types.SSOProvider
		organizationID sql.NullString
		oidcConfig     sql.NullString
		samlConfig     sql.NullString
		domainVerified int
		createdAt      int64
		updatedAt      int64
	)
	err := row.Scan(
		&provider.ID, &provider.ProviderID, &provider.Issuer, &provider.Domain, &organizationID, &provider.UserID,
		&oidcConfig, &samlConfig, &domainVerified, &createdAt, &updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	provider.OrganizationID = organizationID.String
	provider.OIDCConfig = oidcConfig.String
	provider.SAMLConfig = samlConfig.String
	provider.DomainVerified = domainVerified != 0
	provider.CreatedAt = fromMillis(createdAt)
	provider.UpdatedAt = fromMillis(updatedAt)
	return &provider, nil
}

// =========================================================================
// Passkey
// =========================================================================

var passkeyColNames = []string{
	"id", "userId", "name", "credentialID", "credentialJSON", "transports", "backedUp", "createdAt", "updatedAt",
}

func (s *Store) CreatePasskey(ctx context.Context, passkey *types.Passkey) error {
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO `+s.table("passkey")+` (`+s.cols(passkeyColNames...)+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		passkey.ID, passkey.UserID, nullStr(passkey.Name), passkey.CredentialID, passkey.CredentialJSON,
		nullStr(passkey.Transports), boolToInt(passkey.BackedUp), toMillis(passkey.CreatedAt), toMillis(passkey.UpdatedAt))
	return err
}

func (s *Store) FindPasskeyByCredentialID(ctx context.Context, credentialID string) (*types.Passkey, error) {
	return s.scanPasskey(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(passkeyColNames...)+` FROM `+s.table("passkey")+` WHERE `+s.table("credentialID")+` = ?`), credentialID))
}

func (s *Store) ListPasskeysByUserID(ctx context.Context, userID string) ([]types.Passkey, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+s.cols(passkeyColNames...)+` FROM `+s.table("passkey")+` WHERE `+s.table("userId")+` = ?`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]types.Passkey, 0)
	for rows.Next() {
		passkey, err := s.scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *passkey)
	}
	return out, rows.Err()
}

func (s *Store) UpdatePasskey(ctx context.Context, id string, update store.PasskeyUpdate) (*types.Passkey, error) {
	passkey, err := s.findPasskeyByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if update.Name != nil {
		passkey.Name = *update.Name
	}
	if update.CredentialJSON != nil {
		passkey.CredentialJSON = *update.CredentialJSON
	}
	if update.Transports != nil {
		passkey.Transports = *update.Transports
	}
	if update.BackedUp != nil {
		passkey.BackedUp = *update.BackedUp
	}
	if update.UpdatedAt != nil {
		passkey.UpdatedAt = *update.UpdatedAt
	} else {
		passkey.UpdatedAt = time.Now().UTC()
	}
	_, err = s.db.ExecContext(ctx, s.q(`
		UPDATE `+s.table("passkey")+` SET name = ?, `+s.table("credentialJSON")+` = ?, transports = ?,
		`+s.table("backedUp")+` = ?, `+s.table("updatedAt")+` = ? WHERE id = ?`),
		nullStr(passkey.Name), passkey.CredentialJSON, nullStr(passkey.Transports),
		boolToInt(passkey.BackedUp), toMillis(passkey.UpdatedAt), id)
	if err != nil {
		return nil, err
	}
	return passkey, nil
}

func (s *Store) DeletePasskey(ctx context.Context, id string, userID string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("passkey")+` WHERE id = ? AND `+s.table("userId")+` = ?`), id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

func (s *Store) findPasskeyByID(ctx context.Context, id string) (*types.Passkey, error) {
	return s.scanPasskey(s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(passkeyColNames...)+` FROM `+s.table("passkey")+` WHERE id = ?`), id))
}

func (s *Store) scanPasskey(row interface{ Scan(...any) error }) (*types.Passkey, error) {
	var (
		passkey    types.Passkey
		name       sql.NullString
		transports sql.NullString
		backedUp   int
		createdAt  int64
		updatedAt  int64
	)
	err := row.Scan(&passkey.ID, &passkey.UserID, &name, &passkey.CredentialID, &passkey.CredentialJSON, &transports, &backedUp, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	passkey.Name = name.String
	passkey.Transports = transports.String
	passkey.BackedUp = backedUp != 0
	passkey.CreatedAt = fromMillis(createdAt)
	passkey.UpdatedAt = fromMillis(updatedAt)
	return &passkey, nil
}

func nullZeroInt(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullZeroInt64(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullInt(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func scanNullInt(value sql.NullInt64) *int {
	if !value.Valid {
		return nil
	}
	out := int(value.Int64)
	return &out
}
