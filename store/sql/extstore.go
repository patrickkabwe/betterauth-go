package sql

import (
	"context"
	"database/sql"
	"errors"
	"time"

	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/types"
)

// =========================================================================
// Organization
// =========================================================================

func (s *Store) CreateOrganization(ctx context.Context, o *types.Organization) error {
	var existing string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id FROM ba_organization WHERE slug = ?`), o.Slug).Scan(&existing)
	if err == nil {
		return berrors.ErrAlreadyExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.q(`
		INSERT INTO ba_organization (id, name, slug, logo, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`),
		o.ID, o.Name, o.Slug, strOrNil(o.Logo), nullStr(o.Metadata), toMillis(o.CreatedAt))
	return err
}

func (s *Store) scanOrg(row interface{ Scan(...any) error }) (*types.Organization, error) {
	var (
		o         types.Organization
		logo      sql.NullString
		metadata  sql.NullString
		createdAt int64
	)
	if err := row.Scan(&o.ID, &o.Name, &o.Slug, &logo, &metadata, &createdAt); err != nil {
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
	return &o, nil
}

const orgCols = `id, name, slug, logo, metadata, created_at`

func (s *Store) FindOrganizationByID(ctx context.Context, id string) (*types.Organization, error) {
	return s.scanOrg(s.db.QueryRowContext(ctx, s.q(`SELECT `+orgCols+` FROM ba_organization WHERE id = ?`), id))
}

func (s *Store) FindOrganizationBySlug(ctx context.Context, slug string) (*types.Organization, error) {
	return s.scanOrg(s.db.QueryRowContext(ctx, s.q(`SELECT `+orgCols+` FROM ba_organization WHERE slug = ?`), slug))
}

func (s *Store) UpdateOrganization(ctx context.Context, id string, name, slug string, logo *string) (*types.Organization, error) {
	o, err := s.FindOrganizationByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if slug != "" && slug != o.Slug {
		var existing string
		err := s.db.QueryRowContext(ctx, s.q(`SELECT id FROM ba_organization WHERE slug = ?`), slug).Scan(&existing)
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
	_, err = s.db.ExecContext(ctx, s.q(`UPDATE ba_organization SET name = ?, slug = ?, logo = ? WHERE id = ?`),
		o.Name, o.Slug, strOrNil(o.Logo), id)
	if err != nil {
		return nil, err
	}
	return o, nil
}

func (s *Store) DeleteOrganization(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM ba_organization WHERE id = ?`), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	_, _ = s.db.ExecContext(ctx, s.q(`DELETE FROM ba_member WHERE organization_id = ?`), id)
	_, _ = s.db.ExecContext(ctx, s.q(`DELETE FROM ba_invitation WHERE organization_id = ?`), id)
	_, _ = s.db.ExecContext(ctx, s.q(`DELETE FROM ba_team WHERE organization_id = ?`), id)
	return nil
}

func (s *Store) ListOrganizations(ctx context.Context) ([]types.Organization, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+orgCols+` FROM ba_organization`))
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

const memberCols = `id, organization_id, user_id, role, created_at`

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
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO ba_member (`+memberCols+`) VALUES (?, ?, ?, ?, ?)`),
		m.ID, m.OrganizationID, m.UserID, m.Role, toMillis(m.CreatedAt))
	return err
}

func (s *Store) DeleteMember(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM ba_member WHERE id = ?`), id)
	return err
}

func (s *Store) FindMemberByOrgAndUser(ctx context.Context, orgID, userID string) (*types.Member, error) {
	return s.scanMember(s.db.QueryRowContext(ctx, s.q(`SELECT `+memberCols+` FROM ba_member WHERE organization_id = ? AND user_id = ?`), orgID, userID))
}

func (s *Store) listMembers(ctx context.Context, where string, arg string) ([]types.Member, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+memberCols+` FROM ba_member WHERE `+where), arg)
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
	return s.listMembers(ctx, "organization_id = ?", orgID)
}

func (s *Store) ListMembersByUser(ctx context.Context, userID string) ([]types.Member, error) {
	return s.listMembers(ctx, "user_id = ?", userID)
}

// =========================================================================
// Invitation
// =========================================================================

const invitationCols = `id, organization_id, email, role, status, inviter_id, expires_at, created_at`

func (s *Store) scanInvitation(row interface{ Scan(...any) error }) (*types.Invitation, error) {
	var (
		inv       types.Invitation
		expiresAt int64
		createdAt int64
	)
	if err := row.Scan(&inv.ID, &inv.OrganizationID, &inv.Email, &inv.Role, &inv.Status, &inv.InviterID, &expiresAt, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	inv.ExpiresAt = fromMillis(expiresAt)
	inv.CreatedAt = fromMillis(createdAt)
	return &inv, nil
}

func (s *Store) CreateInvitation(ctx context.Context, inv *types.Invitation) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO ba_invitation (`+invitationCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		inv.ID, inv.OrganizationID, inv.Email, inv.Role, inv.Status, inv.InviterID, toMillis(inv.ExpiresAt), toMillis(inv.CreatedAt))
	return err
}

func (s *Store) FindInvitationByID(ctx context.Context, id string) (*types.Invitation, error) {
	return s.scanInvitation(s.db.QueryRowContext(ctx, s.q(`SELECT `+invitationCols+` FROM ba_invitation WHERE id = ?`), id))
}

func (s *Store) UpdateInvitationStatus(ctx context.Context, id, status string) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE ba_invitation SET status = ? WHERE id = ?`), status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

func (s *Store) listInvitations(ctx context.Context, where, arg string) ([]types.Invitation, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+invitationCols+` FROM ba_invitation WHERE `+where), arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Invitation
	for rows.Next() {
		inv, err := s.scanInvitation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *inv)
	}
	return out, rows.Err()
}

func (s *Store) ListInvitationsByOrg(ctx context.Context, orgID string) ([]types.Invitation, error) {
	return s.listInvitations(ctx, "organization_id = ?", orgID)
}

func (s *Store) ListInvitationsByEmail(ctx context.Context, email string) ([]types.Invitation, error) {
	return s.listInvitations(ctx, "LOWER(email) = ?", lowerLike(email))
}

// =========================================================================
// Team
// =========================================================================

const teamCols = `id, name, organization_id, created_at`

func (s *Store) scanTeam(row interface{ Scan(...any) error }) (*types.Team, error) {
	var (
		t         types.Team
		createdAt int64
	)
	if err := row.Scan(&t.ID, &t.Name, &t.OrganizationID, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	t.CreatedAt = fromMillis(createdAt)
	return &t, nil
}

func (s *Store) CreateTeam(ctx context.Context, t *types.Team) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO ba_team (`+teamCols+`) VALUES (?, ?, ?, ?)`),
		t.ID, t.Name, t.OrganizationID, toMillis(t.CreatedAt))
	return err
}

func (s *Store) DeleteTeam(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM ba_team WHERE id = ?`), id)
	if err != nil {
		return err
	}
	_, _ = s.db.ExecContext(ctx, s.q(`DELETE FROM ba_team_member WHERE team_id = ?`), id)
	return nil
}

func (s *Store) FindTeamByID(ctx context.Context, id string) (*types.Team, error) {
	return s.scanTeam(s.db.QueryRowContext(ctx, s.q(`SELECT `+teamCols+` FROM ba_team WHERE id = ?`), id))
}

func (s *Store) ListTeamsByOrg(ctx context.Context, orgID string) ([]types.Team, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+teamCols+` FROM ba_team WHERE organization_id = ?`), orgID)
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
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO ba_team_member (id, team_id, user_id, created_at) VALUES (?, ?, ?, ?)`),
		tm.ID, tm.TeamID, tm.UserID, toMillis(tm.CreatedAt))
	return err
}

func (s *Store) DeleteTeamMember(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM ba_team_member WHERE id = ?`), id)
	return err
}

func (s *Store) ListTeamMembers(ctx context.Context, teamID string) ([]types.TeamMember, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT id, team_id, user_id, created_at FROM ba_team_member WHERE team_id = ?`), teamID)
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
// TwoFactor
// =========================================================================

func (s *Store) CreateTwoFactor(ctx context.Context, rec *types.TwoFactorRecord) error {
	_, _ = s.db.ExecContext(ctx, s.q(`DELETE FROM ba_two_factor WHERE user_id = ?`), rec.UserID)
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO ba_two_factor (id, user_id, secret, backup_codes, verified, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`),
		rec.ID, rec.UserID, rec.Secret, rec.BackupCodes, boolToInt(rec.Verified), toMillis(rec.CreatedAt), toMillis(rec.UpdatedAt))
	return err
}

func (s *Store) FindTwoFactorByUserID(ctx context.Context, userID string) (*types.TwoFactorRecord, error) {
	var (
		rec       types.TwoFactorRecord
		verified  int
		createdAt int64
		updatedAt int64
	)
	row := s.db.QueryRowContext(ctx, s.q(`
		SELECT id, user_id, secret, backup_codes, verified, created_at, updated_at FROM ba_two_factor WHERE user_id = ?`), userID)
	if err := row.Scan(&rec.ID, &rec.UserID, &rec.Secret, &rec.BackupCodes, &verified, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	rec.Verified = verified != 0
	rec.CreatedAt = fromMillis(createdAt)
	rec.UpdatedAt = fromMillis(updatedAt)
	return &rec, nil
}

func (s *Store) UpdateTwoFactor(ctx context.Context, userID string, secret, backupCodes string, verified bool) error {
	res, err := s.db.ExecContext(ctx, s.q(`
		UPDATE ba_two_factor SET secret = ?, backup_codes = ?, verified = ?, updated_at = ? WHERE user_id = ?`),
		secret, backupCodes, boolToInt(verified), toMillis(time.Now()), userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteTwoFactor(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM ba_two_factor WHERE user_id = ?`), userID)
	return err
}

// =========================================================================
// DeviceCode
// =========================================================================

const deviceCols = `id, device_code, user_code, user_id, status, expires_at, poll_interval, client_id, scope, created_at`

func (s *Store) scanDeviceCode(row interface{ Scan(...any) error }) (*types.DeviceCode, error) {
	var (
		dc        types.DeviceCode
		userID    sql.NullString
		clientID  sql.NullString
		scope     sql.NullString
		expiresAt int64
		createdAt int64
	)
	if err := row.Scan(&dc.ID, &dc.DeviceCode, &dc.UserCode, &userID, &dc.Status, &expiresAt, &dc.Interval, &clientID, &scope, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	dc.UserID = userID.String
	dc.ClientID = clientID.String
	dc.Scope = scope.String
	dc.ExpiresAt = fromMillis(expiresAt)
	dc.CreatedAt = fromMillis(createdAt)
	return &dc, nil
}

func (s *Store) CreateDeviceCode(ctx context.Context, dc *types.DeviceCode) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO ba_device_code (`+deviceCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		dc.ID, dc.DeviceCode, dc.UserCode, nullStr(dc.UserID), dc.Status, toMillis(dc.ExpiresAt), dc.Interval,
		nullStr(dc.ClientID), nullStr(dc.Scope), toMillis(dc.CreatedAt))
	return err
}

func (s *Store) FindDeviceCodeByDeviceCode(ctx context.Context, code string) (*types.DeviceCode, error) {
	return s.scanDeviceCode(s.db.QueryRowContext(ctx, s.q(`SELECT `+deviceCols+` FROM ba_device_code WHERE device_code = ?`), code))
}

func (s *Store) FindDeviceCodeByUserCode(ctx context.Context, code string) (*types.DeviceCode, error) {
	return s.scanDeviceCode(s.db.QueryRowContext(ctx, s.q(`SELECT `+deviceCols+` FROM ba_device_code WHERE user_code = ?`), code))
}

func (s *Store) UpdateDeviceCode(ctx context.Context, id string, userID, status string) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE ba_device_code SET user_id = ?, status = ? WHERE id = ?`),
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
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO ba_jwks (id, public_key, private_key, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`),
		rec.ID, rec.PublicKey, nullStr(rec.PrivateKey), toMillis(rec.CreatedAt), nullMillis(rec.ExpiresAt))
	return err
}

func (s *Store) ListJWKS(ctx context.Context) ([]types.JWKSRecord, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT id, public_key, private_key, created_at, expires_at FROM ba_jwks`))
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
		INSERT INTO ba_oauth_app (id, client_id, client_secret, name, redirect_urls, type, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`),
		app.ID, app.ClientID, nullStr(app.ClientSecret), app.Name, app.RedirectURLs, app.Type, toMillis(app.CreatedAt))
	return err
}

func (s *Store) FindOAuthAppByClientID(ctx context.Context, clientID string) (*types.OAuthApplication, error) {
	var (
		app          types.OAuthApplication
		clientSecret sql.NullString
		createdAt    int64
	)
	row := s.db.QueryRowContext(ctx, s.q(`
		SELECT id, client_id, client_secret, name, redirect_urls, type, created_at FROM ba_oauth_app WHERE client_id = ?`), clientID)
	if err := row.Scan(&app.ID, &app.ClientID, &clientSecret, &app.Name, &app.RedirectURLs, &app.Type, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	app.ClientSecret = clientSecret.String
	app.CreatedAt = fromMillis(createdAt)
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
		INSERT INTO ba_wallet (id, user_id, address, chain_id, is_primary, created_at) VALUES (?, ?, ?, ?, ?, ?)`),
		w.ID, w.UserID, w.Address, w.ChainID, boolToInt(w.IsPrimary), toMillis(w.CreatedAt))
	return err
}

func (s *Store) FindWalletByAddress(ctx context.Context, address string, chainID int) (*types.WalletAddress, error) {
	return s.scanWallet(s.db.QueryRowContext(ctx, s.q(`
		SELECT id, user_id, address, chain_id, is_primary, created_at FROM ba_wallet WHERE LOWER(address) = ? AND chain_id = ?`),
		lowerLike(address), chainID))
}

func (s *Store) ListWalletsByUser(ctx context.Context, userID string) ([]types.WalletAddress, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`
		SELECT id, user_id, address, chain_id, is_primary, created_at FROM ba_wallet WHERE user_id = ?`), userID)
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
