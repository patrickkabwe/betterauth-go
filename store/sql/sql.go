// Package sql provides a driver-agnostic SQL implementation of the Better Auth
// store.Store and store.ExtStore interfaces.
//
// It works with any database/sql driver. The caller imports the driver, opens
// the *sql.DB, and passes it together with the matching Dialect:
//
//	import _ "modernc.org/sqlite"
//	db, _ := sql.Open("sqlite", "file:auth.db")
//	st := sqlstore.New(db, sqlstore.SQLite)
//	_ = st.Migrate(context.Background())
//
// All timestamps are stored as INTEGER unix-millisecond values and booleans as
// INTEGER 0/1, keeping the schema portable across Postgres, SQLite, and MySQL.
package sql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

// Store is a SQL-backed implementation of store.Store and store.ExtStore.
type Store struct {
	db      *sql.DB
	dialect Dialect
}

// New creates a SQL store over the given database handle and dialect.
func New(db *sql.DB, dialect Dialect) *Store {
	return &Store{db: db, dialect: dialect}
}

// DB returns the underlying database handle.
func (s *Store) DB() *sql.DB { return s.db }

// q rebinds ? placeholders for the active dialect.
func (s *Store) q(query string) string { return s.dialect.rebind(query) }

// --- conversion helpers ---

func toMillis(t time.Time) int64 { return t.UnixMilli() }

func fromMillis(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

func nullMillis(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UnixMilli()
}

func scanNullMillis(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := fromMillis(n.Int64)
	return &t
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func lowerLike(s string) string { return strings.ToLower(s) }

func marshalAdditional(m map[string]any) any {
	if len(m) == 0 {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return string(b)
}

func unmarshalAdditional(n sql.NullString) map[string]any {
	if !n.Valid || n.String == "" {
		return nil
	}
	m := make(map[string]any)
	if err := json.Unmarshal([]byte(n.String), &m); err != nil {
		return nil
	}
	return m
}

// =========================================================================
// User
// =========================================================================

func (s *Store) CreateUser(ctx context.Context, user *types.User) error {
	// Enforce unique email to match the in-memory adapter semantics.
	var existing string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id FROM ba_user WHERE email = ?`), user.Email).Scan(&existing)
	if err == nil {
		return berrors.ErrAlreadyExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.q(`
		INSERT INTO ba_user (id, name, email, email_verified, image, additional, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		user.ID, user.Name, user.Email, boolToInt(user.EmailVerified), strOrNil(user.Image),
		marshalAdditional(user.Additional), toMillis(user.CreatedAt), toMillis(user.UpdatedAt))
	return err
}

func strOrNil(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func (s *Store) scanUser(row interface{ Scan(...any) error }) (*types.User, error) {
	var (
		u          types.User
		image      sql.NullString
		additional sql.NullString
		verified   int
		createdAt  int64
		updatedAt  int64
	)
	if err := row.Scan(&u.ID, &u.Name, &u.Email, &verified, &image, &additional, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	u.EmailVerified = verified != 0
	if image.Valid {
		v := image.String
		u.Image = &v
	}
	u.Additional = unmarshalAdditional(additional)
	u.CreatedAt = fromMillis(createdAt)
	u.UpdatedAt = fromMillis(updatedAt)
	return &u, nil
}

const userCols = `id, name, email, email_verified, image, additional, created_at, updated_at`

func (s *Store) FindUserByID(ctx context.Context, id string) (*types.User, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+userCols+` FROM ba_user WHERE id = ?`), id)
	return s.scanUser(row)
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (*types.User, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+userCols+` FROM ba_user WHERE email = ?`), email)
	return s.scanUser(row)
}

func (s *Store) UpdateUser(ctx context.Context, id string, update store.UserUpdate) (*types.User, error) {
	current, err := s.FindUserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if update.Name != nil {
		current.Name = *update.Name
	}
	if update.Email != nil {
		current.Email = *update.Email
	}
	if update.EmailVerified != nil {
		current.EmailVerified = *update.EmailVerified
	}
	if update.Image != nil {
		current.Image = *update.Image
	}
	if len(update.Additional) > 0 {
		if current.Additional == nil {
			current.Additional = make(map[string]any)
		}
		for k, v := range update.Additional {
			current.Additional[k] = v
		}
	}
	current.UpdatedAt = time.Now()
	_, err = s.db.ExecContext(ctx, s.q(`
		UPDATE ba_user SET name = ?, email = ?, email_verified = ?, image = ?, additional = ?, updated_at = ?
		WHERE id = ?`),
		current.Name, current.Email, boolToInt(current.EmailVerified), strOrNil(current.Image),
		marshalAdditional(current.Additional), toMillis(current.UpdatedAt), id)
	if err != nil {
		return nil, err
	}
	return current, nil
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, s.q(`DELETE FROM ba_account WHERE user_id = ?`), id); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, s.q(`DELETE FROM ba_session WHERE user_id = ?`), id); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM ba_user WHERE id = ?`), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

func (s *Store) ListUsers(ctx context.Context, opts store.ListUsersOpts) ([]types.User, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT ` + userCols + ` FROM ba_user`
	args := []any{}
	if opts.Search != "" {
		query += ` WHERE LOWER(email) LIKE ? OR LOWER(name) LIKE ?`
		like := "%" + lowerLike(opts.Search) + "%"
		args = append(args, like, like)
	}
	query += ` ORDER BY created_at ASC LIMIT ? OFFSET ?`
	args = append(args, limit, opts.Offset)
	rows, err := s.db.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []types.User{}
	for rows.Next() {
		u, err := s.scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// =========================================================================
// Account
// =========================================================================

const accountCols = `id, account_id, provider_id, user_id, password, access_token, refresh_token,
	access_token_expires_at, refresh_token_expires_at, id_token, scope, created_at, updated_at`

func (s *Store) scanAccount(row interface{ Scan(...any) error }) (*types.Account, error) {
	var (
		a            types.Account
		password     sql.NullString
		accessToken  sql.NullString
		refreshToken sql.NullString
		atExpires    sql.NullInt64
		rtExpires    sql.NullInt64
		idToken      sql.NullString
		scope        sql.NullString
		createdAt    int64
		updatedAt    int64
	)
	if err := row.Scan(&a.ID, &a.AccountID, &a.ProviderID, &a.UserID, &password, &accessToken,
		&refreshToken, &atExpires, &rtExpires, &idToken, &scope, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	a.Password = password.String
	a.AccessToken = accessToken.String
	a.RefreshToken = refreshToken.String
	a.AccessTokenExpiresAt = scanNullMillis(atExpires)
	a.RefreshTokenExpiresAt = scanNullMillis(rtExpires)
	a.IDToken = idToken.String
	a.Scope = scope.String
	a.CreatedAt = fromMillis(createdAt)
	a.UpdatedAt = fromMillis(updatedAt)
	return &a, nil
}

func (s *Store) CreateAccount(ctx context.Context, a *types.Account) error {
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO ba_account (`+accountCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		a.ID, a.AccountID, a.ProviderID, a.UserID, nullStr(a.Password), nullStr(a.AccessToken),
		nullStr(a.RefreshToken), nullMillis(a.AccessTokenExpiresAt), nullMillis(a.RefreshTokenExpiresAt),
		nullStr(a.IDToken), nullStr(a.Scope), toMillis(a.CreatedAt), toMillis(a.UpdatedAt))
	return err
}

func (s *Store) UpdateAccount(ctx context.Context, id string, update store.AccountUpdate) (*types.Account, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+accountCols+` FROM ba_account WHERE id = ?`), id)
	a, err := s.scanAccount(row)
	if err != nil {
		return nil, err
	}
	if update.AccessToken != nil {
		a.AccessToken = *update.AccessToken
	}
	if update.RefreshToken != nil {
		a.RefreshToken = *update.RefreshToken
	}
	if update.AccessTokenExpiresAt != nil {
		a.AccessTokenExpiresAt = update.AccessTokenExpiresAt
	}
	if update.RefreshTokenExpiresAt != nil {
		a.RefreshTokenExpiresAt = update.RefreshTokenExpiresAt
	}
	if update.IDToken != nil {
		a.IDToken = *update.IDToken
	}
	if update.Scope != nil {
		a.Scope = *update.Scope
	}
	a.UpdatedAt = time.Now()
	_, err = s.db.ExecContext(ctx, s.q(`
		UPDATE ba_account SET access_token = ?, refresh_token = ?, access_token_expires_at = ?,
		refresh_token_expires_at = ?, id_token = ?, scope = ?, updated_at = ? WHERE id = ?`),
		nullStr(a.AccessToken), nullStr(a.RefreshToken), nullMillis(a.AccessTokenExpiresAt),
		nullMillis(a.RefreshTokenExpiresAt), nullStr(a.IDToken), nullStr(a.Scope), toMillis(a.UpdatedAt), id)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Store) UpdateAccountPassword(ctx context.Context, userID, providerID, password string) error {
	res, err := s.db.ExecContext(ctx, s.q(`
		UPDATE ba_account SET password = ?, updated_at = ? WHERE user_id = ? AND provider_id = ?`),
		password, toMillis(time.Now()), userID, providerID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

func (s *Store) FindAccountByUserAndProvider(ctx context.Context, userID, providerID string) (*types.Account, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+accountCols+` FROM ba_account WHERE user_id = ? AND provider_id = ?`), userID, providerID)
	return s.scanAccount(row)
}

func (s *Store) FindAccountByProviderAndAccountID(ctx context.Context, providerID, accountID string) (*types.Account, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+accountCols+` FROM ba_account WHERE provider_id = ? AND account_id = ?`), providerID, accountID)
	return s.scanAccount(row)
}

func (s *Store) ListAccountsByUserID(ctx context.Context, userID string) ([]types.Account, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+accountCols+` FROM ba_account WHERE user_id = ?`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Account
	for rows.Next() {
		a, err := s.scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM ba_account WHERE id = ?`), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

// =========================================================================
// Session
// =========================================================================

const sessionCols = `id, token, user_id, expires_at, ip_address, user_agent, additional, created_at, updated_at`

func (s *Store) scanSession(row interface{ Scan(...any) error }) (*types.Session, error) {
	var (
		sess       types.Session
		ip         sql.NullString
		ua         sql.NullString
		additional sql.NullString
		expiresAt  int64
		createdAt  int64
		updatedAt  int64
	)
	if err := row.Scan(&sess.ID, &sess.Token, &sess.UserID, &expiresAt, &ip, &ua, &additional, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	sess.IPAddress = ip.String
	sess.UserAgent = ua.String
	sess.Additional = unmarshalAdditional(additional)
	sess.ExpiresAt = fromMillis(expiresAt)
	sess.CreatedAt = fromMillis(createdAt)
	sess.UpdatedAt = fromMillis(updatedAt)
	return &sess, nil
}

func (s *Store) CreateSession(ctx context.Context, sess *types.Session) error {
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO ba_session (`+sessionCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		sess.ID, sess.Token, sess.UserID, toMillis(sess.ExpiresAt), nullStr(sess.IPAddress),
		nullStr(sess.UserAgent), marshalAdditional(sess.Additional), toMillis(sess.CreatedAt), toMillis(sess.UpdatedAt))
	return err
}

func (s *Store) UpdateSession(ctx context.Context, token string, update store.SessionUpdate) (*types.Session, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+sessionCols+` FROM ba_session WHERE token = ?`), token)
	sess, err := s.scanSession(row)
	if err != nil {
		return nil, err
	}
	if update.ExpiresAt != nil {
		sess.ExpiresAt = *update.ExpiresAt
	}
	if update.UpdatedAt != nil {
		sess.UpdatedAt = *update.UpdatedAt
	}
	if update.IPAddress != nil {
		sess.IPAddress = *update.IPAddress
	}
	if update.UserAgent != nil {
		sess.UserAgent = *update.UserAgent
	}
	if len(update.Additional) > 0 {
		if sess.Additional == nil {
			sess.Additional = make(map[string]any)
		}
		for k, v := range update.Additional {
			sess.Additional[k] = v
		}
	}
	_, err = s.db.ExecContext(ctx, s.q(`
		UPDATE ba_session SET expires_at = ?, ip_address = ?, user_agent = ?, additional = ?, updated_at = ?
		WHERE token = ?`),
		toMillis(sess.ExpiresAt), nullStr(sess.IPAddress), nullStr(sess.UserAgent),
		marshalAdditional(sess.Additional), toMillis(sess.UpdatedAt), token)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *Store) FindSessionByToken(ctx context.Context, token string) (*types.Session, *types.User, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+sessionCols+` FROM ba_session WHERE token = ?`), token)
	sess, err := s.scanSession(row)
	if err != nil {
		return nil, nil, err
	}
	user, err := s.FindUserByID(ctx, sess.UserID)
	if err != nil {
		return nil, nil, err
	}
	return sess, user, nil
}

func (s *Store) ListSessionsByUserID(ctx context.Context, userID string) ([]types.Session, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+sessionCols+` FROM ba_session WHERE user_id = ?`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Session
	for rows.Next() {
		sess, err := s.scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sess)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM ba_session WHERE token = ?`), token)
	return err
}

func (s *Store) DeleteSessionsByUserID(ctx context.Context, userID, exceptToken string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM ba_session WHERE user_id = ? AND token <> ?`), userID, exceptToken)
	return err
}

func (s *Store) DeleteAllSessionsByUserID(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM ba_session WHERE user_id = ?`), userID)
	return err
}

// =========================================================================
// Verification
// =========================================================================

func (s *Store) CreateVerification(ctx context.Context, v *types.Verification) error {
	// Upsert by identifier to match the in-memory adapter (single value per identifier).
	_, _ = s.db.ExecContext(ctx, s.q(`DELETE FROM ba_verification WHERE identifier = ?`), v.Identifier)
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO ba_verification (id, identifier, value, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`),
		v.ID, v.Identifier, v.Value, toMillis(v.ExpiresAt), toMillis(v.CreatedAt), toMillis(v.UpdatedAt))
	return err
}

func (s *Store) FindVerificationByIdentifier(ctx context.Context, identifier string) (*types.Verification, error) {
	var (
		v         types.Verification
		expiresAt int64
		createdAt int64
		updatedAt int64
	)
	row := s.db.QueryRowContext(ctx, s.q(`
		SELECT id, identifier, value, expires_at, created_at, updated_at FROM ba_verification WHERE identifier = ?`), identifier)
	if err := row.Scan(&v.ID, &v.Identifier, &v.Value, &expiresAt, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	v.ExpiresAt = fromMillis(expiresAt)
	v.CreatedAt = fromMillis(createdAt)
	v.UpdatedAt = fromMillis(updatedAt)
	return &v, nil
}

func (s *Store) DeleteVerificationByIdentifier(ctx context.Context, identifier string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM ba_verification WHERE identifier = ?`), identifier)
	return err
}

// compile-time interface checks
var (
	_ store.Store    = (*Store)(nil)
	_ store.ExtStore = (*Store)(nil)
)
