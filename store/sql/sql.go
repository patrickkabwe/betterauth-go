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
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

// Store is a SQL-backed implementation of store.Store and store.ExtStore.
type Store struct {
	db        *sql.DB
	dialect   Dialect
	columnMu  sync.RWMutex
	columnMap map[string]map[string]bool
}

// New creates a SQL store over the given database handle and dialect.
func New(db *sql.DB, dialect Dialect) *Store {
	return &Store{db: db, dialect: dialect, columnMap: make(map[string]map[string]bool)}
}

// DB returns the underlying database handle.
func (s *Store) DB() *sql.DB { return s.db }

// q rebinds ? placeholders for the active dialect.
func (s *Store) q(query string) string { return s.dialect.rebind(query) }

func (s *Store) table(name string) string { return s.dialect.quoteIdent(name) }

func (s *Store) cols(names ...string) string { return s.dialect.quoteIdents(names...) }

func (s *Store) tableColumns(ctx context.Context, table string) (map[string]bool, error) {
	s.columnMu.RLock()
	if cols, ok := s.columnMap[table]; ok {
		s.columnMu.RUnlock()
		return cols, nil
	}
	s.columnMu.RUnlock()

	rows, err := s.db.QueryContext(ctx, s.q(`SELECT * FROM `+s.table(table)+` WHERE 1 = 0`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	cols := make(map[string]bool, len(names))
	for _, name := range names {
		cols[name] = true
	}

	s.columnMu.Lock()
	if s.columnMap == nil {
		s.columnMap = make(map[string]map[string]bool)
	}
	s.columnMap[table] = cols
	s.columnMu.Unlock()
	return cols, nil
}

func (s *Store) columnsPresent(ctx context.Context, table string, optional []string) ([]string, error) {
	cols, err := s.tableColumns(ctx, table)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(optional))
	for _, name := range optional {
		if cols[name] {
			out = append(out, name)
		}
	}
	return out, nil
}

// --- conversion helpers ---

func toMillis(t time.Time) int64 { return t.UnixMilli() }

func fromMillis(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

func nullMillis(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UnixMilli()
}

func nullTimeMillis(t time.Time) any {
	if t.IsZero() {
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

func marshalAdditional(m map[string]any) (any, error) {
	if len(m) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal additional fields: %w", err)
	}
	return string(b), nil
}

func unmarshalAdditional(n sql.NullString) (map[string]any, error) {
	if !n.Valid || n.String == "" {
		return nil, nil
	}
	m := make(map[string]any)
	if err := json.Unmarshal([]byte(n.String), &m); err != nil {
		return nil, fmt.Errorf("unmarshal additional fields: %w", err)
	}
	return m, nil
}

func additionalToDBValue(key string, value any) any {
	if value == nil {
		return nil
	}
	switch key {
	case "banned", "isAnonymous", "phoneNumberVerified", "twoFactorEnabled":
		if v, ok := value.(bool); ok {
			return boolToInt(v)
		}
	case "banExpires":
		switch v := value.(type) {
		case time.Time:
			return toMillis(v)
		case *time.Time:
			return nullMillis(v)
		case int64, int, float64, string:
			return v
		}
	}
	return value
}

func dbValueToAdditional(key string, value any) any {
	switch v := value.(type) {
	case nil:
		return nil
	case int64:
		switch key {
		case "banned", "isAnonymous", "phoneNumberVerified", "twoFactorEnabled":
			return v != 0
		case "banExpires":
			return fromMillis(v)
		}
	case int:
		switch key {
		case "banned", "isAnonymous", "phoneNumberVerified", "twoFactorEnabled":
			return v != 0
		case "banExpires":
			return fromMillis(int64(v))
		}
	case bool:
		return v
	case []byte:
		return string(v)
	}
	return value
}

// =========================================================================
// User
// =========================================================================

func (s *Store) CreateUser(ctx context.Context, user *types.User) error {
	// Enforce unique email to match the in-memory adapter semantics.
	var existing string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id FROM `+s.table("user")+` WHERE email = ?`), user.Email).Scan(&existing)
	if err == nil {
		return berrors.ErrAlreadyExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	cols := append([]string{}, userColNames...)
	args := []any{
		user.ID, user.Name, user.Email, boolToInt(user.EmailVerified), strOrNil(user.Image),
		nil, toMillis(user.CreatedAt), toMillis(user.UpdatedAt),
	}
	additional := copyAdditional(user.Additional)
	extraCols, err := s.columnsPresent(ctx, "user", userAdditionalColNames)
	if err != nil {
		return err
	}
	for _, col := range extraCols {
		if value, ok := additional[col]; ok {
			cols = append(cols, col)
			args = append(args, additionalToDBValue(col, value))
			delete(additional, col)
		}
	}
	additionalValue, err := marshalAdditional(additional)
	if err != nil {
		return err
	}
	args[5] = additionalValue
	placeholders := strings.TrimRight(strings.Repeat("?, ", len(cols)), ", ")
	_, err = s.db.ExecContext(ctx, s.q(`
		INSERT INTO `+s.table("user")+` (`+s.cols(cols...)+`)
		VALUES (`+placeholders+`)`),
		args...)
	return err
}

func copyAdditional(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func strOrNil(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func (s *Store) scanUser(row interface{ Scan(...any) error }, cols []string) (*types.User, error) {
	var (
		u          types.User
		image      sql.NullString
		additional sql.NullString
		verified   int
		createdAt  int64
		updatedAt  int64
	)
	dest := []any{&u.ID, &u.Name, &u.Email, &verified, &image, &additional, &createdAt, &updatedAt}
	extra := make([]any, 0, len(cols)-len(userColNames))
	for range cols[len(userColNames):] {
		var v any
		extra = append(extra, &v)
		dest = append(dest, &v)
	}
	if err := row.Scan(dest...); err != nil {
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
	additionalFields, err := unmarshalAdditional(additional)
	if err != nil {
		return nil, err
	}
	u.Additional = additionalFields
	for i, col := range cols[len(userColNames):] {
		value := *(extra[i].(*any))
		if value != nil {
			if u.Additional == nil {
				u.Additional = make(map[string]any)
			}
			u.Additional[col] = dbValueToAdditional(col, value)
		}
	}
	u.CreatedAt = fromMillis(createdAt)
	u.UpdatedAt = fromMillis(updatedAt)
	return &u, nil
}

var userColNames = []string{"id", "name", "email", "emailVerified", "image", "additional", "createdAt", "updatedAt"}
var userAdditionalColNames = []string{
	"role", "banned", "banReason", "banExpires", "isAnonymous",
	"username", "displayUsername", "phoneNumber", "phoneNumberVerified",
	"twoFactorEnabled", "lastLoginMethod",
}

func (s *Store) userSelectCols(ctx context.Context) ([]string, error) {
	extra, err := s.columnsPresent(ctx, "user", userAdditionalColNames)
	if err != nil {
		return nil, err
	}
	cols := append([]string{}, userColNames...)
	return append(cols, extra...), nil
}

func (s *Store) FindUserByID(ctx context.Context, id string) (*types.User, error) {
	cols, err := s.userSelectCols(ctx)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(cols...)+` FROM `+s.table("user")+` WHERE id = ?`), id)
	return s.scanUser(row, cols)
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (*types.User, error) {
	cols, err := s.userSelectCols(ctx)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(cols...)+` FROM `+s.table("user")+` WHERE email = ?`), email)
	return s.scanUser(row, cols)
}

// FindUserByAdditional uses dedicated Better Auth JS plugin columns when they
// exist, then scans hydrated Additional values for custom fields.
func (s *Store) FindUserByAdditional(ctx context.Context, key string, value any) (*types.User, error) {
	if isKnownUserAdditionalColumn(key) {
		present, err := s.columnsPresent(ctx, "user", []string{key})
		if err != nil {
			return nil, err
		}
		if len(present) > 0 {
			cols, err := s.userSelectCols(ctx)
			if err != nil {
				return nil, err
			}
			row := s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(cols...)+` FROM `+s.table("user")+` WHERE `+s.table(key)+` = ? LIMIT 1`), additionalToDBValue(key, value))
			return s.scanUser(row, cols)
		}
	}
	return s.findUserByAdditionalScan(ctx, key, value)
}

func isKnownUserAdditionalColumn(key string) bool {
	for _, col := range userAdditionalColNames {
		if col == key {
			return true
		}
	}
	return false
}

func (s *Store) findUserByAdditionalScan(ctx context.Context, key string, value any) (*types.User, error) {
	users, err := s.ListUsers(ctx, store.ListUsersOpts{Limit: 10000})
	if err != nil {
		return nil, err
	}
	for _, user := range users {
		if user.Additional != nil {
			if v, ok := user.Additional[key]; ok && reflect.DeepEqual(v, value) {
				cp := user
				return &cp, nil
			}
		}
	}
	return nil, berrors.ErrNotFound
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
	extraCols, err := s.columnsPresent(ctx, "user", userAdditionalColNames)
	if err != nil {
		return nil, err
	}
	sets := []string{"name = ?", "email = ?", s.table("emailVerified") + " = ?", "image = ?", "additional = ?", s.table("updatedAt") + " = ?"}
	args := []any{
		current.Name, current.Email, boolToInt(current.EmailVerified), strOrNil(current.Image),
		nil, toMillis(current.UpdatedAt),
	}
	additional := copyAdditional(current.Additional)
	for _, col := range extraCols {
		if value, ok := additional[col]; ok {
			sets = append(sets, s.table(col)+" = ?")
			args = append(args, additionalToDBValue(col, value))
			delete(additional, col)
		}
	}
	additionalValue, err := marshalAdditional(additional)
	if err != nil {
		return nil, err
	}
	args[4] = additionalValue
	args = append(args, id)
	_, err = s.db.ExecContext(ctx, s.q(`
		UPDATE `+s.table("user")+` SET `+strings.Join(sets, ", ")+`
		WHERE id = ?`), args...)
	if err != nil {
		return nil, err
	}
	current.Additional = mergeKnownAdditional(additional, current.Additional, extraCols)
	return current, nil
}

func mergeKnownAdditional(base map[string]any, source map[string]any, keys []string) map[string]any {
	out := copyAdditional(base)
	for _, key := range keys {
		if value, ok := source[key]; ok {
			if out == nil {
				out = make(map[string]any)
			}
			out[key] = value
		}
	}
	return out
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("account")+` WHERE `+s.table("userId")+` = ?`), id); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("session")+` WHERE `+s.table("userId")+` = ?`), id); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("user")+` WHERE id = ?`), id)
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
	cols, err := s.userSelectCols(ctx)
	if err != nil {
		return nil, err
	}
	query := `SELECT ` + s.cols(cols...) + ` FROM ` + s.table("user")
	args := []any{}
	if opts.Search != "" {
		query += ` WHERE LOWER(email) LIKE ? OR LOWER(name) LIKE ?`
		like := "%" + lowerLike(opts.Search) + "%"
		args = append(args, like, like)
	}
	query += ` ORDER BY ` + s.table("createdAt") + ` ASC LIMIT ? OFFSET ?`
	args = append(args, limit, opts.Offset)
	rows, err := s.db.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []types.User{}
	for rows.Next() {
		u, err := s.scanUser(rows, cols)
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

var accountColNames = []string{
	"id", "accountId", "providerId", "userId", "password", "accessToken", "refreshToken",
	"accessTokenExpiresAt", "refreshTokenExpiresAt", "idToken", "scope", "createdAt", "updatedAt",
}

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
		INSERT INTO `+s.table("account")+` (`+s.cols(accountColNames...)+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		a.ID, a.AccountID, a.ProviderID, a.UserID, nullStr(a.Password), nullStr(a.AccessToken),
		nullStr(a.RefreshToken), nullMillis(a.AccessTokenExpiresAt), nullMillis(a.RefreshTokenExpiresAt),
		nullStr(a.IDToken), nullStr(a.Scope), toMillis(a.CreatedAt), toMillis(a.UpdatedAt))
	return err
}

func (s *Store) UpdateAccount(ctx context.Context, id string, update store.AccountUpdate) (*types.Account, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(accountColNames...)+` FROM `+s.table("account")+` WHERE id = ?`), id)
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
		UPDATE `+s.table("account")+` SET `+s.table("accessToken")+` = ?, `+s.table("refreshToken")+` = ?, `+s.table("accessTokenExpiresAt")+` = ?,
		`+s.table("refreshTokenExpiresAt")+` = ?, `+s.table("idToken")+` = ?, scope = ?, `+s.table("updatedAt")+` = ? WHERE id = ?`),
		nullStr(a.AccessToken), nullStr(a.RefreshToken), nullMillis(a.AccessTokenExpiresAt),
		nullMillis(a.RefreshTokenExpiresAt), nullStr(a.IDToken), nullStr(a.Scope), toMillis(a.UpdatedAt), id)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Store) UpdateAccountPassword(ctx context.Context, userID, providerID, password string) error {
	res, err := s.db.ExecContext(ctx, s.q(`
		UPDATE `+s.table("account")+` SET password = ?, `+s.table("updatedAt")+` = ? WHERE `+s.table("userId")+` = ? AND `+s.table("providerId")+` = ?`),
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
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(accountColNames...)+` FROM `+s.table("account")+` WHERE `+s.table("userId")+` = ? AND `+s.table("providerId")+` = ?`), userID, providerID)
	return s.scanAccount(row)
}

func (s *Store) FindAccountByProviderAndAccountID(ctx context.Context, providerID, accountID string) (*types.Account, error) {
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(accountColNames...)+` FROM `+s.table("account")+` WHERE `+s.table("providerId")+` = ? AND `+s.table("accountId")+` = ?`), providerID, accountID)
	return s.scanAccount(row)
}

func (s *Store) ListAccountsByUserID(ctx context.Context, userID string) ([]types.Account, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+s.cols(accountColNames...)+` FROM `+s.table("account")+` WHERE `+s.table("userId")+` = ?`), userID)
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
	res, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("account")+` WHERE id = ?`), id)
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

var sessionColNames = []string{"id", "token", "userId", "expiresAt", "ipAddress", "userAgent", "additional", "createdAt", "updatedAt"}
var sessionAdditionalColNames = []string{"impersonatedBy", "activeOrganizationId", "activeTeamId"}

func (s *Store) sessionSelectCols(ctx context.Context) ([]string, error) {
	extra, err := s.columnsPresent(ctx, "session", sessionAdditionalColNames)
	if err != nil {
		return nil, err
	}
	cols := append([]string{}, sessionColNames...)
	return append(cols, extra...), nil
}

func (s *Store) scanSession(row interface{ Scan(...any) error }, cols []string) (*types.Session, error) {
	var (
		sess       types.Session
		ip         sql.NullString
		ua         sql.NullString
		additional sql.NullString
		expiresAt  int64
		createdAt  int64
		updatedAt  int64
	)
	dest := []any{&sess.ID, &sess.Token, &sess.UserID, &expiresAt, &ip, &ua, &additional, &createdAt, &updatedAt}
	extra := make([]any, 0, len(cols)-len(sessionColNames))
	for range cols[len(sessionColNames):] {
		var v any
		extra = append(extra, &v)
		dest = append(dest, &v)
	}
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, berrors.ErrNotFound
		}
		return nil, err
	}
	sess.IPAddress = ip.String
	sess.UserAgent = ua.String
	additionalFields, err := unmarshalAdditional(additional)
	if err != nil {
		return nil, err
	}
	sess.Additional = additionalFields
	for i, col := range cols[len(sessionColNames):] {
		value := *(extra[i].(*any))
		if value != nil {
			if sess.Additional == nil {
				sess.Additional = make(map[string]any)
			}
			sess.Additional[col] = dbValueToAdditional(col, value)
		}
	}
	sess.ExpiresAt = fromMillis(expiresAt)
	sess.CreatedAt = fromMillis(createdAt)
	sess.UpdatedAt = fromMillis(updatedAt)
	return &sess, nil
}

func (s *Store) CreateSession(ctx context.Context, sess *types.Session) error {
	cols := append([]string{}, sessionColNames...)
	args := []any{
		sess.ID, sess.Token, sess.UserID, toMillis(sess.ExpiresAt), nullStr(sess.IPAddress),
		nullStr(sess.UserAgent), nil, toMillis(sess.CreatedAt), toMillis(sess.UpdatedAt),
	}
	additional := copyAdditional(sess.Additional)
	extraCols, err := s.columnsPresent(ctx, "session", sessionAdditionalColNames)
	if err != nil {
		return err
	}
	for _, col := range extraCols {
		if value, ok := additional[col]; ok {
			cols = append(cols, col)
			args = append(args, additionalToDBValue(col, value))
			delete(additional, col)
		}
	}
	additionalValue, err := marshalAdditional(additional)
	if err != nil {
		return err
	}
	args[6] = additionalValue
	placeholders := strings.TrimRight(strings.Repeat("?, ", len(cols)), ", ")
	_, err = s.db.ExecContext(ctx, s.q(`
		INSERT INTO `+s.table("session")+` (`+s.cols(cols...)+`)
		VALUES (`+placeholders+`)`),
		args...)
	return err
}

func (s *Store) UpdateSession(ctx context.Context, token string, update store.SessionUpdate) (*types.Session, error) {
	cols, err := s.sessionSelectCols(ctx)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(cols...)+` FROM `+s.table("session")+` WHERE token = ?`), token)
	sess, err := s.scanSession(row, cols)
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
	extraCols, err := s.columnsPresent(ctx, "session", sessionAdditionalColNames)
	if err != nil {
		return nil, err
	}
	sets := []string{s.table("expiresAt") + " = ?", s.table("ipAddress") + " = ?", s.table("userAgent") + " = ?", "additional = ?", s.table("updatedAt") + " = ?"}
	args := []any{toMillis(sess.ExpiresAt), nullStr(sess.IPAddress), nullStr(sess.UserAgent), nil, toMillis(sess.UpdatedAt)}
	additional := copyAdditional(sess.Additional)
	for _, col := range extraCols {
		if value, ok := additional[col]; ok {
			sets = append(sets, s.table(col)+" = ?")
			args = append(args, additionalToDBValue(col, value))
			delete(additional, col)
		}
	}
	additionalValue, err := marshalAdditional(additional)
	if err != nil {
		return nil, err
	}
	args[3] = additionalValue
	args = append(args, token)
	_, err = s.db.ExecContext(ctx, s.q(`
		UPDATE `+s.table("session")+` SET `+strings.Join(sets, ", ")+`
		WHERE token = ?`), args...)
	if err != nil {
		return nil, err
	}
	sess.Additional = mergeKnownAdditional(additional, sess.Additional, extraCols)
	return sess, nil
}

func (s *Store) FindSessionByToken(ctx context.Context, token string) (*types.Session, *types.User, error) {
	cols, err := s.sessionSelectCols(ctx)
	if err != nil {
		return nil, nil, err
	}
	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+s.cols(cols...)+` FROM `+s.table("session")+` WHERE token = ?`), token)
	sess, err := s.scanSession(row, cols)
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
	cols, err := s.sessionSelectCols(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+s.cols(cols...)+` FROM `+s.table("session")+` WHERE `+s.table("userId")+` = ?`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Session
	for rows.Next() {
		sess, err := s.scanSession(rows, cols)
		if err != nil {
			return nil, err
		}
		out = append(out, *sess)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("session")+` WHERE token = ?`), token)
	return err
}

func (s *Store) DeleteSessionsByUserID(ctx context.Context, userID, exceptToken string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("session")+` WHERE `+s.table("userId")+` = ? AND token <> ?`), userID, exceptToken)
	return err
}

func (s *Store) DeleteAllSessionsByUserID(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("session")+` WHERE `+s.table("userId")+` = ?`), userID)
	return err
}

// =========================================================================
// Verification
// =========================================================================

func (s *Store) CreateVerification(ctx context.Context, v *types.Verification) error {
	// Upsert by identifier to match the in-memory adapter (single value per identifier).
	_, _ = s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("verification")+` WHERE identifier = ?`), v.Identifier)
	_, err := s.db.ExecContext(ctx, s.q(`
		INSERT INTO `+s.table("verification")+` (id, identifier, value, `+s.table("expiresAt")+`, `+s.table("createdAt")+`, `+s.table("updatedAt")+`)
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
		SELECT id, identifier, value, `+s.table("expiresAt")+`, `+s.table("createdAt")+`, `+s.table("updatedAt")+` FROM `+s.table("verification")+` WHERE identifier = ?`), identifier)
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
	result, err := s.db.ExecContext(ctx, s.q(`DELETE FROM `+s.table("verification")+` WHERE identifier = ?`), identifier)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return berrors.ErrNotFound
	}
	return nil
}

// compile-time interface checks
var (
	_ store.Store    = (*Store)(nil)
	_ store.ExtStore = (*Store)(nil)
)
