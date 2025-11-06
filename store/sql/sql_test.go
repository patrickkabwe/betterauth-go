package sql

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"

	_ "modernc.org/sqlite"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	st := New(db, SQLite)
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

func TestRebindPostgres(t *testing.T) {
	got := Postgres.rebind(`SELECT * FROM t WHERE a = ? AND b = ?`)
	want := `SELECT * FROM t WHERE a = $1 AND b = $2`
	if got != want {
		t.Fatalf("rebind = %q, want %q", got, want)
	}
	if SQLite.rebind(`a = ?`) != `a = ?` {
		t.Fatal("sqlite rebind should be unchanged")
	}
}

func TestUserCRUD(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	img := "https://example.com/a.png"
	u := &types.User{
		ID: "u1", Name: "Alice", Email: "alice@example.com", EmailVerified: true,
		Image: &img, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		Additional: map[string]any{"role": "admin"},
	}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	// duplicate email rejected
	if err := st.CreateUser(ctx, &types.User{ID: "u2", Email: "alice@example.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}); !errors.Is(err, berrors.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
	got, err := st.FindUserByID(ctx, "u1")
	if err != nil {
		t.Fatalf("find by id: %v", err)
	}
	if got.Name != "Alice" || !got.EmailVerified || got.Image == nil || *got.Image != img {
		t.Fatalf("unexpected user: %+v", got)
	}
	if got.Additional["role"] != "admin" {
		t.Fatalf("additional not persisted: %+v", got.Additional)
	}
	byEmail, err := st.FindUserByEmail(ctx, "alice@example.com")
	if err != nil || byEmail.ID != "u1" {
		t.Fatalf("find by email: %v %+v", err, byEmail)
	}
	newName := "Alice B"
	updated, err := st.UpdateUser(ctx, "u1", store.UserUpdate{Name: &newName, Additional: map[string]any{"tier": "pro"}})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "Alice B" || updated.Additional["tier"] != "pro" || updated.Additional["role"] != "admin" {
		t.Fatalf("update merge failed: %+v", updated)
	}
	if err := st.DeleteUser(ctx, "u1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.FindUserByID(ctx, "u1"); !errors.Is(err, berrors.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestSessionAndAccount(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	must(t, st.CreateUser(ctx, &types.User{ID: "u1", Email: "a@b.com", CreatedAt: now, UpdatedAt: now}))

	exp := now.Add(time.Hour)
	acc := &types.Account{ID: "acc1", AccountID: "u1", ProviderID: "credential", UserID: "u1",
		Password: "hash", AccessToken: "at", AccessTokenExpiresAt: &exp, Scope: "read", CreatedAt: now, UpdatedAt: now}
	must(t, st.CreateAccount(ctx, acc))
	gotAcc, err := st.FindAccountByUserAndProvider(ctx, "u1", "credential")
	if err != nil || gotAcc.Password != "hash" || gotAcc.AccessTokenExpiresAt == nil {
		t.Fatalf("account: %v %+v", err, gotAcc)
	}
	must(t, st.UpdateAccountPassword(ctx, "u1", "credential", "newhash"))
	gotAcc, _ = st.FindAccountByUserAndProvider(ctx, "u1", "credential")
	if gotAcc.Password != "newhash" {
		t.Fatalf("password update failed: %s", gotAcc.Password)
	}

	sess := &types.Session{ID: "s1", Token: "tok1", UserID: "u1", ExpiresAt: exp,
		IPAddress: "1.2.3.4", UserAgent: "go-test", CreatedAt: now, UpdatedAt: now}
	must(t, st.CreateSession(ctx, sess))
	gotSess, gotUser, err := st.FindSessionByToken(ctx, "tok1")
	if err != nil || gotUser.ID != "u1" || gotSess.IPAddress != "1.2.3.4" {
		t.Fatalf("session lookup: %v %+v %+v", err, gotSess, gotUser)
	}
	newExp := now.Add(48 * time.Hour)
	if _, err := st.UpdateSession(ctx, "tok1", store.SessionUpdate{ExpiresAt: &newExp, Additional: map[string]any{"impersonated": true}}); err != nil {
		t.Fatalf("update session: %v", err)
	}
	gotSess, _, _ = st.FindSessionByToken(ctx, "tok1")
	if gotSess.Additional["impersonated"] != true {
		t.Fatalf("session additional not persisted: %+v", gotSess.Additional)
	}
	// second session, revoke others
	must(t, st.CreateSession(ctx, &types.Session{ID: "s2", Token: "tok2", UserID: "u1", ExpiresAt: exp, CreatedAt: now, UpdatedAt: now}))
	must(t, st.DeleteSessionsByUserID(ctx, "u1", "tok1"))
	list, _ := st.ListSessionsByUserID(ctx, "u1")
	if len(list) != 1 || list[0].Token != "tok1" {
		t.Fatalf("expected only tok1 after revoke-others, got %+v", list)
	}
	// cascade on user delete
	must(t, st.DeleteUser(ctx, "u1"))
	if _, _, err := st.FindSessionByToken(ctx, "tok1"); !errors.Is(err, berrors.ErrNotFound) {
		t.Fatalf("session should be gone after user delete: %v", err)
	}
}

func TestVerification(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	must(t, st.CreateVerification(ctx, &types.Verification{ID: "v1", Identifier: "reset:a@b.com", Value: "token1", ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now}))
	// upsert by identifier
	must(t, st.CreateVerification(ctx, &types.Verification{ID: "v2", Identifier: "reset:a@b.com", Value: "token2", ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now}))
	v, err := st.FindVerificationByIdentifier(ctx, "reset:a@b.com")
	if err != nil || v.Value != "token2" {
		t.Fatalf("verification upsert: %v %+v", err, v)
	}
	must(t, st.DeleteVerificationByIdentifier(ctx, "reset:a@b.com"))
	if _, err := st.FindVerificationByIdentifier(ctx, "reset:a@b.com"); !errors.Is(err, berrors.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestListUsers(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	for _, e := range []string{"alice@x.com", "bob@x.com", "carol@y.com"} {
		must(t, st.CreateUser(ctx, &types.User{ID: e, Name: e, Email: e, CreatedAt: now, UpdatedAt: now}))
		now = now.Add(time.Millisecond)
	}
	all, err := st.ListUsers(ctx, store.ListUsersOpts{})
	if err != nil || len(all) != 3 {
		t.Fatalf("list all: %v len=%d", err, len(all))
	}
	filtered, _ := st.ListUsers(ctx, store.ListUsersOpts{Search: "x.com"})
	if len(filtered) != 2 {
		t.Fatalf("search x.com expected 2, got %d", len(filtered))
	}
	paged, _ := st.ListUsers(ctx, store.ListUsersOpts{Limit: 1, Offset: 1})
	if len(paged) != 1 {
		t.Fatalf("paged expected 1, got %d", len(paged))
	}
}

func TestExtStoreOrganization(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	must(t, st.CreateOrganization(ctx, &types.Organization{ID: "o1", Name: "Acme", Slug: "acme", CreatedAt: now}))
	if err := st.CreateOrganization(ctx, &types.Organization{ID: "o2", Name: "Acme2", Slug: "acme", CreatedAt: now}); !errors.Is(err, berrors.ErrAlreadyExists) {
		t.Fatalf("expected slug conflict, got %v", err)
	}
	must(t, st.CreateMember(ctx, &types.Member{ID: "m1", OrganizationID: "o1", UserID: "u1", Role: "owner", CreatedAt: now}))
	mem, err := st.FindMemberByOrgAndUser(ctx, "o1", "u1")
	if err != nil || mem.Role != "owner" {
		t.Fatalf("member: %v %+v", err, mem)
	}
	logo := "logo.png"
	org, err := st.UpdateOrganization(ctx, "o1", "Acme Inc", "acme-inc", &logo)
	if err != nil || org.Name != "Acme Inc" || org.Slug != "acme-inc" || org.Logo == nil {
		t.Fatalf("update org: %v %+v", err, org)
	}
	must(t, st.DeleteOrganization(ctx, "o1"))
	if _, err := st.FindMemberByOrgAndUser(ctx, "o1", "u1"); !errors.Is(err, berrors.ErrNotFound) {
		t.Fatalf("member should cascade delete: %v", err)
	}
}

func TestExtStoreTwoFactorAndWallet(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	must(t, st.CreateTwoFactor(ctx, &types.TwoFactorRecord{ID: "tf1", UserID: "u1", Secret: "s", BackupCodes: "a,b", CreatedAt: now, UpdatedAt: now}))
	must(t, st.UpdateTwoFactor(ctx, "u1", "s2", "c,d", true))
	tf, err := st.FindTwoFactorByUserID(ctx, "u1")
	if err != nil || tf.Secret != "s2" || !tf.Verified {
		t.Fatalf("twofactor: %v %+v", err, tf)
	}

	must(t, st.CreateWallet(ctx, &types.WalletAddress{ID: "w1", UserID: "u1", Address: "0xABC", ChainID: 1, IsPrimary: true, CreatedAt: now}))
	w, err := st.FindWalletByAddress(ctx, "0xabc", 1) // case-insensitive
	if err != nil || w.UserID != "u1" || !w.IsPrimary {
		t.Fatalf("wallet: %v %+v", err, w)
	}
	wallets, _ := st.ListWalletsByUser(ctx, "u1")
	if len(wallets) != 1 {
		t.Fatalf("expected 1 wallet, got %d", len(wallets))
	}
}

func TestExtStoreDeviceCode(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	must(t, st.CreateDeviceCode(ctx, &types.DeviceCode{ID: "d1", DeviceCode: "dev", UserCode: "USER-1", Status: "pending", Interval: 5, ExpiresAt: now.Add(time.Hour), CreatedAt: now}))
	dc, err := st.FindDeviceCodeByUserCode(ctx, "USER-1")
	if err != nil || dc.DeviceCode != "dev" || dc.Interval != 5 {
		t.Fatalf("device code: %v %+v", err, dc)
	}
	must(t, st.UpdateDeviceCode(ctx, "d1", "u1", "approved"))
	dc, _ = st.FindDeviceCodeByDeviceCode(ctx, "dev")
	if dc.UserID != "u1" || dc.Status != "approved" {
		t.Fatalf("device update: %+v", dc)
	}
}

func TestSchemaScoping(t *testing.T) {
	core := joinSchema(Schema())
	for _, want := range []string{"ba_user", "ba_account", "ba_session", "ba_verification"} {
		if !contains(core, want) {
			t.Fatalf("core schema missing %q", want)
		}
	}
	for _, unexpected := range []string{"ba_organization", "ba_two_factor", "ba_wallet", "ba_jwks", "ba_oauth_app", "ba_device_code"} {
		if contains(core, unexpected) {
			t.Fatalf("core schema unexpectedly contains %q", unexpected)
		}
	}

	org := joinSchema(Schema("organization"))
	if !contains(org, "ba_organization") || !contains(org, "ba_member") || !contains(org, "ba_team") {
		t.Fatal("organization schema missing its tables")
	}
	if contains(org, "ba_two_factor") || contains(org, "ba_wallet") {
		t.Fatal("organization schema should not include unrelated plugin tables")
	}

	// oidc-provider and mcp share the oauth app table; it must appear once.
	shared := joinSchema(Schema("oidc-provider", "mcp"))
	if n := countSubstr(shared, "CREATE TABLE IF NOT EXISTS ba_oauth_app"); n != 1 {
		t.Fatalf("shared ba_oauth_app should appear once, got %d", n)
	}

	// MigrateFor should only create the requested tables. Use a fresh DB so the
	// full Migrate from newTestStore does not interfere.
	dbPath := filepath.Join(t.TempDir(), "scoped.db")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fs := New(db, SQLite)
	if err := fs.MigrateFor(context.Background()); err != nil {
		t.Fatalf("MigrateFor core: %v", err)
	}
	if tableExists(t, db, "ba_organization") {
		t.Fatal("core-only MigrateFor should not create ba_organization")
	}
	if !tableExists(t, db, "ba_user") {
		t.Fatal("core-only MigrateFor must create ba_user")
	}
	if err := fs.MigrateFor(context.Background(), "organization"); err != nil {
		t.Fatalf("MigrateFor organization: %v", err)
	}
	if !tableExists(t, db, "ba_organization") {
		t.Fatal("MigrateFor(organization) should create ba_organization")
	}
}

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var found string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		t.Fatalf("tableExists(%s): %v", name, err)
	}
	return found == name
}

func joinSchema(stmts []string) string {
	return strings.Join(stmts, "\n")
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

func countSubstr(haystack, needle string) int { return strings.Count(haystack, needle) }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
