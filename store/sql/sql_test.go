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
	mem, err = st.FindMemberByID(ctx, "m1")
	if err != nil || mem.Role != "owner" {
		t.Fatalf("member by id: %v %+v", err, mem)
	}
	mem, err = st.UpdateMemberRole(ctx, "m1", "admin")
	if err != nil || mem.Role != "admin" {
		t.Fatalf("update member role: %v %+v", err, mem)
	}
	logo := "logo.png"
	metadata := `{"tier":"pro"}`
	org, err := st.UpdateOrganization(ctx, "o1", "Acme Inc", "acme-inc", &logo, &metadata)
	if err != nil || org.Name != "Acme Inc" || org.Slug != "acme-inc" || org.Logo == nil || org.Metadata != metadata {
		t.Fatalf("update org: %v %+v", err, org)
	}
	if org.UpdatedAt == nil {
		t.Fatalf("updated org missing updatedAt")
	}
	must(t, st.CreateTeam(ctx, &types.Team{ID: "t1", Name: "Engineering", OrganizationID: "o1", CreatedAt: now, UpdatedAt: now}))
	team, err := st.UpdateTeam(ctx, "t1", "Platform")
	if err != nil || team.Name != "Platform" {
		t.Fatalf("update team: %v %+v", err, team)
	}
	must(t, st.CreateTeamMember(ctx, &types.TeamMember{ID: "tm1", TeamID: "t1", UserID: "u1", CreatedAt: now}))
	tm, err := st.FindTeamMember(ctx, "t1", "u1")
	if err != nil || tm.ID != "tm1" {
		t.Fatalf("find team member: %v %+v", err, tm)
	}
	teams, err := st.ListTeamsByUser(ctx, "u1")
	if err != nil || len(teams) != 1 || teams[0].ID != "t1" {
		t.Fatalf("list teams by user: %v %+v", err, teams)
	}
	must(t, st.DeleteTeamMemberByTeamAndUser(ctx, "t1", "u1"))
	if _, err := st.FindTeamMember(ctx, "t1", "u1"); !errors.Is(err, berrors.ErrNotFound) {
		t.Fatalf("team member should be deleted: %v", err)
	}
	must(t, st.CreateInvitation(ctx, &types.Invitation{
		ID: "inv1", OrganizationID: "o1", Email: "invite@example.com", Role: "member",
		Status: "pending", InviterID: "u1", TeamID: "t1", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}))
	inv, err := st.FindInvitationByID(ctx, "inv1")
	if err != nil || inv.TeamID != "t1" {
		t.Fatalf("invitation team id: %v %+v", err, inv)
	}
	must(t, st.CreateOrganizationRole(ctx, &types.OrganizationRole{
		ID:             "or1",
		OrganizationID: "o1",
		Role:           "reviewer",
		Permission:     map[string][]string{"organization": []string{"update"}},
		CreatedAt:      now,
	}))
	if err := st.CreateOrganizationRole(ctx, &types.OrganizationRole{
		ID:             "or2",
		OrganizationID: "o1",
		Role:           "reviewer",
		Permission:     map[string][]string{"ac": []string{"read"}},
		CreatedAt:      now,
	}); !errors.Is(err, berrors.ErrAlreadyExists) {
		t.Fatalf("expected organization role conflict, got %v", err)
	}
	orgRole, err := st.FindOrganizationRoleByOrgAndRole(ctx, "o1", "reviewer")
	if err != nil || orgRole.Permission["organization"][0] != "update" {
		t.Fatalf("find organization role: %v %+v", err, orgRole)
	}
	orgRole, err = st.UpdateOrganizationRole(ctx, "or1", "auditor", map[string][]string{"ac": []string{"read"}})
	if err != nil || orgRole.Role != "auditor" || orgRole.UpdatedAt == nil {
		t.Fatalf("update organization role: %v %+v", err, orgRole)
	}
	orgRoles, err := st.ListOrganizationRolesByOrg(ctx, "o1")
	if err != nil || len(orgRoles) != 1 || orgRoles[0].Role != "auditor" {
		t.Fatalf("list organization roles: %v %+v", err, orgRoles)
	}
	must(t, st.DeleteOrganization(ctx, "o1"))
	if _, err := st.FindMemberByOrgAndUser(ctx, "o1", "u1"); !errors.Is(err, berrors.ErrNotFound) {
		t.Fatalf("member should cascade delete: %v", err)
	}
	if _, err := st.FindOrganizationRoleByID(ctx, "or1"); !errors.Is(err, berrors.ErrNotFound) {
		t.Fatalf("organization role should cascade delete: %v", err)
	}
}

func TestExtStoreTwoFactorAndWallet(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	lockedUntil := now.Add(time.Minute)
	must(t, st.CreateTwoFactor(ctx, &types.TwoFactorRecord{
		ID: "tf1", UserID: "u1", Secret: "s", BackupCodes: "a,b",
		Verified: false, FailedVerificationCount: 2, LockedUntil: &lockedUntil,
		CreatedAt: now, UpdatedAt: now,
	}))
	tf, err := st.FindTwoFactorByUserID(ctx, "u1")
	if err != nil || tf.FailedVerificationCount != 2 || tf.LockedUntil == nil {
		t.Fatalf("twofactor JS fields: %v %+v", err, tf)
	}
	must(t, st.UpdateTwoFactor(ctx, "u1", "s2", "c,d", true))
	tf, err = st.FindTwoFactorByUserID(ctx, "u1")
	if err != nil || tf.Secret != "s2" || !tf.Verified {
		t.Fatalf("twofactor: %v %+v", err, tf)
	}
	nextLock := now.Add(2 * time.Minute)
	must(t, st.UpdateTwoFactorLockout(ctx, "u1", 4, &nextLock))
	tf, err = st.FindTwoFactorByUserID(ctx, "u1")
	if err != nil || tf.FailedVerificationCount != 4 || tf.LockedUntil == nil {
		t.Fatalf("twofactor lockout: %v %+v", err, tf)
	}
	must(t, st.UpdateTwoFactorLockout(ctx, "u1", 0, nil))
	tf, err = st.FindTwoFactorByUserID(ctx, "u1")
	if err != nil || tf.FailedVerificationCount != 0 || tf.LockedUntil != nil {
		t.Fatalf("twofactor lockout reset: %v %+v", err, tf)
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
	lastPoll := now.Add(time.Minute)
	must(t, st.CreateDeviceCode(ctx, &types.DeviceCode{
		ID: "d1", DeviceCode: "dev", UserCode: "USER-1", Status: "pending",
		Interval: 5, ExpiresAt: now.Add(time.Hour), LastPolledAt: &lastPoll, CreatedAt: now,
	}))
	dc, err := st.FindDeviceCodeByUserCode(ctx, "USER-1")
	if err != nil || dc.DeviceCode != "dev" || dc.Interval != 5 || dc.LastPolledAt == nil {
		t.Fatalf("device code: %v %+v", err, dc)
	}
	must(t, st.UpdateDeviceCode(ctx, "d1", "u1", "approved"))
	dc, _ = st.FindDeviceCodeByDeviceCode(ctx, "dev")
	if dc.UserID != "u1" || dc.Status != "approved" {
		t.Fatalf("device update: %+v", dc)
	}
}

func TestExtStoreOAuthApplication(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	must(t, st.CreateOAuthApp(ctx, &types.OAuthApplication{
		ID: "app1", ClientID: "client1", ClientSecret: "secret", Name: "App",
		Icon: "https://example.com/icon.png", Metadata: `{"env":"test"}`,
		RedirectURLs: "https://example.com/callback", Type: "web", Disabled: true,
		UserID: "u1", CreatedAt: now, UpdatedAt: now,
	}))
	app, err := st.FindOAuthAppByClientID(ctx, "client1")
	if err != nil {
		t.Fatalf("oauth app: %v", err)
	}
	if app.ID != "app1" || app.Icon == "" || app.Metadata == "" || !app.Disabled || app.UserID != "u1" || app.UpdatedAt.IsZero() {
		t.Fatalf("oauth app JS fields not persisted: %+v", app)
	}
}

func TestSchemaScoping(t *testing.T) {
	core := joinSchema(Schema())
	for _, want := range []string{`"user"`, `"account"`, `"session"`, `"verification"`} {
		if !contains(core, want) {
			t.Fatalf("core schema missing %q", want)
		}
	}
	coreUser := tableStatement(t, Schema(), `"user"`)
	for _, unexpected := range []string{"role", `"twoFactorEnabled"`, `"isAnonymous"`, `"activeOrganizationId"`} {
		if contains(coreUser, unexpected) {
			t.Fatalf("core schema unexpectedly contains plugin field %q", unexpected)
		}
	}
	adminUser := tableStatement(t, Schema("admin"), `"user"`)
	for _, want := range []string{"role", "banned", `"banReason"`, `"banExpires"`} {
		if !contains(adminUser, want) {
			t.Fatalf("admin user schema missing field %q", want)
		}
	}
	adminSession := tableStatement(t, Schema("admin"), `"session"`)
	if !contains(adminSession, `"impersonatedBy"`) {
		t.Fatal("admin session schema missing impersonatedBy")
	}
	userPluginFields := tableStatement(t, Schema("anonymous", "username", "phone-number", "two-factor", "last-login-method"), `"user"`)
	for _, want := range []string{`"isAnonymous"`, "username", `"displayUsername"`, `"phoneNumber"`, `"phoneNumberVerified"`, `"twoFactorEnabled"`, `"lastLoginMethod"`} {
		if !contains(userPluginFields, want) {
			t.Fatalf("user plugin schema missing field %q", want)
		}
	}
	orgSession := tableStatement(t, Schema("organization"), `"session"`)
	for _, want := range []string{`"activeOrganizationId"`} {
		if !contains(orgSession, want) {
			t.Fatalf("organization session schema missing field %q", want)
		}
	}
	if contains(orgSession, `"activeTeamId"`) {
		t.Fatal("organization schema should not include activeTeamId without teams")
	}
	for _, unexpected := range []string{`"organization"`, `"twoFactor"`, `"walletAddress"`, `"jwks"`, `"oauthApplication"`, `"deviceCode"`} {
		if contains(core, unexpected) {
			t.Fatalf("core schema unexpectedly contains %q", unexpected)
		}
	}

	org := joinSchema(Schema("organization"))
	if !contains(org, `"organization"`) || !contains(org, `"member"`) {
		t.Fatal("organization schema missing its tables")
	}
	if contains(org, `CREATE TABLE IF NOT EXISTS "team"`) || contains(org, `CREATE TABLE IF NOT EXISTS "teamMember"`) {
		t.Fatal("organization schema should not include team tables without teams")
	}
	if contains(org, `CREATE TABLE IF NOT EXISTS "organizationRole"`) {
		t.Fatal("organization schema should not include dynamic role table without dynamic access control")
	}
	if contains(org, `"twoFactor"`) || contains(org, `"walletAddress"`) {
		t.Fatal("organization schema should not include unrelated plugin tables")
	}
	orgTable := tableStatement(t, Schema("organization"), `"organization"`)
	if !contains(orgTable, `"updatedAt"`) {
		t.Fatal("organization schema should include Better Auth JS updatedAt field")
	}
	invitationTable := tableStatement(t, Schema("organization"), `"invitation"`)
	if contains(invitationTable, `"teamId"`) {
		t.Fatal("organization invitation schema should not include teamId without teams")
	}
	orgTeamsSession := tableStatement(t, Schema("organization", "organization-teams"), `"session"`)
	if !contains(orgTeamsSession, `"activeTeamId"`) {
		t.Fatal("organization teams schema should include activeTeamId")
	}
	orgTeamsInvitation := tableStatement(t, Schema("organization", "organization-teams"), `"invitation"`)
	if !contains(orgTeamsInvitation, `"teamId"`) {
		t.Fatal("organization teams schema should include invitation teamId")
	}
	teamTable := tableStatement(t, Schema("organization", "organization-teams"), `"team"`)
	if !contains(teamTable, `"updatedAt"`) {
		t.Fatal("team schema should include Better Auth JS updatedAt field")
	}
	roleTable := tableStatement(t, Schema("organization", "organization-roles"), `"organizationRole"`)
	for _, want := range []string{`"organizationId"`, `permission TEXT NOT NULL`, `"createdAt"`, `"updatedAt"`} {
		if !contains(roleTable, want) {
			t.Fatalf("organizationRole schema missing field %q", want)
		}
	}

	twoFactorTable := tableStatement(t, Schema("two-factor"), `"twoFactor"`)
	for _, want := range []string{`"failedVerificationCount"`, `"lockedUntil"`} {
		if !contains(twoFactorTable, want) {
			t.Fatalf("twoFactor schema missing Better Auth JS field %q", want)
		}
	}
	for _, unexpected := range []string{`"createdAt"`, `"updatedAt"`} {
		if contains(twoFactorTable, unexpected) {
			t.Fatalf("twoFactor schema should not contain non-JS field %q", unexpected)
		}
	}

	deviceTable := tableStatement(t, Schema("device-authorization"), `"deviceCode"`)
	if !contains(deviceTable, `"lastPolledAt"`) || !contains(deviceTable, `"pollingInterval"`) {
		t.Fatal("deviceCode schema missing Better Auth JS polling fields")
	}
	if contains(deviceTable, `"createdAt"`) {
		t.Fatal("deviceCode schema should not contain non-JS createdAt field")
	}

	oauthTable := tableStatement(t, Schema("oidc-provider"), `"oauthApplication"`)
	for _, want := range []string{"icon", "metadata", "disabled", `"userId"`, `"updatedAt"`} {
		if !contains(oauthTable, want) {
			t.Fatalf("oauthApplication schema missing Better Auth JS field %q", want)
		}
	}

	// oidc-provider and mcp share the oauth app table; it must appear once.
	shared := joinSchema(Schema("oidc-provider", "mcp"))
	if n := countSubstr(shared, `CREATE TABLE IF NOT EXISTS "oauthApplication"`); n != 1 {
		t.Fatalf("shared oauthApplication should appear once, got %d", n)
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
	if tableExists(t, db, "organization") {
		t.Fatal("core-only MigrateFor should not create organization")
	}
	if !tableExists(t, db, "user") {
		t.Fatal("core-only MigrateFor must create user")
	}
	if err := fs.MigrateFor(context.Background(), "organization"); err != nil {
		t.Fatalf("MigrateFor organization: %v", err)
	}
	if !tableExists(t, db, "organization") {
		t.Fatal("MigrateFor(organization) should create organization")
	}
	if columnExists(t, db, "invitation", "teamId") {
		t.Fatal("MigrateFor(organization) should not create invitation.teamId")
	}
	now := time.Now()
	must(t, fs.CreateInvitation(context.Background(), &types.Invitation{
		ID: "org-inv", OrganizationID: "org1", Email: "invite@example.com", Role: "member",
		Status: "pending", InviterID: "user1", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}))
	inv, err := fs.FindInvitationByID(context.Background(), "org-inv")
	if err != nil || inv.TeamID != "" {
		t.Fatalf("organization-only invitation: %v %+v", err, inv)
	}
	err = fs.CreateInvitation(context.Background(), &types.Invitation{
		ID: "team-inv-missing-schema", OrganizationID: "org1", Email: "team@example.com", Role: "member",
		Status: "pending", InviterID: "user1", TeamID: "team1", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	})
	if err == nil || !strings.Contains(err.Error(), "organization teams schema") {
		t.Fatalf("expected explicit missing team schema error, got %v", err)
	}

	teamDBPath := filepath.Join(t.TempDir(), "team-scoped.db")
	teamDB, err := sql.Open("sqlite", "file:"+teamDBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { teamDB.Close() })
	teamStore := New(teamDB, SQLite)
	if err := teamStore.MigrateFor(context.Background(), "organization", "organization-teams"); err != nil {
		t.Fatalf("MigrateFor organization teams: %v", err)
	}
	if !columnExists(t, teamDB, "invitation", "teamId") {
		t.Fatal("MigrateFor(organization, organization-teams) should create invitation.teamId")
	}
	must(t, teamStore.CreateInvitation(context.Background(), &types.Invitation{
		ID: "team-inv", OrganizationID: "org1", Email: "team@example.com", Role: "member",
		Status: "pending", InviterID: "user1", TeamID: "team1", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}))
	teamInv, err := teamStore.FindInvitationByID(context.Background(), "team-inv")
	if err != nil || teamInv.TeamID != "team1" {
		t.Fatalf("team invitation: %v %+v", err, teamInv)
	}
}

func TestCorePluginFieldsPersistInDedicatedColumns(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	banExpires := now.Add(time.Hour)
	must(t, st.CreateUser(ctx, &types.User{
		ID: "plugin-user", Name: "Plugin", Email: "plugin@example.com",
		CreatedAt: now, UpdatedAt: now,
		Additional: map[string]any{
			"role": "admin", "banned": true, "banReason": "test", "banExpires": banExpires,
			"isAnonymous": true, "username": "plugin", "displayUsername": "Plugin",
			"phoneNumber": "+123", "phoneNumberVerified": true,
			"twoFactorEnabled": true, "lastLoginMethod": "email",
		},
	}))
	user, err := st.FindUserByID(ctx, "plugin-user")
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	for _, key := range []string{"role", "banned", "banReason", "banExpires", "isAnonymous", "username", "displayUsername", "phoneNumber", "phoneNumberVerified", "twoFactorEnabled", "lastLoginMethod"} {
		if _, ok := user.Additional[key]; !ok {
			t.Fatalf("user missing hydrated plugin field %q: %+v", key, user.Additional)
		}
	}
	var role string
	var banned int
	var additional sql.NullString
	err = st.DB().QueryRowContext(ctx, `SELECT role, banned, additional FROM "user" WHERE id = ?`, "plugin-user").Scan(&role, &banned, &additional)
	if err != nil || role != "admin" || banned != 1 {
		t.Fatalf("dedicated user columns not persisted: role=%q banned=%d err=%v", role, banned, err)
	}
	if additional.Valid && strings.Contains(additional.String, "twoFactorEnabled") {
		t.Fatalf("known plugin field should not be duplicated in additional JSON: %s", additional.String)
	}

	expires := now.Add(time.Hour)
	must(t, st.CreateSession(ctx, &types.Session{
		ID: "plugin-session", Token: "plugin-token", UserID: "plugin-user",
		ExpiresAt: expires, CreatedAt: now, UpdatedAt: now,
		Additional: map[string]any{"impersonatedBy": "admin-user", "activeOrganizationId": "org1", "activeTeamId": "team1"},
	}))
	session, _, err := st.FindSessionByToken(ctx, "plugin-token")
	if err != nil {
		t.Fatalf("find session: %v", err)
	}
	for _, key := range []string{"impersonatedBy", "activeOrganizationId", "activeTeamId"} {
		if _, ok := session.Additional[key]; !ok {
			t.Fatalf("session missing hydrated plugin field %q: %+v", key, session.Additional)
		}
	}
	var impersonatedBy string
	err = st.DB().QueryRowContext(ctx, `SELECT "impersonatedBy" FROM "session" WHERE token = ?`, "plugin-token").Scan(&impersonatedBy)
	if err != nil || impersonatedBy != "admin-user" {
		t.Fatalf("dedicated session column not persisted: impersonatedBy=%q err=%v", impersonatedBy, err)
	}
}

func TestFindUserByAdditionalUsesDedicatedColumn(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	must(t, st.CreateUser(ctx, &types.User{
		ID: "lookup-user", Name: "Lookup", Email: "lookup@example.com",
		CreatedAt: now, UpdatedAt: now,
		Additional: map[string]any{
			"username": "lookup",
			"tier":     "pro",
		},
	}))
	var additional sql.NullString
	err := st.DB().QueryRowContext(ctx, `SELECT additional FROM "user" WHERE id = ?`, "lookup-user").Scan(&additional)
	if err != nil {
		t.Fatalf("read additional: %v", err)
	}
	if additional.Valid && strings.Contains(additional.String, "username") {
		t.Fatalf("username should not be duplicated in additional JSON: %s", additional.String)
	}
	user, err := st.FindUserByAdditional(ctx, "username", "lookup")
	if err != nil {
		t.Fatalf("find dedicated username: %v", err)
	}
	if user.ID != "lookup-user" || user.Additional["username"] != "lookup" {
		t.Fatalf("dedicated lookup did not hydrate username: %+v", user)
	}
	custom, err := st.FindUserByAdditional(ctx, "tier", "pro")
	if err != nil {
		t.Fatalf("find custom additional: %v", err)
	}
	if custom.ID != "lookup-user" || custom.Additional["tier"] != "pro" {
		t.Fatalf("custom lookup failed: %+v", custom)
	}
}

func TestUpdateUserClearsDedicatedPhoneNumberColumn(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	must(t, st.CreateUser(ctx, &types.User{
		ID: "phone-user", Name: "Phone", Email: "phone@example.com",
		CreatedAt: now, UpdatedAt: now,
		Additional: map[string]any{
			"phoneNumber":         "+1234567890",
			"phoneNumberVerified": true,
		},
	}))
	updated, err := st.UpdateUser(ctx, "phone-user", store.UserUpdate{
		Additional: map[string]any{
			"phoneNumber":         nil,
			"phoneNumberVerified": false,
		},
	})
	if err != nil {
		t.Fatalf("update user: %v", err)
	}
	if updated.Additional["phoneNumber"] != nil || updated.Additional["phoneNumberVerified"] != false {
		t.Fatalf("returned additional mismatch: %+v", updated.Additional)
	}
	var phone sql.NullString
	var verified int
	err = st.DB().QueryRowContext(ctx, `SELECT "phoneNumber", "phoneNumberVerified" FROM "user" WHERE id = ?`, "phone-user").Scan(&phone, &verified)
	if err != nil {
		t.Fatalf("read phone columns: %v", err)
	}
	if phone.Valid || verified != 0 {
		t.Fatalf("phone columns not cleared: phone=%q valid=%v verified=%d", phone.String, phone.Valid, verified)
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

func columnExists(t *testing.T, db *sql.DB, table string, column string) bool {
	t.Helper()
	rows, err := db.Query(`SELECT * FROM "` + table + `" WHERE 1 = 0`)
	if err != nil {
		t.Fatalf("columnExists(%s, %s): %v", table, column, err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatalf("columnExists(%s, %s): %v", table, column, err)
	}
	for _, name := range columns {
		if name == column {
			return true
		}
	}
	return false
}

func joinSchema(stmts []string) string {
	return strings.Join(stmts, "\n")
}

func tableStatement(t *testing.T, stmts []string, table string) string {
	t.Helper()
	prefix := "CREATE TABLE IF NOT EXISTS " + table
	for _, stmt := range stmts {
		if strings.HasPrefix(strings.TrimSpace(stmt), prefix) {
			return stmt
		}
	}
	t.Fatalf("schema missing table %s", table)
	return ""
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

func countSubstr(haystack, needle string) int { return strings.Count(haystack, needle) }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
