package sql

import (
	"context"
	"sort"
	"strings"
)

// Plugin schema group identifiers. These match the plugin IDs reported by
// auth.Plugin.ID(), so a schema can be tailored to exactly the plugins a user
// has enabled — mirroring the Better Auth CLI, which only emits tables for
// configured features.
const (
	pluginOrganization      = "organization"
	pluginOrganizationTeams = "organization-teams"
	pluginOrganizationRoles = "organization-roles"
	pluginTwoFactor         = "two-factor"
	pluginDeviceAuth        = "device-authorization"
	pluginJWT               = "jwt"
	pluginOIDCProvider      = "oidc-provider"
	pluginMCP               = "mcp"
	pluginSIWE              = "siwe"
	pluginAdmin             = "admin"
	pluginAnonymous         = "anonymous"
	pluginUsername          = "username"
	pluginPhoneNumber       = "phone-number"
	pluginLastLogin         = "last-login-method"
)

// coreStatements returns the always-present tables (user, account, session,
// verification) and their indexes. Table and field names mirror Better Auth JS
// defaults; identifiers are quoted because "user" is reserved in some dialects
// and the default fields are camelCase.
func coreStatements(d Dialect, pluginIDs ...string) []string {
	userFields := []string{
		"id TEXT PRIMARY KEY",
		"name TEXT NOT NULL DEFAULT ''",
		"email TEXT NOT NULL",
		d.quoteIdent("emailVerified") + " INTEGER NOT NULL DEFAULT 0",
		"image TEXT",
		"additional TEXT",
		d.quoteIdent("createdAt") + " " + d.timestampType() + " NOT NULL",
		d.quoteIdent("updatedAt") + " " + d.timestampType() + " NOT NULL",
	}
	sessionFields := []string{
		"id TEXT PRIMARY KEY",
		"token TEXT NOT NULL",
		d.quoteIdent("userId") + " TEXT NOT NULL",
		d.quoteIdent("expiresAt") + " " + d.timestampType() + " NOT NULL",
		d.quoteIdent("ipAddress") + " TEXT",
		d.quoteIdent("userAgent") + " TEXT",
		"additional TEXT",
		d.quoteIdent("createdAt") + " " + d.timestampType() + " NOT NULL",
		d.quoteIdent("updatedAt") + " " + d.timestampType() + " NOT NULL",
	}
	for _, id := range pluginIDs {
		switch id {
		case pluginAdmin:
			userFields = append(userFields,
				"role TEXT",
				"banned INTEGER NOT NULL DEFAULT 0",
				d.quoteIdent("banReason")+" TEXT",
				d.quoteIdent("banExpires")+" "+d.timestampType()+"",
			)
			sessionFields = append(sessionFields, d.quoteIdent("impersonatedBy")+" TEXT")
		case pluginAnonymous:
			userFields = append(userFields, d.quoteIdent("isAnonymous")+" INTEGER NOT NULL DEFAULT 0")
		case pluginUsername:
			userFields = append(userFields,
				"username TEXT",
				d.quoteIdent("displayUsername")+" TEXT",
			)
		case pluginPhoneNumber:
			userFields = append(userFields,
				d.quoteIdent("phoneNumber")+" TEXT",
				d.quoteIdent("phoneNumberVerified")+" INTEGER NOT NULL DEFAULT 0",
			)
		case pluginTwoFactor:
			userFields = append(userFields, d.quoteIdent("twoFactorEnabled")+" INTEGER NOT NULL DEFAULT 0")
		case pluginLastLogin:
			userFields = append(userFields, d.quoteIdent("lastLoginMethod")+" TEXT")
		case pluginOrganization:
			sessionFields = append(sessionFields,
				d.quoteIdent("activeOrganizationId")+" TEXT",
			)
		case pluginOrganizationTeams:
			sessionFields = append(sessionFields, d.quoteIdent("activeTeamId")+" TEXT")
		}
	}
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + d.quoteIdent("user") + ` (
			` + strings.Join(userFields, ",\n\t\t\t") + `
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS user_email_idx ON ` + d.quoteIdent("user") + ` (email)`,

		`CREATE TABLE IF NOT EXISTS ` + d.quoteIdent("account") + ` (
			id TEXT PRIMARY KEY,
			` + d.quoteIdent("accountId") + ` TEXT NOT NULL,
			` + d.quoteIdent("providerId") + ` TEXT NOT NULL,
			` + d.quoteIdent("userId") + ` TEXT NOT NULL,
			password TEXT,
			` + d.quoteIdent("accessToken") + ` TEXT,
			` + d.quoteIdent("refreshToken") + ` TEXT,
			` + d.quoteIdent("accessTokenExpiresAt") + ` ` + d.timestampType() + `,
			` + d.quoteIdent("refreshTokenExpiresAt") + ` ` + d.timestampType() + `,
			` + d.quoteIdent("idToken") + ` TEXT,
			scope TEXT,
			` + d.quoteIdent("createdAt") + ` ` + d.timestampType() + ` NOT NULL,
			` + d.quoteIdent("updatedAt") + ` ` + d.timestampType() + ` NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS account_userId_idx ON ` + d.quoteIdent("account") + ` (` + d.quoteIdent("userId") + `)`,
		`CREATE INDEX IF NOT EXISTS account_provider_idx ON ` + d.quoteIdent("account") + ` (` + d.quoteIdent("providerId") + `, ` + d.quoteIdent("accountId") + `)`,

		`CREATE TABLE IF NOT EXISTS ` + d.quoteIdent("session") + ` (
			` + strings.Join(sessionFields, ",\n\t\t\t") + `
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS session_token_idx ON ` + d.quoteIdent("session") + ` (token)`,
		`CREATE INDEX IF NOT EXISTS session_userId_idx ON ` + d.quoteIdent("session") + ` (` + d.quoteIdent("userId") + `)`,

		`CREATE TABLE IF NOT EXISTS ` + d.quoteIdent("verification") + ` (
			id TEXT PRIMARY KEY,
			identifier TEXT NOT NULL,
			value TEXT NOT NULL,
			` + d.quoteIdent("expiresAt") + ` ` + d.timestampType() + ` NOT NULL,
			` + d.quoteIdent("createdAt") + ` ` + d.timestampType() + ` NOT NULL,
			` + d.quoteIdent("updatedAt") + ` ` + d.timestampType() + ` NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS verification_identifier_idx ON ` + d.quoteIdent("verification") + ` (identifier)`,
	}
}

// pluginStatements maps a plugin ID to the extra tables that plugin requires.
// Some plugin IDs contribute only core table columns and have no entries here.
func enabledPluginIDs(pluginIDs []string) map[string]bool {
	out := make(map[string]bool, len(pluginIDs))
	for _, id := range pluginIDs {
		out[id] = true
	}
	return out
}

func invitationStatements(d Dialect, teamSupport bool) []string {
	fields := []string{
		"id TEXT PRIMARY KEY",
		d.quoteIdent("organizationId") + " TEXT NOT NULL",
		"email TEXT NOT NULL",
		"role TEXT NOT NULL DEFAULT ''",
		"status TEXT NOT NULL DEFAULT ''",
		d.quoteIdent("inviterId") + " TEXT NOT NULL DEFAULT ''",
	}
	if teamSupport {
		fields = append(fields, d.quoteIdent("teamId")+" TEXT")
	}
	fields = append(fields,
		d.quoteIdent("expiresAt")+" "+d.timestampType()+" NOT NULL",
		d.quoteIdent("createdAt")+" "+d.timestampType()+" NOT NULL",
	)
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + d.quoteIdent("invitation") + ` (
			` + strings.Join(fields, ",\n\t\t\t\t") + `
			)`,
		`CREATE INDEX IF NOT EXISTS invitation_organizationId_idx ON ` + d.quoteIdent("invitation") + ` (` + d.quoteIdent("organizationId") + `)`,
		`CREATE INDEX IF NOT EXISTS invitation_email_idx ON ` + d.quoteIdent("invitation") + ` (email)`,
	}
}

func pluginStatements(d Dialect, pluginIDs ...string) map[string][]string {
	enabled := enabledPluginIDs(pluginIDs)
	organizationStatements := []string{
		`CREATE TABLE IF NOT EXISTS ` + d.quoteIdent("organization") + ` (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				slug TEXT NOT NULL,
				logo TEXT,
				metadata TEXT,
				` + d.quoteIdent("createdAt") + ` ` + d.timestampType() + ` NOT NULL,
				` + d.quoteIdent("updatedAt") + ` ` + d.timestampType() + `
			)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS organization_slug_idx ON ` + d.quoteIdent("organization") + ` (slug)`,
		`CREATE TABLE IF NOT EXISTS ` + d.quoteIdent("member") + ` (
				id TEXT PRIMARY KEY,
				` + d.quoteIdent("organizationId") + ` TEXT NOT NULL,
				` + d.quoteIdent("userId") + ` TEXT NOT NULL,
				role TEXT NOT NULL DEFAULT '',
				` + d.quoteIdent("createdAt") + ` ` + d.timestampType() + ` NOT NULL
			)`,
		`CREATE INDEX IF NOT EXISTS member_organizationId_idx ON ` + d.quoteIdent("member") + ` (` + d.quoteIdent("organizationId") + `)`,
		`CREATE INDEX IF NOT EXISTS member_userId_idx ON ` + d.quoteIdent("member") + ` (` + d.quoteIdent("userId") + `)`,
	}
	organizationStatements = append(organizationStatements, invitationStatements(d, enabled[pluginOrganizationTeams])...)
	return map[string][]string{
		pluginOrganization: organizationStatements,
		pluginOrganizationTeams: {
			`CREATE TABLE IF NOT EXISTS ` + d.quoteIdent("team") + ` (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				` + d.quoteIdent("organizationId") + ` TEXT NOT NULL,
				` + d.quoteIdent("createdAt") + ` ` + d.timestampType() + ` NOT NULL,
				` + d.quoteIdent("updatedAt") + ` ` + d.timestampType() + `
			)`,
			`CREATE INDEX IF NOT EXISTS team_organizationId_idx ON ` + d.quoteIdent("team") + ` (` + d.quoteIdent("organizationId") + `)`,
			`CREATE TABLE IF NOT EXISTS ` + d.quoteIdent("teamMember") + ` (
				id TEXT PRIMARY KEY,
				` + d.quoteIdent("teamId") + ` TEXT NOT NULL,
				` + d.quoteIdent("userId") + ` TEXT NOT NULL,
				` + d.quoteIdent("createdAt") + ` ` + d.timestampType() + ` NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS teamMember_teamId_idx ON ` + d.quoteIdent("teamMember") + ` (` + d.quoteIdent("teamId") + `)`,
		},
		pluginOrganizationRoles: {
			`CREATE TABLE IF NOT EXISTS ` + d.quoteIdent("organizationRole") + ` (
				id TEXT PRIMARY KEY,
				` + d.quoteIdent("organizationId") + ` TEXT NOT NULL,
				role TEXT NOT NULL,
				permission TEXT NOT NULL,
				` + d.quoteIdent("createdAt") + ` ` + d.timestampType() + ` NOT NULL,
				` + d.quoteIdent("updatedAt") + ` ` + d.timestampType() + `
			)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS organizationRole_organizationId_role_idx ON ` + d.quoteIdent("organizationRole") + ` (` + d.quoteIdent("organizationId") + `, role)`,
			`CREATE INDEX IF NOT EXISTS organizationRole_organizationId_idx ON ` + d.quoteIdent("organizationRole") + ` (` + d.quoteIdent("organizationId") + `)`,
		},
		pluginTwoFactor: {
			`CREATE TABLE IF NOT EXISTS ` + d.quoteIdent("twoFactor") + ` (
				id TEXT PRIMARY KEY,
				` + d.quoteIdent("userId") + ` TEXT NOT NULL,
				secret TEXT NOT NULL DEFAULT '',
				` + d.quoteIdent("backupCodes") + ` TEXT NOT NULL DEFAULT '',
				verified INTEGER NOT NULL DEFAULT 0,
				` + d.quoteIdent("failedVerificationCount") + ` INTEGER NOT NULL DEFAULT 0,
				` + d.quoteIdent("lockedUntil") + ` ` + d.timestampType() + `
			)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS twoFactor_userId_idx ON ` + d.quoteIdent("twoFactor") + ` (` + d.quoteIdent("userId") + `)`,
		},
		pluginDeviceAuth: {
			`CREATE TABLE IF NOT EXISTS ` + d.quoteIdent("deviceCode") + ` (
				id TEXT PRIMARY KEY,
				` + d.quoteIdent("deviceCode") + ` TEXT NOT NULL,
				` + d.quoteIdent("userCode") + ` TEXT NOT NULL,
				` + d.quoteIdent("userId") + ` TEXT,
				status TEXT NOT NULL DEFAULT '',
				` + d.quoteIdent("expiresAt") + ` ` + d.timestampType() + ` NOT NULL,
				` + d.quoteIdent("lastPolledAt") + ` ` + d.timestampType() + `,
				` + d.quoteIdent("pollingInterval") + ` INTEGER NOT NULL DEFAULT 5,
				` + d.quoteIdent("clientId") + ` TEXT,
				scope TEXT
			)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS deviceCode_deviceCode_idx ON ` + d.quoteIdent("deviceCode") + ` (` + d.quoteIdent("deviceCode") + `)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS deviceCode_userCode_idx ON ` + d.quoteIdent("deviceCode") + ` (` + d.quoteIdent("userCode") + `)`,
		},
		pluginJWT: {
			`CREATE TABLE IF NOT EXISTS ` + d.quoteIdent("jwks") + ` (
				id TEXT PRIMARY KEY,
				` + d.quoteIdent("publicKey") + ` TEXT NOT NULL,
				` + d.quoteIdent("privateKey") + ` TEXT,
				` + d.quoteIdent("createdAt") + ` ` + d.timestampType() + ` NOT NULL,
				` + d.quoteIdent("expiresAt") + ` ` + d.timestampType() + `
			)`,
		},
		// oidc-provider and mcp both persist registered OAuth applications.
		pluginOIDCProvider: {oauthAppStatements(d)[0], oauthAppStatements(d)[1]},
		pluginMCP:          {oauthAppStatements(d)[0], oauthAppStatements(d)[1]},
		pluginSIWE: {
			`CREATE TABLE IF NOT EXISTS ` + d.quoteIdent("walletAddress") + ` (
				id TEXT PRIMARY KEY,
				` + d.quoteIdent("userId") + ` TEXT NOT NULL,
				address TEXT NOT NULL,
				` + d.quoteIdent("chainId") + ` INTEGER NOT NULL DEFAULT 0,
				` + d.quoteIdent("isPrimary") + ` INTEGER NOT NULL DEFAULT 0,
				` + d.quoteIdent("createdAt") + ` ` + d.timestampType() + ` NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS walletAddress_userId_idx ON ` + d.quoteIdent("walletAddress") + ` (` + d.quoteIdent("userId") + `)`,
			`CREATE INDEX IF NOT EXISTS walletAddress_address_idx ON ` + d.quoteIdent("walletAddress") + ` (address, ` + d.quoteIdent("chainId") + `)`,
		},
	}
}

func oauthAppStatements(d Dialect) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + d.quoteIdent("oauthApplication") + ` (
			id TEXT PRIMARY KEY,
			` + d.quoteIdent("clientId") + ` TEXT NOT NULL,
			` + d.quoteIdent("clientSecret") + ` TEXT,
			name TEXT NOT NULL DEFAULT '',
			icon TEXT,
			metadata TEXT,
			` + d.quoteIdent("redirectUrls") + ` TEXT NOT NULL DEFAULT '',
			type TEXT NOT NULL DEFAULT '',
			disabled INTEGER NOT NULL DEFAULT 0,
			` + d.quoteIdent("userId") + ` TEXT,
			` + d.quoteIdent("createdAt") + ` ` + d.timestampType() + ` NOT NULL,
			` + d.quoteIdent("updatedAt") + ` ` + d.timestampType() + ` NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS oauthApplication_clientId_idx ON ` + d.quoteIdent("oauthApplication") + ` (` + d.quoteIdent("clientId") + `)`,
	}
}

// AllPluginIDs returns every plugin ID that contributes SQL schema, sorted for
// stable output.
func AllPluginIDs() []string {
	stmts := pluginStatements(SQLite)
	ids := make([]string, 0, len(stmts)+5)
	for id := range stmts {
		ids = append(ids, id)
	}
	ids = append(ids, pluginAdmin, pluginAnonymous, pluginUsername, pluginPhoneNumber, pluginLastLogin)
	sort.Strings(ids)
	return ids
}

// Schema returns the CREATE TABLE / CREATE INDEX statements (without trailing
// semicolons) for the core tables plus the tables required by the given plugin
// IDs. Pass the IDs from auth.Plugin.ID() so the schema matches exactly the
// features that are enabled. With no plugin IDs, only the core schema is
// returned. Duplicate tables (e.g. the OAuth app table shared by oidc-provider
// and mcp) are emitted once.
func Schema(pluginIDs ...string) []string {
	return SchemaForDialect(SQLite, pluginIDs...)
}

// SchemaForDialect returns quoted DDL for the target dialect.
func SchemaForDialect(dialect Dialect, pluginIDs ...string) []string {
	out := coreStatements(dialect, pluginIDs...)
	groups := pluginStatements(dialect, pluginIDs...)
	seen := make(map[string]bool)
	for _, id := range pluginIDs {
		for _, stmt := range groups[id] {
			if seen[stmt] {
				continue
			}
			seen[stmt] = true
			out = append(out, stmt)
		}
	}
	return out
}

// SchemaSQL renders the schema as a single runnable SQL script with each
// statement terminated by a semicolon, scoped to the given plugin IDs. The DDL
// uses only TEXT and integer columns and is identical across Postgres, SQLite, and
// MySQL, so dialect only affects the header comment.
func SchemaSQL(dialect Dialect, pluginIDs ...string) string {
	var b strings.Builder
	b.WriteString("-- Better Auth schema (" + dialect.String() + ")\n")
	if len(pluginIDs) > 0 {
		b.WriteString("-- Plugins: " + strings.Join(pluginIDs, ", ") + "\n")
	}
	b.WriteString("-- Generated by the betterauth CLI. Safe to re-run (IF NOT EXISTS).\n\n")
	for _, stmt := range SchemaForDialect(dialect, pluginIDs...) {
		b.WriteString(formatDDL(stmt))
		b.WriteString(";\n\n")
	}
	return b.String()
}

// formatDDL normalizes the source-indented DDL into clean SQL: the leading
// keyword line is flush-left and indented continuation lines (column defs) get
// a consistent two-space indent.
func formatDDL(stmt string) string {
	lines := strings.Split(strings.TrimSpace(stmt), "\n")
	var b strings.Builder
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if i == 0 {
			b.WriteString(trimmed)
			continue
		}
		b.WriteByte('\n')
		if trimmed == ")" {
			b.WriteString(trimmed)
		} else {
			b.WriteString("  " + trimmed)
		}
	}
	return b.String()
}

// Migrate creates the core tables plus tables for every supported plugin. It is
// safe to call repeatedly (IF NOT EXISTS). To create only the tables your
// enabled plugins need, use MigrateFor.
func (s *Store) Migrate(ctx context.Context) error {
	return s.MigrateFor(ctx, AllPluginIDs()...)
}

// MigrateFor creates the core tables plus the tables required by the given
// plugin IDs (typically derived from auth.Plugin.ID()). This mirrors the Better
// Auth CLI behavior of only provisioning schema for enabled features.
func (s *Store) MigrateFor(ctx context.Context, pluginIDs ...string) error {
	for _, stmt := range SchemaForDialect(s.dialect, pluginIDs...) {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}
