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
	pluginOrganization = "organization"
	pluginTwoFactor    = "two-factor"
	pluginDeviceAuth   = "device-authorization"
	pluginJWT          = "jwt"
	pluginOIDCProvider = "oidc-provider"
	pluginMCP          = "mcp"
	pluginSIWE         = "siwe"
)

// coreStatements returns the always-present tables (user, account, session,
// verification) and their indexes. Every Better Auth deployment needs these.
func coreStatements() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ba_user (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL DEFAULT '',
			email TEXT NOT NULL,
			email_verified INTEGER NOT NULL DEFAULT 0,
			image TEXT,
			additional TEXT,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ba_user_email_idx ON ba_user (email)`,

		`CREATE TABLE IF NOT EXISTS ba_account (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			provider_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			password TEXT,
			access_token TEXT,
			refresh_token TEXT,
			access_token_expires_at INTEGER,
			refresh_token_expires_at INTEGER,
			id_token TEXT,
			scope TEXT,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS ba_account_user_idx ON ba_account (user_id)`,
		`CREATE INDEX IF NOT EXISTS ba_account_provider_idx ON ba_account (provider_id, account_id)`,

		`CREATE TABLE IF NOT EXISTS ba_session (
			id TEXT PRIMARY KEY,
			token TEXT NOT NULL,
			user_id TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			ip_address TEXT,
			user_agent TEXT,
			additional TEXT,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ba_session_token_idx ON ba_session (token)`,
		`CREATE INDEX IF NOT EXISTS ba_session_user_idx ON ba_session (user_id)`,

		`CREATE TABLE IF NOT EXISTS ba_verification (
			id TEXT PRIMARY KEY,
			identifier TEXT NOT NULL,
			value TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ba_verification_identifier_idx ON ba_verification (identifier)`,
	}
}

// pluginStatements maps a plugin ID to the extra tables that plugin requires.
// A plugin not listed here (bearer, username, admin, …) stores its data in the
// core tables' JSON `additional` column and needs no extra tables.
func pluginStatements() map[string][]string {
	return map[string][]string{
		pluginOrganization: {
			`CREATE TABLE IF NOT EXISTS ba_organization (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				slug TEXT NOT NULL,
				logo TEXT,
				metadata TEXT,
				created_at INTEGER NOT NULL
			)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS ba_organization_slug_idx ON ba_organization (slug)`,
			`CREATE TABLE IF NOT EXISTS ba_member (
				id TEXT PRIMARY KEY,
				organization_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				role TEXT NOT NULL DEFAULT '',
				created_at INTEGER NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS ba_member_org_idx ON ba_member (organization_id)`,
			`CREATE INDEX IF NOT EXISTS ba_member_user_idx ON ba_member (user_id)`,
			`CREATE TABLE IF NOT EXISTS ba_invitation (
				id TEXT PRIMARY KEY,
				organization_id TEXT NOT NULL,
				email TEXT NOT NULL,
				role TEXT NOT NULL DEFAULT '',
				status TEXT NOT NULL DEFAULT '',
				inviter_id TEXT NOT NULL DEFAULT '',
				expires_at INTEGER NOT NULL,
				created_at INTEGER NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS ba_invitation_org_idx ON ba_invitation (organization_id)`,
			`CREATE INDEX IF NOT EXISTS ba_invitation_email_idx ON ba_invitation (email)`,
			`CREATE TABLE IF NOT EXISTS ba_team (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				organization_id TEXT NOT NULL,
				created_at INTEGER NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS ba_team_org_idx ON ba_team (organization_id)`,
			`CREATE TABLE IF NOT EXISTS ba_team_member (
				id TEXT PRIMARY KEY,
				team_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				created_at INTEGER NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS ba_team_member_team_idx ON ba_team_member (team_id)`,
		},
		pluginTwoFactor: {
			`CREATE TABLE IF NOT EXISTS ba_two_factor (
				id TEXT PRIMARY KEY,
				user_id TEXT NOT NULL,
				secret TEXT NOT NULL DEFAULT '',
				backup_codes TEXT NOT NULL DEFAULT '',
				verified INTEGER NOT NULL DEFAULT 0,
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL
			)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS ba_two_factor_user_idx ON ba_two_factor (user_id)`,
		},
		pluginDeviceAuth: {
			`CREATE TABLE IF NOT EXISTS ba_device_code (
				id TEXT PRIMARY KEY,
				device_code TEXT NOT NULL,
				user_code TEXT NOT NULL,
				user_id TEXT,
				status TEXT NOT NULL DEFAULT '',
				expires_at INTEGER NOT NULL,
				poll_interval INTEGER NOT NULL DEFAULT 5,
				client_id TEXT,
				scope TEXT,
				created_at INTEGER NOT NULL
			)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS ba_device_code_device_idx ON ba_device_code (device_code)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS ba_device_code_user_idx ON ba_device_code (user_code)`,
		},
		pluginJWT: {
			`CREATE TABLE IF NOT EXISTS ba_jwks (
				id TEXT PRIMARY KEY,
				public_key TEXT NOT NULL,
				private_key TEXT,
				created_at INTEGER NOT NULL,
				expires_at INTEGER
			)`,
		},
		// oidc-provider and mcp both persist registered OAuth applications.
		pluginOIDCProvider: {oauthAppStatements()[0], oauthAppStatements()[1]},
		pluginMCP:          {oauthAppStatements()[0], oauthAppStatements()[1]},
		pluginSIWE: {
			`CREATE TABLE IF NOT EXISTS ba_wallet (
				id TEXT PRIMARY KEY,
				user_id TEXT NOT NULL,
				address TEXT NOT NULL,
				chain_id INTEGER NOT NULL DEFAULT 0,
				is_primary INTEGER NOT NULL DEFAULT 0,
				created_at INTEGER NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS ba_wallet_user_idx ON ba_wallet (user_id)`,
			`CREATE INDEX IF NOT EXISTS ba_wallet_address_idx ON ba_wallet (address, chain_id)`,
		},
	}
}

func oauthAppStatements() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ba_oauth_app (
			id TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			client_secret TEXT,
			name TEXT NOT NULL DEFAULT '',
			redirect_urls TEXT NOT NULL DEFAULT '',
			type TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ba_oauth_app_client_idx ON ba_oauth_app (client_id)`,
	}
}

// AllPluginIDs returns every plugin ID that contributes tables, sorted for
// stable output.
func AllPluginIDs() []string {
	stmts := pluginStatements()
	ids := make([]string, 0, len(stmts))
	for id := range stmts {
		ids = append(ids, id)
	}
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
	out := coreStatements()
	groups := pluginStatements()
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
// uses only TEXT/INTEGER columns and is identical across Postgres, SQLite, and
// MySQL, so dialect only affects the header comment.
func SchemaSQL(dialect Dialect, pluginIDs ...string) string {
	var b strings.Builder
	b.WriteString("-- Better Auth schema (" + dialect.String() + ")\n")
	if len(pluginIDs) > 0 {
		b.WriteString("-- Plugins: " + strings.Join(pluginIDs, ", ") + "\n")
	}
	b.WriteString("-- Generated by the betterauth-go CLI. Safe to re-run (IF NOT EXISTS).\n\n")
	for _, stmt := range Schema(pluginIDs...) {
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
	for _, stmt := range Schema(pluginIDs...) {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}
