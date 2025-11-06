package core_test

import (
	"bytes"
	"context"
	databasesql "database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/cli/core"
	"github.com/patrickkabwe/betterauth-go/plugins"
	"github.com/patrickkabwe/betterauth-go/store/memory"
	sqlstore "github.com/patrickkabwe/betterauth-go/store/sql"

	_ "modernc.org/sqlite"
)

func run(t *testing.T, args []string, opts core.Options) (string, string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	opts.Stdout = &out
	opts.Stderr = &errb
	if opts.Stdin == nil {
		opts.Stdin = strings.NewReader("")
	}
	err := core.Run(args, opts)
	return out.String(), errb.String(), err
}

func TestSecret(t *testing.T) {
	out, _, err := run(t, []string{"secret"}, core.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "BETTER_AUTH_SECRET=") {
		t.Fatalf("secret output missing env line: %q", out)
	}
	// Extract the value and assert it is non-trivial.
	idx := strings.Index(out, "BETTER_AUTH_SECRET=")
	val := strings.TrimSpace(out[idx+len("BETTER_AUTH_SECRET="):])
	if len(val) < 24 {
		t.Fatalf("secret too short: %q", val)
	}
	// Two invocations must differ.
	out2, _, _ := run(t, []string{"secret"}, core.Options{})
	if out == out2 {
		t.Fatal("secret should be random per invocation")
	}
}

func TestGenerateCoreOnly(t *testing.T) {
	dir := t.TempDir()
	out, _, err := run(t, []string{"generate", "--dialect", "postgres", "-o", "schema.sql", "--yes"}, core.Options{WorkingDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "generated successfully") {
		t.Fatalf("unexpected output: %q", out)
	}
	sql := readFile(t, filepath.Join(dir, "schema.sql"))
	// Core tables present.
	for _, want := range []string{"CREATE TABLE IF NOT EXISTS ba_user", "ba_session", "ba_account", "ba_verification", "(postgres)"} {
		if !strings.Contains(sql, want) {
			t.Fatalf("schema missing core table %q", want)
		}
	}
	// Plugin tables absent without any feature enabled.
	for _, unexpected := range []string{"ba_organization", "ba_two_factor", "ba_wallet", "ba_jwks", "ba_device_code", "ba_oauth_app"} {
		if strings.Contains(sql, unexpected) {
			t.Fatalf("core-only schema should not contain %q", unexpected)
		}
	}
}

func TestGenerateWithPluginsFlag(t *testing.T) {
	dir := t.TempDir()
	_, _, err := run(t, []string{"generate", "--plugins", "organization,two-factor", "-o", "schema.sql", "--yes"}, core.Options{WorkingDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	sql := readFile(t, filepath.Join(dir, "schema.sql"))
	for _, want := range []string{"ba_organization", "ba_member", "ba_team", "ba_two_factor"} {
		if !strings.Contains(sql, want) {
			t.Fatalf("schema missing enabled-plugin table %q", want)
		}
	}
	for _, unexpected := range []string{"ba_wallet", "ba_jwks", "ba_oauth_app", "ba_device_code"} {
		if strings.Contains(sql, unexpected) {
			t.Fatalf("schema should not contain disabled-plugin table %q", unexpected)
		}
	}
}

func TestGenerateFromAuthConfig(t *testing.T) {
	// An auth instance with only the organization plugin should yield org tables
	// but not, say, the SIWE wallet or JWKS tables.
	a, err := auth.New(auth.Config{
		Secret:  "x-secret-aaaaaaaaaaaaaaaaaaaaaa",
		Store:   memory.New(),
		Plugins: []auth.Plugin{plugins.Organization(plugins.OrganizationOptions{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, _, err := run(t, []string{"generate", "-o", "schema.sql", "--yes"}, core.Options{Auth: a, WorkingDir: dir}); err != nil {
		t.Fatal(err)
	}
	sql := readFile(t, filepath.Join(dir, "schema.sql"))
	if !strings.Contains(sql, "ba_organization") {
		t.Fatal("expected organization tables from configured plugin")
	}
	for _, unexpected := range []string{"ba_wallet", "ba_jwks", "ba_two_factor"} {
		if strings.Contains(sql, unexpected) {
			t.Fatalf("schema should not contain %q (plugin not enabled)", unexpected)
		}
	}
}

func TestGenerateAll(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := run(t, []string{"generate", "--all", "-o", "schema.sql", "--yes"}, core.Options{WorkingDir: dir}); err != nil {
		t.Fatal(err)
	}
	sql := readFile(t, filepath.Join(dir, "schema.sql"))
	for _, want := range []string{"ba_organization", "ba_two_factor", "ba_wallet", "ba_jwks", "ba_oauth_app", "ba_device_code"} {
		if !strings.Contains(sql, want) {
			t.Fatalf("--all schema missing %q", want)
		}
	}
	// The shared OAuth app table must appear exactly once even though both
	// oidc-provider and mcp need it.
	if n := strings.Count(sql, "CREATE TABLE IF NOT EXISTS ba_oauth_app"); n != 1 {
		t.Fatalf("ba_oauth_app should be emitted once, got %d", n)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestGenerateOverwritePromptDeclined(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "schema.sql")
	if err := os.WriteFile(path, []byte("EXISTING"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Answer "n" to the overwrite prompt.
	out, _, err := run(t, []string{"generate"}, core.Options{WorkingDir: dir, Stdin: strings.NewReader("n\n")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Aborted") {
		t.Fatalf("expected abort message, got %q", out)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "EXISTING" {
		t.Fatal("file should not have been overwritten")
	}
}

func TestGenerateInvalidDialect(t *testing.T) {
	_, _, err := run(t, []string{"generate", "--dialect", "oracle", "--yes"}, core.Options{WorkingDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error for unsupported dialect")
	}
}

func TestMigrateWithAuthStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "auth.db")
	db, err := databasesql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := sqlstore.New(db, sqlstore.SQLite)

	a, err := auth.New(auth.Config{Secret: "x-secret-aaaaaaaaaaaaaaaaaaaaaa", Store: st})
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := run(t, []string{"migrate", "--yes"}, core.Options{Auth: a})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !strings.Contains(out, "Migration complete") {
		t.Fatalf("unexpected output: %q", out)
	}
	// Verify a core table now exists.
	var name string
	row := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='ba_user'`)
	if err := row.Scan(&name); err != nil {
		t.Fatalf("ba_user table not created: %v", err)
	}
}

func TestMigrateUnwrapsHookedStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "auth.db")
	db, _ := databasesql.Open("sqlite", "file:"+dbPath)
	defer db.Close()
	st := sqlstore.New(db, sqlstore.SQLite)

	// DatabaseHooks cause the store to be wrapped; migrate must unwrap it.
	a, err := auth.New(auth.Config{
		Secret: "x-secret-aaaaaaaaaaaaaaaaaaaaaa",
		Store:  st,
		DatabaseHooks: auth.DatabaseHooksConfig{
			User: &auth.UserDatabaseHooks{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, []string{"migrate", "--yes"}, core.Options{Auth: a}); err != nil {
		t.Fatalf("migrate through wrapper: %v", err)
	}
	if err := db.QueryRow(`SELECT 1 FROM ba_session LIMIT 1`).Err(); err != nil {
		// table existing (no rows) returns ErrNoRows, which is fine; a "no such
		// table" error is not.
		if strings.Contains(err.Error(), "no such table") {
			t.Fatalf("migration did not run through wrapper: %v", err)
		}
	}
}

func TestMigrateFromDSN(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "dsn.db")
	out, _, err := run(t, []string{"migrate", "--database", "file:" + dbPath, "--dialect", "sqlite", "--yes"}, core.Options{})
	if err != nil {
		t.Fatalf("migrate from dsn: %v", err)
	}
	if !strings.Contains(out, "Migration complete") {
		t.Fatalf("unexpected output: %q", out)
	}
	db, _ := databasesql.Open("sqlite", "file:"+dbPath)
	defer db.Close()
	if err := db.QueryRowContext(context.Background(), `SELECT name FROM sqlite_master WHERE name='ba_account'`).Scan(new(string)); err != nil {
		t.Fatalf("ba_account not created via DSN migrate: %v", err)
	}
}

func TestInfoJSON(t *testing.T) {
	a, err := auth.New(auth.Config{
		AppName: "Test", Secret: "x-secret-aaaaaaaaaaaaaaaaaaaaaa",
		Store:   memory.New(),
		Plugins: []auth.Plugin{plugins.Bearer(plugins.BearerOptions{})},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := run(t, []string{"info", "--json"}, core.Options{Auth: a, Version: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"betterauth": "1.2.3"`, `"appName": "Test"`, `"plugins"`, `"bearer"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("info json missing %q in %s", want, out)
		}
	}
}

func TestInit(t *testing.T) {
	dir := t.TempDir()
	out, _, err := run(t, []string{"init", "--name", "Demo", "--database", "sqlite", "--yes"}, core.Options{WorkingDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "initialized") {
		t.Fatalf("unexpected output: %q", out)
	}
	env, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(env), "BETTER_AUTH_SECRET=") {
		t.Fatal(".env missing secret")
	}
	goFile, err := os.ReadFile(filepath.Join(dir, "betterauth.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"package main", `AppName:        "Demo"`, "sqlstore.New", "modernc.org/sqlite"} {
		if !strings.Contains(string(goFile), want) {
			t.Fatalf("betterauth.go missing %q", want)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	_, _, err := run(t, []string{"frobnicate"}, core.Options{})
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
}

func TestHelp(t *testing.T) {
	out, _, err := run(t, []string{"help"}, core.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"generate", "migrate", "secret", "info", "init"} {
		if !strings.Contains(out, want) {
			t.Fatalf("help missing %q", want)
		}
	}
}
