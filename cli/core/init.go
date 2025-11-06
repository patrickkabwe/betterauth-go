package core

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/patrickkabwe/betterauth-go/internal/id"
)

// runInit scaffolds Better Auth into a project: a .env with a generated secret
// and a starter Go file wiring up an auth.Auth instance. It mirrors
// `npx @better-auth/cli init`.
func runInit(args []string, opts Options) error {
	fs := newFlagSet("init", opts)
	var (
		name     string
		database string
		yes      bool
	)
	fs.StringVar(&name, "name", "Better Auth App", "application name")
	fs.StringVar(&database, "database", "sqlite", "database: sqlite | memory")
	fs.BoolVar(&yes, "yes", false, "overwrite existing files without prompting")
	fs.BoolVar(&yes, "y", false, "overwrite existing files without prompting (shorthand)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	secret, err := id.Generate(32)
	if err != nil {
		return err
	}

	envContent := "BETTER_AUTH_SECRET=" + secret + "\n" +
		"BETTER_AUTH_URL=http://localhost:8080\n" +
		"DATABASE_PATH=better-auth.db\n"

	if err := writeFileMaybe(opts, ".env", envContent, yes); err != nil {
		return err
	}
	if err := writeFileMaybe(opts, "betterauth.go", starterGo(name, database), yes); err != nil {
		return err
	}

	fmt.Fprintln(opts.Stdout, "")
	fmt.Fprintln(opts.Stdout, "✅ Better Auth initialized.")
	fmt.Fprintln(opts.Stdout, "Next steps:")
	fmt.Fprintln(opts.Stdout, "  1. go get github.com/patrickkabwe/betterauth-go")
	if database == "sqlite" {
		fmt.Fprintln(opts.Stdout, "  2. go get modernc.org/sqlite")
		fmt.Fprintln(opts.Stdout, "  3. go run . (server on http://localhost:8080)")
	} else {
		fmt.Fprintln(opts.Stdout, "  2. go run . (server on http://localhost:8080)")
	}
	return nil
}

// writeFileMaybe writes content to a file under the working dir, prompting
// before overwriting unless yes is set.
func writeFileMaybe(opts Options, name, content string, yes bool) error {
	path := filepath.Join(opts.WorkingDir, name)
	if _, err := os.Stat(path); err == nil && !yes {
		if !confirm(opts, fmt.Sprintf("%s already exists. Overwrite?", name)) {
			fmt.Fprintf(opts.Stdout, "Skipped %s\n", name)
			return nil
		}
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	fmt.Fprintf(opts.Stdout, "Created %s\n", name)
	return nil
}

func starterGo(appName, database string) string {
	var stdImports, thirdImports, storeSetup string
	if database == "sqlite" {
		stdImports = `	"context"
	databasesql "database/sql"
	"log"
	"net/http"
	"os"`
		thirdImports = `	"github.com/patrickkabwe/betterauth-go/auth"
	sqlstore "github.com/patrickkabwe/betterauth-go/store/sql"

	_ "modernc.org/sqlite"`
		storeSetup = `	db, err := databasesql.Open("sqlite", "file:"+envOr("DATABASE_PATH", "better-auth.db"))
	if err != nil {
		log.Fatal(err)
	}
	st := sqlstore.New(db, sqlstore.SQLite)
	if err := st.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}
	store := st`
	} else {
		stdImports = `	"log"
	"net/http"
	"os"`
		thirdImports = `	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/store/memory"`
		storeSetup = `	store := memory.New()`
	}

	return fmt.Sprintf(`package main

import (
%s

%s
)

// NewAuth builds the application's Better Auth instance.
func NewAuth() (*auth.Auth, error) {
%s
	return auth.New(auth.Config{
		AppName:        %q,
		Secret:         os.Getenv("BETTER_AUTH_SECRET"),
		BaseURL:        envOr("BETTER_AUTH_URL", "http://localhost:8080"),
		TrustedOrigins: []string{"http://localhost:3000"},
		Store:          store,
	})
}

func main() {
	a, err := NewAuth()
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", a.Handler()))
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
`, stdImports, thirdImports, storeSetup, appName)
}
