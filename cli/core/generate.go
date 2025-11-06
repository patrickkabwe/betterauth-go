package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sqlstore "github.com/patrickkabwe/betterauth-go/store/sql"
)

// runGenerate writes the SQL schema required by Better Auth to a file. It
// mirrors `npx @better-auth/cli generate`. For the SQL adapter the default
// output is schema.sql (matching the Kysely adapter behavior).
func runGenerate(args []string, opts Options) error {
	fs := newFlagSet("generate", opts)
	var (
		output  string
		dialect string
		plugins string
		all     bool
		yes     bool
	)
	fs.StringVar(&output, "output", "schema.sql", "where to write the generated schema")
	fs.StringVar(&output, "o", "schema.sql", "where to write the generated schema (shorthand)")
	fs.StringVar(&dialect, "dialect", "sqlite", "target dialect: postgres | sqlite | mysql")
	fs.StringVar(&plugins, "plugins", "", "comma-separated plugin IDs whose tables to include (ignored when an auth instance is supplied)")
	fs.BoolVar(&all, "all", false, "include tables for every supported plugin")
	fs.BoolVar(&yes, "yes", false, "skip the confirmation prompt and write the schema directly")
	fs.BoolVar(&yes, "y", false, "skip the confirmation prompt (shorthand)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	d, err := parseDialect(dialect)
	if err != nil {
		return err
	}

	pluginIDs := resolvePluginIDs(opts, plugins, all)

	path := output
	if !filepath.IsAbs(path) {
		path = filepath.Join(opts.WorkingDir, output)
	}

	if _, statErr := os.Stat(path); statErr == nil && !yes {
		if !confirm(opts, fmt.Sprintf("%s already exists. Overwrite?", output)) {
			fmt.Fprintln(opts.Stdout, "Aborted.")
			return nil
		}
	}

	schema := sqlstore.SchemaSQL(d, pluginIDs...)
	if err := os.WriteFile(path, []byte(schema), 0o644); err != nil {
		return fmt.Errorf("write schema: %w", err)
	}

	if len(pluginIDs) > 0 {
		fmt.Fprintf(opts.Stdout, "🚀 Schema (core + %s) was generated successfully at %s\n", strings.Join(pluginIDs, ", "), output)
	} else {
		fmt.Fprintf(opts.Stdout, "🚀 Schema (core tables) was generated successfully at %s\n", output)
	}
	return nil
}

func parseDialect(s string) (sqlstore.Dialect, error) {
	switch s {
	case "postgres", "postgresql", "pg":
		return sqlstore.Postgres, nil
	case "sqlite", "sqlite3":
		return sqlstore.SQLite, nil
	case "mysql", "mariadb":
		return sqlstore.MySQL, nil
	default:
		return 0, fmt.Errorf("unsupported dialect %q (use postgres, sqlite, or mysql)", s)
	}
}
