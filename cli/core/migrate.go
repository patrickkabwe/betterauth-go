package core

import (
	"context"
	databasesql "database/sql"
	"fmt"

	"github.com/patrickkabwe/betterauth-go/store"
	sqlstore "github.com/patrickkabwe/betterauth-go/store/sql"
)

// runMigrate applies the Better Auth schema directly to the database. It
// mirrors `npx @better-auth/cli migrate`.
//
// It works in two modes:
//   - With Options.Auth whose store is a SQL store (or wraps one): migrate that
//     live store, using whatever driver it was opened with.
//   - With --database <dsn>: open a fresh connection using the dialect's driver
//     (which the calling binary must have imported) and migrate it.
func runMigrate(args []string, opts Options) error {
	fs := newFlagSet("migrate", opts)
	var (
		database string
		dialect  string
		driver   string
		plugins  string
		all      bool
		yes      bool
	)
	fs.StringVar(&database, "database", "", "database DSN to migrate (when no Auth instance is supplied)")
	fs.StringVar(&database, "d", "", "database DSN (shorthand)")
	fs.StringVar(&dialect, "dialect", "sqlite", "target dialect: postgres | sqlite | mysql")
	fs.StringVar(&driver, "driver", "", "database/sql driver name (defaults from dialect)")
	fs.StringVar(&plugins, "plugins", "", "comma-separated plugin IDs whose tables to include (ignored when an auth instance is supplied)")
	fs.BoolVar(&all, "all", false, "include tables for every supported plugin")
	fs.BoolVar(&yes, "yes", false, "skip the confirmation prompt and apply the schema directly")
	fs.BoolVar(&yes, "y", false, "skip the confirmation prompt (shorthand)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pluginIDs := resolvePluginIDs(opts, plugins, all)

	// Mode 1: migrate the live store from the provided Auth instance, scoped to
	// the plugins that instance has configured.
	if opts.Auth != nil {
		if fm, ok := asFeatureMigrator(opts.Auth.Store()); ok {
			if !yes && !confirm(opts, "Apply the Better Auth schema to the configured database?") {
				fmt.Fprintln(opts.Stdout, "Migration aborted.")
				return nil
			}
			if err := fm.MigrateFor(context.Background(), pluginIDs...); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}
			fmt.Fprintln(opts.Stdout, "✅ Migration complete.")
			return nil
		}
		if m, ok := asMigrator(opts.Auth.Store()); ok {
			if !yes && !confirm(opts, "Apply the Better Auth schema to the configured database?") {
				fmt.Fprintln(opts.Stdout, "Migration aborted.")
				return nil
			}
			if err := m.Migrate(context.Background()); err != nil {
				return fmt.Errorf("migrate: %w", err)
			}
			fmt.Fprintln(opts.Stdout, "✅ Migration complete.")
			return nil
		}
		if database == "" {
			return fmt.Errorf("the configured store does not support automatic migration; pass --database to migrate a SQL database, or run `betterauth-go generate` and apply the SQL yourself")
		}
	}

	// Mode 2: open a database from the DSN and migrate it.
	if database == "" {
		return fmt.Errorf("no database to migrate: supply Options.Auth with a SQL store or pass --database <dsn>")
	}

	d, err := parseDialect(dialect)
	if err != nil {
		return err
	}
	if driver == "" {
		driver = defaultDriver(d)
	}

	db, err := databasesql.Open(driver, database)
	if err != nil {
		return fmt.Errorf("open database (driver %q): %w", driver, err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}

	if !yes && !confirm(opts, fmt.Sprintf("Apply the Better Auth schema to the %s database?", d)) {
		fmt.Fprintln(opts.Stdout, "Migration aborted.")
		return nil
	}

	st := sqlstore.New(db, d)
	if err := st.MigrateFor(context.Background(), pluginIDs...); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	fmt.Fprintln(opts.Stdout, "✅ Migration complete.")
	return nil
}

// asFeatureMigrator returns a featureMigrator for s, unwrapping store decorators.
func asFeatureMigrator(s store.Store) (featureMigrator, bool) {
	if m, ok := s.(featureMigrator); ok {
		return m, true
	}
	if u, ok := s.(interface{ Unwrap() store.Store }); ok {
		return asFeatureMigrator(u.Unwrap())
	}
	return nil, false
}

// asMigrator returns a migrator for s, transparently unwrapping store decorators
// (e.g. the database-hooks wrapper).
func asMigrator(s store.Store) (migrator, bool) {
	if m, ok := s.(migrator); ok {
		return m, true
	}
	if u, ok := s.(interface{ Unwrap() store.Store }); ok {
		return asMigrator(u.Unwrap())
	}
	return nil, false
}

func defaultDriver(d sqlstore.Dialect) string {
	switch d {
	case sqlstore.Postgres:
		return "postgres"
	case sqlstore.MySQL:
		return "mysql"
	default:
		return "sqlite"
	}
}
