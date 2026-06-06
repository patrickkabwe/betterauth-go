// Package core implements the betterauth command-line interface, mirroring the
// official Better Auth CLI (`npx @better-auth/cli`): generate, migrate, secret,
// info, and init.
//
// Because Go is statically compiled, commands that need your auth configuration
// (generate / migrate / info) read it from an *auth.Auth value you pass in via
// Options.Auth — this is the Go equivalent of the TypeScript CLI's --config
// file discovery. Build a tiny binary that constructs your auth instance and
// calls core.Run:
//
//	import "github.com/patrickkabwe/betterauth-go/cli/core"
//
//	func main() {
//		a, _ := auth.New(myConfig)
//		if err := core.Run(os.Args[1:], core.Options{Auth: a, Version: "1.0.0"}); err != nil {
//			os.Exit(1)
//		}
//	}
//
// The bundled betterauth-go binary wires this up with a SQLite driver and the default
// schema for config-less use.
package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/patrickkabwe/betterauth-go/auth"
	"github.com/patrickkabwe/betterauth-go/internal/id"
	sqlstore "github.com/patrickkabwe/betterauth-go/store/sql"
)

// Options configures a CLI invocation.
type Options struct {
	// Auth is the configured auth instance. Optional: secret/init never need it,
	// generate/migrate/info use it to reflect plugins, store, and config.
	Auth *auth.Auth
	// Version is reported by `info` and `--version`.
	Version string

	// IO. Defaults: os.Stdin / os.Stdout / os.Stderr.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// WorkingDir for file output (generate/init). Defaults to ".".
	WorkingDir string
}

func (o *Options) applyDefaults() {
	if o.Stdin == nil {
		o.Stdin = os.Stdin
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.WorkingDir == "" {
		o.WorkingDir = "."
	}
}

// Run dispatches a CLI invocation. args is the argument list without the program
// name (typically os.Args[1:]).
func Run(args []string, opts Options) error {
	opts.applyDefaults()

	if len(args) == 0 {
		printUsage(opts.Stdout)
		return nil
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "secret":
		return runSecret(rest, opts)
	case "generate":
		return runGenerate(rest, opts)
	case "migrate":
		return runMigrate(rest, opts)
	case "info":
		return runInfo(rest, opts)
	case "init":
		return runInit(rest, opts)
	case "help", "-h", "--help":
		printUsage(opts.Stdout)
		return nil
	case "version", "-v", "--version":
		v := opts.Version
		if v == "" {
			v = "dev"
		}
		fmt.Fprintln(opts.Stdout, "betterauth-go "+v)
		return nil
	default:
		fmt.Fprintf(opts.Stderr, "unknown command %q\n\n", cmd)
		printUsage(opts.Stderr)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `betterauth-go — Better Auth CLI for Go

Usage:
  betterauth-go <command> [flags]

Commands:
  generate   Generate the database schema required by Better Auth
  migrate    Apply the Better Auth schema directly to your database
  secret     Generate a secret key for your Better Auth instance
  info       Print diagnostic information about your setup
  init       Scaffold Better Auth into a new project

Run "betterauth-go <command> --help" for command-specific flags.
`)
}

// runSecret generates a high-entropy secret and prints the .env line. It mirrors
// `npx @better-auth/cli secret`.
func runSecret(args []string, opts Options) error {
	fs := newFlagSet("secret", opts)
	if err := fs.Parse(args); err != nil {
		return err
	}
	secret, err := id.Generate(32)
	if err != nil {
		return err
	}
	fmt.Fprintln(opts.Stdout, "Add the following to your .env file:")
	fmt.Fprintln(opts.Stdout)
	fmt.Fprintln(opts.Stdout, "BETTER_AUTH_SECRET="+secret)
	return nil
}

// confirm prompts the user with a yes/no question. An empty answer defaults to
// yes. It returns true when confirmed.
func confirm(opts Options, question string) bool {
	fmt.Fprintf(opts.Stdout, "%s [Y/n] ", question)
	reader := bufio.NewReader(opts.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "" || line == "y" || line == "yes"
}

// migrator is implemented by stores that can create their own schema (the SQL
// adapter). Used by `migrate` when an Auth instance is supplied.
type migrator interface {
	Migrate(context.Context) error
}

// featureMigrator is implemented by stores that can provision only the tables a
// given set of plugins requires (the SQL adapter's MigrateFor).
type featureMigrator interface {
	MigrateFor(context.Context, ...string) error
}

// resolvePluginIDs determines which plugin schema groups to include. When an
// auth instance is supplied its configured plugins are authoritative (the Go
// equivalent of the TS CLI reading your config). Otherwise the --plugins list
// or --all flag is used; with neither, only the core schema is emitted.
func resolvePluginIDs(opts Options, explicit string, all bool) []string {
	if opts.Auth != nil {
		ids := make([]string, 0, len(opts.Auth.Plugins()))
		for _, p := range opts.Auth.Plugins() {
			ids = append(ids, p.ID())
		}
		return ids
	}
	if all {
		return sqlstore.AllPluginIDs()
	}
	if explicit == "" {
		return nil
	}
	var ids []string
	for _, part := range strings.Split(explicit, ",") {
		if p := strings.TrimSpace(part); p != "" {
			ids = append(ids, p)
		}
	}
	return ids
}
