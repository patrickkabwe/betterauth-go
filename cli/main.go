// Command betterauth is the Better Auth CLI for Go: generate, migrate, secret,
// info, and init.
//
// Install (binary named betterauth):
//
//	go build -o "$(go env GOPATH)/bin/betterauth" github.com/patrickkabwe/betterauth-go/cli@latest
//
// Usage:
//
//	betterauth secret
//	betterauth generate --dialect postgres --output schema.sql
//	betterauth migrate  --database "file:auth.db" --dialect sqlite
//	betterauth init      --name "My App" --database sqlite
//	betterauth info
//
// The SQLite driver (modernc.org/sqlite) is bundled, so `migrate --dialect
// sqlite` works out of the box. To migrate Postgres or MySQL from a DSN, build
// your own binary that imports the relevant driver and calls core.Run, or run
// `betterauth generate` and apply the SQL with your usual migration tooling.
package main

import (
	"fmt"
	"os"

	"github.com/patrickkabwe/betterauth-go/cli/core"

	_ "modernc.org/sqlite"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := core.Run(os.Args[1:], core.Options{Version: version}); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
