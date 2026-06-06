# CLI

The `betterauth-go` CLI mirrors [`@better-auth/cli`](https://better-auth.com/docs/concepts/cli):
generate schema, migrate, create secrets, scaffold projects, and print diagnostics.

## Install

```bash
go install github.com/patrickkabwe/betterauth-go/cmd/betterauth-go@latest
```

Or download a prebuilt `betterauth-go-*` binary from
[GitHub Releases](https://github.com/patrickkabwe/betterauth-go/releases).

One-off without installing:

```bash
go run github.com/patrickkabwe/betterauth-go/cmd/betterauth-go@latest secret
```

## Package layout

| Path | Purpose |
|------|---------|
| `github.com/patrickkabwe/betterauth-go/cmd/betterauth-go` | Installable binary (`package main`) |
| `github.com/patrickkabwe/betterauth-go/cli/core` | Embeddable library — `core.Run`, `core.Options` |

Import `cli/core` when you embed the CLI in your own binary with a configured
`*auth.Auth`. See below.

## Commands

| Command | Description |
|---------|-------------|
| `secret` | Print a fresh `BETTER_AUTH_SECRET` |
| `generate` | Write SQL schema to a file |
| `migrate` | Apply schema to a database |
| `init` | Scaffold `.env` and starter `betterauth.go` |
| `info` | Print diagnostics (Go version, plugins, store) |

### secret

```bash
betterauth-go secret
# BETTER_AUTH_SECRET=…
```

### generate

Write feature-scoped SQL (core tables + enabled plugins only):

```bash
betterauth-go generate --dialect postgres -o schema.sql
betterauth-go generate --plugins organization,two-factor --dialect sqlite
betterauth-go generate --all --yes
```

| Flag | Description |
|------|-------------|
| `-o`, `--output` | Output file (default `schema.sql`) |
| `--dialect` | `postgres`, `sqlite`, or `mysql` |
| `--plugins` | Comma-separated plugin IDs |
| `--all` | Include every plugin table |
| `-y`, `--yes` | Skip overwrite confirmation |

### migrate

```bash
betterauth-go migrate --database "file:auth.db" --dialect sqlite
betterauth-go migrate --database "$DATABASE_URL" --dialect postgres --plugins organization
```

The bundled binary embeds a SQLite driver. For Postgres/MySQL, pass your
configured `*auth.Auth` via an embedded CLI (below).

### init

```bash
betterauth-go init --name "My App" --database sqlite --yes
```

Creates a starter project with `.env` and a minimal `betterauth.go`.

### info

```bash
betterauth-go info
betterauth-go info --json
```

## Feature-scoped schema

Like the TypeScript CLI, `generate` and `migrate` emit only the tables your
enabled plugins need:

- **Core:** `user`, `account`, `session`, `verification`
- **Plugins:** organization, two-factor, jwt, oidc-provider, mcp, siwe,
  device-authorization, etc.

When you pass an `*auth.Auth` instance, plugin detection is automatic.

## Embedded CLI

Go is statically compiled — commands that need your real config read from an
`*auth.Auth` you provide (the Go equivalent of `--config` in the TS CLI):

```go
package main

import (
    "os"
    "github.com/patrickkabwe/betterauth-go/cli/core"
)

func main() {
    a, _ := NewAuth() // your configured instance
    if err := core.Run(os.Args[1:], core.Options{Auth: a, Version: "1.0.0"}); err != nil {
        os.Exit(1)
    }
}
```

Build and run (from a directory with your `main.go` above):

```bash
go build -o myauth-cli .
./myauth-cli migrate
./myauth-cli info
```

For Postgres/MySQL, import the driver in your `main.go` (e.g. `_ "github.com/lib/pq"`)
before calling `core.Run`.

Next: [Plugin overview →](../plugins/overview.md)
