# betterauth (Go)

A Go server implementation compatible with [Better Auth](https://better-auth.com) clients — React, Vue, Svelte, Solid, and the framework-agnostic client.

Drop this into any Go HTTP server and point your `better-auth/react` (or other) client at it.

## Features

- **Client-compatible API** — implements the endpoints expected by official Better Auth clients
- **Signed session cookies** — HMAC-SHA256 signing matching `better-call` (`better-auth.session_token`)
- **Scrypt passwords** — compatible hash format (`salt:key`) with the TypeScript server
- **Pluggable storage** — `Store` interface with in-memory and SQL (Postgres / SQLite / MySQL) adapters
- **24 core plugins** — bearer, JWT, organization, admin, 2FA, magic link, email OTP, passkey-adjacent, OIDC provider, and more
- **Production middleware** — credentials-aware CORS (with wildcard origins), origin-based CSRF protection, and per-path rate limiting
- **Database hooks** — before/after callbacks around user and session create/update/delete
- **Secret rotation** — sign with a new secret while still trusting old ones (zero-downtime rotation)
- **Cross-subdomain & custom cookies** — shared cookie domains, custom names, and the `Partitioned` attribute

## Supported Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/ok` | Health check |
| POST | `/sign-up/email` | Register with email/password |
| POST | `/sign-in/email` | Sign in with email/password |
| GET/POST | `/get-session` | Get current session |
| POST | `/sign-out` | Sign out |
| GET | `/list-sessions` | List active sessions |
| POST | `/revoke-session` | Revoke a session by token |
| POST | `/revoke-sessions` | Revoke all sessions |
| POST | `/revoke-other-sessions` | Revoke all other sessions |

Plus email verification, password reset, user/account management, social OAuth (`/sign-in/social`, `/callback/:provider`), and all plugin endpoints. Default base path: `/api/auth`

## Quick Start

### Go Server

```go
package main

import (
    "log"
    "net/http"

    "github.com/patrickkabwe/betterauth-go/auth"
    "github.com/patrickkabwe/betterauth-go/store/memory"
)

func main() {
    a, err := auth.New(auth.Config{
        Secret:  "your-secret-at-least-32-chars-long",
        BaseURL: "http://localhost:8080",
        TrustedOrigins: []string{"http://localhost:3000"},
        Store:   memory.New(),
    })
    if err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    mux.Handle("/api/auth/", http.StripPrefix("/api/auth", a.Handler()))
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

Run the Go server:

```bash
go run ./examples/basic
```

### React Client Example

A full Vite + React app lives in `examples/client/`:

```bash
# Terminal 1 — Go server
go run ./examples/basic

# Terminal 2 — React client
cd examples/client
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173). See [`examples/client/README.md`](examples/client/README.md) for details.

### React Client (manual setup)

```ts
// lib/auth-client.ts
import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient({
  baseURL: "http://localhost:8080", // your Go server
});
```

```tsx
// Usage
const { data, error } = await authClient.signUp.email({
  name: "Jane Doe",
  email: "jane@example.com",
  password: "securepassword",
});

const { data: session } = await authClient.getSession();
const { data: user } = await authClient.useSession(); // reactive hook
```

## Configuration

```go
auth.New(auth.Config{
    Secret:         "required",
    OldSecrets:     []string{"previous-secret"}, // optional: zero-downtime rotation
    BaseURL:        "http://localhost:8080",
    BasePath:       "/api/auth",                 // default
    Store:          myStore,                     // required
    TrustedOrigins: []string{"https://*.example.com"}, // CORS + CSRF (wildcards ok)

    Session: auth.SessionConfig{
        ExpiresIn: 7 * 24 * time.Hour, // default
    },

    // Per-path rate limiting (in-memory by default; supply Storage for Redis/DB).
    RateLimit: auth.RateLimitConfig{
        Enabled: true,
        Window:  time.Minute,
        Max:     100,
        CustomRules: map[string]auth.RateLimitRule{
            "/sign-in/*": {Max: 10, Window: time.Minute},
        },
    },

    // before/after callbacks around core store operations.
    DatabaseHooks: auth.DatabaseHooksConfig{
        User: &auth.UserDatabaseHooks{
            AfterCreate: func(ctx context.Context, u *types.User) error { return nil },
        },
    },

    Advanced: auth.AdvancedConfig{
        UseSecureCookies:      true, // production (HTTPS)
        DisableCSRFCheck:      false,
        IPAddressHeaders:      []string{"X-Forwarded-For"}, // behind a proxy
        CrossSubDomainCookies: auth.CrossSubDomainConfig{Enabled: true, Domain: ".example.com"},
        Cookies:               map[string]auth.CookieOverride{"session_token": {Name: "my_session"}},
    },
})
```

## Storage

### SQL (Postgres / SQLite / MySQL)

The `store/sql` adapter is **driver-agnostic**: you supply your own `*sql.DB` and a dialect.

```go
import (
    databasesql "database/sql"
    sqlstore "github.com/patrickkabwe/betterauth-go/store/sql"
    _ "modernc.org/sqlite" // or lib/pq, jackc/pgx, go-sql-driver/mysql
)

db, _ := databasesql.Open("sqlite", "file:auth.db")
st := sqlstore.New(db, sqlstore.SQLite) // or sqlstore.Postgres / sqlstore.MySQL
_ = st.Migrate(context.Background())     // creates tables if missing

a, _ := auth.New(auth.Config{Secret: "...", Store: st})
```

Timestamps are stored as unix-millisecond integers and booleans as `0/1`, so the
schema is identical across all three databases. The adapter implements both
`store.Store` and `store.ExtStore` (plugin entities).

### Custom Storage

Implement the `store.Store` interface for any backend:

```go
type Store interface {
    CreateUser(ctx context.Context, user *types.User) error
    FindUserByEmail(ctx context.Context, email string) (*types.User, error)
    // ... see store/store.go
}
```

## CLI

A Better Auth-compatible CLI ships as both an installable binary and an embeddable package, mirroring `npx @better-auth/cli`.

```bash
go build -o "$(go env GOPATH)/bin/betterauth" github.com/patrickkabwe/betterauth-go/cli@latest

betterauth secret                                   # generate BETTER_AUTH_SECRET
betterauth generate --dialect postgres -o schema.sql # write the SQL schema
betterauth migrate  --database "file:auth.db" --dialect sqlite
betterauth init     --name "My App" --database sqlite
betterauth info
```

| Command | Description | Flags |
|---------|-------------|-------|
| `secret` | Print a fresh secret for your `.env` | — |
| `generate` | Write the SQL schema to a file (`schema.sql`) | `--output/-o`, `--dialect`, `--plugins`, `--all`, `--yes/-y` |
| `migrate` | Apply the schema to a database | `--database/-d`, `--dialect`, `--driver`, `--plugins`, `--all`, `--yes/-y` |
| `info` | Diagnostics (Go/OS, app, store, plugins) | `--json` |
| `init` | Scaffold `.env` + a starter `betterauth.go` | `--name`, `--database`, `--yes/-y` |

`generate` and `migrate` are **feature-scoped**, like the TS CLI: they emit the
four core tables (`user`, `account`, `session`, `verification`) plus only the
tables required by the plugins you've enabled. When you pass an `*auth.Auth`
(via `core.Run`), the enabled plugins are detected automatically. From the
config-less binary, select features with `--plugins organization,two-factor` or
include everything with `--all`.

The bundled binary embeds the SQLite driver. Because Go is statically compiled,
`generate`/`migrate`/`info` read your real config from an `*auth.Auth` instance
(the Go equivalent of the TS CLI's `--config` file). Build a tiny binary that
constructs your auth and calls `core.Run` — this lets `migrate` apply the schema
to your already-configured Postgres/MySQL connection:

```go
package main

import (
    "os"
    "github.com/patrickkabwe/betterauth-go/cli/core"
)

func main() {
    a, _ := NewAuth() // your configured *auth.Auth
    if err := core.Run(os.Args[1:], core.Options{Auth: a, Version: "1.0.0"}); err != nil {
        os.Exit(1)
    }
}
```

## Framework Integration

### Chi

```go
r.Mount("/api/auth", a.Handler())
```

### Gin

```go
r.Any("/api/auth/*path", func(c *gin.Context) {
    a.Handler().ServeHTTP(c.Writer, c.Request)
})
```

### Echo / Fiber

Wrap `a.Handler()` as middleware or mount at `/api/auth`.

## Compatibility Notes

This library implements the core email/password flow, social OAuth, session
management, user/account management, and 24 core plugins (bearer, JWT,
organization, admin, two-factor, magic link, email OTP, OIDC provider, and
more — see [`plugins/`](plugins) and the [ROADMAP](ROADMAP.md)).

Session cookies use the same signing algorithm as Better Auth (`value.hmac_sha256_base64`). Password hashes use scrypt with `N=16384, r=16, p=1, dkLen=64`.

See the [ROADMAP](ROADMAP.md) for the full feature-parity tracker against the TypeScript server.

## License

MIT
