# Installation

## 1. Add the module

```bash
go get github.com/patrickkabwe/betterauth-go
```

Requires Go 1.25+.

## 2. Generate a secret

The server needs a signing secret. Generate one with the CLI (or any
high-entropy string):

```bash
# one-off (no install)
go run github.com/patrickkabwe/betterauth-go/cli@latest secret

# or install as betterauth
go build -o "$(go env GOPATH)/bin/betterauth" github.com/patrickkabwe/betterauth-go/cli@latest
betterauth secret
# → BETTER_AUTH_SECRET=…
```

Store it in your environment, not in source. The server reads it from
`auth.Config.Secret`.

## 3. Choose a store

| Store | Import | Use for |
|-------|--------|---------|
| In-memory | `store/memory` | tests, prototypes (data lost on restart) |
| SQL | `store/sql` | Postgres / SQLite / MySQL via any `database/sql` driver |
| Custom | implement `store.Store` | your own ORM (GORM, ent, sqlx, …) |

In-memory needs no driver:

```go
import "github.com/patrickkabwe/betterauth-go/store/memory"

store := memory.New()
```

SQL needs a `database/sql` driver (you import the driver, the adapter is
driver-agnostic):

```go
import (
    databasesql "database/sql"
    sqlstore "github.com/patrickkabwe/betterauth-go/store/sql"
    _ "modernc.org/sqlite" // pure-Go SQLite; or lib/pq, jackc/pgx, go-sql-driver/mysql
)

db, _ := databasesql.Open("sqlite", "file:auth.db")
st := sqlstore.New(db, sqlstore.SQLite)
_ = st.Migrate(context.Background()) // or run `betterauth migrate`
```

See [Database & adapters](concepts/database.md) for Postgres/MySQL and ORM
integration.

## 4. Mount the handler

```go
mux := http.NewServeMux()
mux.Handle("/api/auth/", http.StripPrefix("/api/auth", a.Handler()))
```

That's it — continue to [Basic usage →](basic-usage.md).
