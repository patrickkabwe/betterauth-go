# Testing

Test auth flows in Go using the in-memory store and `httptest` — no database
required.

## Minimal test setup

```go
package myapp_test

import (
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/patrickkabwe/betterauth-go/auth"
    "github.com/patrickkabwe/betterauth-go/store/memory"
)

func testAuth(t *testing.T) *auth.Auth {
    t.Helper()
    a, err := auth.New(auth.Config{
        Secret:         "test-secret-at-least-32-characters",
        BaseURL:        "http://localhost:8080",
        TrustedOrigins: []string{"http://localhost:3000"},
        Store:          memory.New(),
    })
    if err != nil {
        t.Fatal(err)
    }
    return a
}
```

## HTTP requests against the handler

Mount paths the way your app does:

```go
func signUp(t *testing.T, a *auth.Auth, email string) *http.Response {
    t.Helper()
    body := `{"name":"Test","email":"` + email + `","password":"password123"}`
    req := httptest.NewRequest(http.MethodPost, "/sign-up/email", strings.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Origin", "http://localhost:3000")
    req.URL.Path = "/sign-up/email" // handler expects stripped path

    rr := httptest.NewRecorder()
    a.Handler().ServeHTTP(rr, req)
    return rr.Result()
}
```

The repo's `auth/testutil_test.go` shows a full helper pattern including cookie
forwarding and query strings.

## Testing with plugins

Enable only the plugins under test:

```go
a, _ := auth.New(auth.Config{
    Secret: "test-secret-at-least-32-characters",
    Store:  memory.New(),
    Plugins: []auth.Plugin{
        plugins.Username(plugins.UsernameOptions{}),
    },
})
```

Memory store implements `ExtStore`, so organization, 2FA, and admin plugins
work in tests without SQL.

## Testing email callbacks

Capture URLs from `SendVerificationEmail`, `SendResetPassword`, or
`SendMagicLink` callbacks:

```go
var sentLinks []string

a, _ := auth.New(auth.Config{
    // …
    EmailVerification: auth.EmailVerificationConfig{
        SendVerificationEmail: func(_ context.Context, data types.VerificationEmailData) error {
            sentLinks = append(sentLinks, data.URL)
            return nil
        },
    },
})
```

## Integration tests

For SQL adapter coverage, use an in-memory SQLite file:

```go
db, _ := sql.Open("sqlite", "file:test.db?mode=memory&cache=shared")
st := sqlstore.New(db, sqlstore.SQLite)
_ = st.Migrate(context.Background())
```

Run the full suite:

```bash
go test ./...
```

Back to: [Examples](examples.md)
