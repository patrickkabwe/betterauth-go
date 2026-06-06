# Go client

The `github.com/patrickkabwe/betterauth-go/client` package calls Better Auth endpoints
from Go services — SSR backends, workers, CLI tools, and custom middleware.

## Install

Included in the main module:

```bash
go get github.com/patrickkabwe/betterauth-go
```

## Basic usage

```go
import "github.com/patrickkabwe/betterauth-go/client"

c := client.New("http://localhost:8080")
sess, err := c.GetSession(ctx)
if err != nil {
    log.Fatal(err)
}
if sess == nil {
    // not authenticated
}
fmt.Println(sess.User.Email)
```

## Authentication modes

### Session cookie

Forward the browser's session cookie:

```go
cookie := r.Header.Get("Cookie") // or extract better-auth.session_token
c := client.New(baseURL, client.WithCookie(cookie))
sess, _ := c.GetSession(ctx)
```

### Bearer token

With the [bearer plugin](../plugins/bearer.md) enabled:

```go
c := client.New(baseURL, client.WithBearerToken(token))
sess, _ := c.GetSession(ctx)
```

### Custom base path

```go
sess, err := c.GetSessionAt(ctx, "/auth/get-session")
```

## Fetch client schema

For codegen or dynamic client configuration:

```go
schema, err := c.FetchSchema(ctx)
// json.RawMessage — same as GET /api/auth/client-schema
```

## Custom HTTP client

```go
c := client.New(baseURL,
    client.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}),
)
```

## Protecting your own routes

```go
func requireAuth(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        c := client.New(authBaseURL, client.WithCookie(r.Header.Get("Cookie")))
        sess, err := c.GetSession(r.Context())
        if err != nil || sess == nil {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        ctx := context.WithValue(r.Context(), userKey, sess.User)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

Next: [Frameworks →](frameworks.md)
