# Server-side API

Beyond `auth.Handler()`, the `*auth.Auth` instance exposes helper methods for
plugins, custom routes, and server-side code — a partial equivalent of the
TypeScript `auth.api.*` namespace.

## Session helpers

```go
// Create a session and set cookies on the response context
sess, err := a.NewSession(ctx, userID, rememberMe)

// Sign / verify session tokens (same algorithm as cookies)
signed := a.SignSessionToken(rawToken)
raw, ok := a.VerifySignedSessionToken(signed)

// Clear session cookie on sign-out
a.ClearSessionCookie(ctx)
```

## Password helpers

```go
hash, err := a.HashPassword("password123")
ok, err := a.VerifyPassword(storedHash, "password123")
err := a.ValidatePasswords("password123") // runs plugin validators (e.g. HIBP)
```

## Verification tokens

Used by magic link, email OTP, password reset, and OAuth state:

```go
err := a.CreateVerification(ctx, identifier, payload, time.Hour)
v, err := a.ConsumeVerification(ctx, identifier) // loads and deletes
```

## User additional fields

```go
user, err := a.FindUserByAdditional(ctx, "username", "jane")
user, err := a.SetUserAdditional(ctx, userID, map[string]any{"role": "admin"})
```

## Session additional fields

```go
sess, err := a.SetSessionAdditional(ctx, token, map[string]any{
    "activeOrganizationId": orgID,
})
```

## ExtStore access

Plugins need `store.ExtStore`. Unwrap decorated stores (e.g. database hooks):

```go
ext, ok := auth.ExtStore(a.Store())
if ok {
    orgs, _ := ext.ListOrganizationsByUserID(ctx, userID)
}
```

## Instance accessors

```go
a.Store()    // store.Store
a.BasePath() // "/api/auth"
a.BaseURL()  // "https://api.example.com"
a.Plugins()  // []Plugin
a.ClientSchemaJSON() // for codegen
```

## Custom routes alongside auth

Mount your own handlers on the same mux; protect them by resolving the session:

```go
func protected(w http.ResponseWriter, r *http.Request) {
    // Forward cookies to get-session, or use the Go client package
}
```

Or call `GetSession` via the [Go client](../integrations/go-client.md).

Next: [Errors →](errors.md)
