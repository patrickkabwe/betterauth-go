# Security & middleware

Production hardening is built into the handler: CORS, CSRF, rate limiting, and
secret rotation.

## Trusted origins

`TrustedOrigins` drives **both** CORS and CSRF:

```go
TrustedOrigins: []string{
    "http://localhost:3000",
    "https://app.example.com",
    "https://*.example.com", // wildcard patterns supported
},
```

`BaseURL` is automatically added to the trusted set.

Wildcards use `*` segments — `"*"` alone allows any origin (use with care).

## CORS

The handler sets appropriate `Access-Control-*` headers for preflight and
actual requests from trusted origins. Credentials (cookies) are supported.

## CSRF protection

For state-changing requests (POST, PUT, PATCH, DELETE), the server checks the
`Origin` header — or `Referer` when Origin is absent — against trusted origins.

- GET/HEAD/OPTIONS are exempt.
- Requests with no Origin or Referer are allowed (non-browser clients, bearer
  tokens).
- Disable with `Advanced.DisableCSRFCheck: true` (not recommended in production).

## Secret rotation

Rotate signing secrets without invalidating existing sessions:

```go
auth.Config{
    Secret:     os.Getenv("BETTER_AUTH_SECRET"),      // new secret
    OldSecrets: []string{os.Getenv("OLD_SECRET")},    // still verify old cookies
}
```

New cookies are signed with `Secret`; verification accepts `OldSecrets` too.

## Secure cookies

```go
UseSecureCookies: true,
// or
Advanced: auth.AdvancedConfig{UseSecureCookies: true},
```

Required for HTTPS deployments. Sets the `Secure` flag and `__Secure-` cookie
prefix.

## Disable paths

Turn off specific endpoints:

```go
DisabledPaths: []string{"/sign-up/email"},
```

## IP tracking

Session records store IP address and user agent on create and refresh. Disable
with `Advanced.DisableIPTracking: true`.

## API errors

Customize error handling:

```go
OnAPIError: auth.OnAPIErrorConfig{
    Throw:    false,
    ErrorURL: "/api/auth/error",
    OnError: func(err *apierror.Error, ctx *auth.Context) {
        log.Printf("auth error: %s", err.Code)
    },
},
```

Next: [CLI →](cli.md)
