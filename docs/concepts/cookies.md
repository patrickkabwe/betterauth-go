# Cookies

Session state is carried in signed HTTP cookies compatible with the TypeScript
Better Auth server.

## Cookie names

| Logical key | Default name | Purpose |
|-------------|--------------|---------|
| `session_token` | `better-auth.session_token` | Signed session token |
| `dont_remember` | `better-auth.dont_remember` | Short-lived session flag |
| `session_data` | `better-auth.session_data` | Compact session cache |

With `UseSecureCookies: true`, names are prefixed with `__Secure-`.

## Signing

Cookies use HMAC-SHA256 in the `value.signature` format (base64), matching
`better-call`'s `serializeSignedCookie`. Verification tries `Secret` first, then
`OldSecrets` for zero-downtime rotation.

## Configuration

```go
auth.Config{
    CookiePrefix:     "my-app", // → my-app.session_token
    UseSecureCookies: true,     // HTTPS only; __Secure- prefix

    Advanced: auth.AdvancedConfig{
        UseSecureCookies: true,
        CookiePrefix:     "my-app",

        CrossSubDomainCookies: auth.CrossSubDomainConfig{
            Enabled: true,
            Domain:  ".example.com", // share across subdomains
        },

        CookieAttributes: auth.CookieAttributes{
            SameSite:    http.SameSiteStrictMode,
            Partitioned: true, // CHIPS partitioned cookies
        },

        Cookies: map[string]auth.CookieOverride{
            "session_token": {Name: "my_session"},
        },
    },
}
```

Custom names in `Advanced.Cookies` bypass the prefix and `__Secure-` logic.

## Cross-subdomain sessions

Enable `CrossSubDomainCookies` when your API and frontend live on different
subdomains (e.g. `api.example.com` and `app.example.com`). Set `Domain` to
`.example.com` and use `UseSecureCookies: true` in production.

## Bearer tokens

The **bearer** plugin exposes session tokens via the `set-auth-token` response
header for non-cookie clients (mobile, API). See
[Integrations → Clients](../integrations/clients.md).

Next: [Hooks →](hooks.md)
