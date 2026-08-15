# Production checklist

Deploying better-auth.go to production mirrors Better Auth best practices with
Go-specific considerations.

## Environment variables

| Variable | Used for |
|----------|----------|
| `BETTER_AUTH_SECRET` | `auth.Config.Secret` (32+ chars, high entropy) |
| `OLD_SECRETS` | Comma-separated previous secrets during rotation |
| `BASE_URL` | Public API URL (`https://api.example.com`) |
| `DATABASE_URL` | SQL connection string |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub OAuth |

Generate a secret:

```bash
betterauth-go secret
```

Never commit secrets to source control.

## HTTPS and cookies

```go
auth.Config{
    BaseURL:          "https://api.example.com",
    UseSecureCookies: true,
    TrustedOrigins:   []string{"https://app.example.com"},

    Advanced: auth.AdvancedConfig{
        UseSecureCookies: true,
        CrossSubDomainCookies: auth.CrossSubDomainConfig{
            Enabled: true,
            Domain:  ".example.com",
        },
        IPAddressHeaders: []string{"X-Forwarded-For", "X-Real-IP"},
    },
}
```

## Database

Use the SQL adapter with your production driver:

```go
db, _ := sql.Open("postgres", os.Getenv("DATABASE_URL"))
st := sqlstore.New(db, sqlstore.Postgres)
_ = st.Migrate(ctx)
```

Run migrations in CI/CD (embedded binary that imports `cli/core`):

```bash
go build -o myauth-cli .
./myauth-cli migrate
```

## Rate limiting

Enable with stricter rules on auth endpoints:

```go
RateLimit: auth.RateLimitConfig{
    Enabled: true,
    Window:  time.Minute,
    Max:     100,
    CustomRules: map[string]auth.RateLimitRule{
        "/sign-in/*":     {Max: 10, Window: time.Minute},
        "/sign-up/email": {Max: 5, Window: time.Minute},
    },
    Storage: redisRateLimitStorage{}, // multi-instance
},
```

## CSRF and CORS

Always set `TrustedOrigins` to your frontend origin(s). Wildcards like
`https://*.example.com` are supported.

Do not disable CSRF unless you fully understand the trade-off (API-only
bearer-token clients are unaffected).

## Secret rotation

1. Add current secret to `OldSecrets`.
2. Set new value as `Secret`.
3. Deploy — existing cookies keep working.
4. After all sessions expire, remove the old secret from `OldSecrets`.

## Health check

Monitor `GET /api/auth/ok` → `{"ok":true}`.

## Logging

Use `DatabaseHooks` and `OnAPIError.OnError` for audit trails. Avoid logging
passwords, tokens, or full session cookies.

Next: [Examples →](examples.md)
