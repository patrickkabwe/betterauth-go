# Rate limiting

Per-path rate limiting is built into the router. Enable it with
`auth.Config.RateLimit`.

## Basic setup

```go
RateLimit: auth.RateLimitConfig{
    Enabled: true,
    Window:  time.Minute, // default when zero
    Max:     100,          // requests per window per client
},
```

When exceeded, the server responds with **429 Too Many Requests**.

## Custom rules

Override limits for sensitive paths (relative to `BasePath`):

```go
CustomRules: map[string]auth.RateLimitRule{
    "/sign-in/*":     {Window: time.Minute, Max: 10},
    "/sign-up/email": {Window: time.Minute, Max: 5},
},
```

Use a `*` suffix for prefix matching (e.g. `/sign-in/*` matches
`/sign-in/email` and `/sign-in/social`).

## Storage

By default counters live in memory (per process). For multi-instance deployments,
implement `RateLimitStorage`:

```go
type RateLimitStorage interface {
    Incr(ctx context.Context, key string, window time.Duration) (count int, err error)
}
```

Pass your Redis or database-backed implementation via `RateLimit.Storage`.

## Client identification

Rate limits are keyed by client IP. When behind a proxy, configure trusted
headers:

```go
Advanced: auth.AdvancedConfig{
    IPAddressHeaders: []string{"X-Forwarded-For", "X-Real-IP"},
},
```

Next: [Security & middleware →](security.md)
