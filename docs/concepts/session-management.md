# Session management

Sessions are stored in your `Store`, exposed to clients as signed cookies, and
refreshed according to `auth.Config.Session`.

## Get session

```bash
# Browser: session cookie sent automatically
curl http://localhost:8080/api/auth/get-session

# Bearer token (with bearer plugin)
curl http://localhost:8080/api/auth/get-session \
  -H 'Authorization: Bearer <token>'
```

Returns `{ session, user }` or `null` when unauthenticated.

## Configuration

```go
Session: auth.SessionConfig{
    ExpiresIn:             7 * 24 * time.Hour, // default
    UpdateAge:             24 * time.Hour,       // throttle DB refresh writes
    DeferSessionRefresh:   false,
    DisableSessionRefresh: false,
    FreshAge:              durationPtr(24 * time.Hour), // nil = default; 0 = disable

    CookieCache: auth.CookieCacheConfig{
        Enabled:  true,
        MaxAge:   5 * time.Minute,
        Strategy: "compact", // JWT/JWE reserved for future
    },
},
```

## Remember me

Sign-in accepts `rememberMe` (default `true`). When `false`, the server sets a
`dont_remember` cookie and uses a shorter session lifetime (24 hours by
default).

## Session refresh

On each `GET /get-session`, the server may update `updatedAt` and extend
`expiresAt` when `UpdateAge` has elapsed since the last refresh.

**Deferred refresh:** set `DeferSessionRefresh: true`. Then:

- `GET /get-session` returns the session with `needsRefresh: true` when an
  update is due (no DB write).
- `POST /get-session` performs the refresh.

Disable entirely with `DisableSessionRefresh: true` or the query parameter
`?disableRefresh=true`.

## Fresh sessions

Some sensitive operations (e.g. delete user) require a **fresh** session —
created within `FreshAge` (default 24h). Set `FreshAge` to `0` to disable
freshness checks.

## Cookie cache

When enabled, a compact `session_data` cookie caches session + user payload to
reduce database reads. Pass `?disableCookieCache=true` on sensitive endpoints to
force a DB lookup.

## Multi-session

The **multi-session** plugin allows multiple concurrent sessions per user with
separate cookies. See [Plugin overview](../plugins/overview.md).

## Revoke sessions

| Endpoint | Description |
|----------|-------------|
| GET `/list-sessions` | All active sessions for the current user |
| POST `/revoke-session` | Revoke by token |
| POST `/revoke-sessions` | Revoke all sessions |
| POST `/revoke-other-sessions` | Revoke all except current |
| POST `/update-session` | Update additional session fields |

## Secondary storage

`SecondaryStorage` (Redis-like interface) is defined for session/cache offload.
Wiring is optional — see [ROADMAP](../../ROADMAP.md).

Next: [Cookies →](cookies.md)
