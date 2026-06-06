# Errors

API errors follow the Better Auth JSON shape so clients handle them uniformly.

## Response format

```json
{
  "code": "INVALID_EMAIL_OR_PASSWORD",
  "message": "Invalid email or password"
}
```

HTTP status codes match semantics (400 validation, 401 unauthorized, 403
forbidden, 404 not found, 429 rate limited, 500 internal).

## Common codes

| Code | HTTP | When |
|------|------|------|
| `INVALID_EMAIL_OR_PASSWORD` | 400 | Bad credentials |
| `EMAIL_NOT_VERIFIED` | 403 | Sign-in blocked until verified |
| `UNAUTHORIZED` | 401 | Missing or invalid session |
| `SESSION_NOT_FRESH` | 403 | Sensitive action needs fresh session |
| `SESSION_EXPIRED` | 401 | Session TTL exceeded |
| `INVALID_ORIGIN` | 403 | CSRF / untrusted Origin |
| `INVALID_TOKEN` | 400 | Bad verification or reset token |
| `FEATURE_NOT_ENABLED` | 400 | Plugin or feature not configured |
| `EXT_STORE_REQUIRED` | 500 | Plugin needs ExtStore on your Store |
| `FORBIDDEN` | 403 | Admin plugin: insufficient role |

See the [full error code reference](../reference/error-codes.md).

## Custom error handling

```go
OnAPIError: auth.OnAPIErrorConfig{
    ErrorURL: "/api/auth/error",
    OnError: func(err *apierror.Error, ctx *auth.Context) {
        log.Printf("%s: %s", err.Code, err.Message)
    },
},
```

`GET /error` renders a redirect target for OAuth and email flows when
`errorCallbackURL` is not provided.

## Go package errors

Configuration errors from `auth.New`:

| Error | Cause |
|-------|-------|
| `errors.ErrSecretRequired` | Missing `Secret` |
| `errors.ErrStoreRequired` | Missing `Store` |

Store layer:

| Error | Cause |
|-------|-------|
| `errors.ErrNotFound` | Record not found |
| `errors.ErrAlreadyExists` | Duplicate record |

Next: [Production guide →](../guides/production.md)
