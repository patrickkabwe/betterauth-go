# API endpoints

All routes are relative to `BasePath` (default `/api/auth`). Plugin routes are
included when the plugin is enabled.

## Core

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ok` | — | Health check |
| GET | `/client-schema` | — | Client type inference schema |
| GET | `/error` | — | Error page redirect target |

## Session

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/get-session` | optional | Current session + user |
| POST | `/get-session` | optional | Refresh session (with defer) |
| GET | `/list-sessions` | ✅ | List active sessions |
| POST | `/update-session` | ✅ | Update session fields |
| POST | `/revoke-session` | ✅ | Revoke by token |
| POST | `/revoke-sessions` | ✅ | Revoke all |
| POST | `/revoke-other-sessions` | ✅ | Revoke all except current |
| POST | `/sign-out` | optional | End session |

## Email & password

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/sign-up/email` | — | Register |
| POST | `/sign-in/email` | — | Sign in |
| POST | `/send-verification-email` | optional | Send verification |
| GET | `/verify-email` | — | Verify from link |
| POST | `/request-password-reset` | — | Start reset |
| GET | `/reset-password/{token}` | — | Reset landing |
| POST | `/reset-password` | — | Set new password |
| POST | `/verify-password` | ✅ | Verify current password |

## Social OAuth

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/sign-in/social` | — | Start OAuth flow |
| GET | `/callback/{provider}` | — | OAuth callback |
| POST | `/link-social` | ✅ | Link provider |
| POST | `/unlink-account` | ✅ | Unlink provider |
| GET | `/list-accounts` | ✅ | Linked accounts |
| GET | `/account-info` | ✅ | Provider account info |
| POST | `/get-access-token` | ✅ | OAuth access token |
| POST | `/refresh-token` | ✅ | Refresh OAuth token |

## User management

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/update-user` | ✅ | Update profile |
| POST | `/change-email` | ✅ | Change email |
| POST | `/change-password` | ✅ | Change password |
| POST | `/set-password` | ✅ | Set password (OAuth-only users) |
| POST | `/delete-user` | ✅ | Delete account |
| GET | `/delete-user/callback` | — | Deletion confirmation |

## Plugin routes

Plugin endpoints are registered dynamically. Common examples:

| Plugin | Example paths |
|--------|----------------|
| `username` | `/sign-in/username`, `/is-username-available` |
| `phone-number` | `/sign-in/phone-number`, `/phone-number/request-password-reset`, `/phone-number/reset-password` |
| `magic-link` | `/sign-in/magic-link`, `/magic-link/verify` |
| `email-otp` | `/email-otp/send-verification-otp`, `/sign-in/email-otp`, `/email-otp/reset-password` |
| `organization` | `/organization/create`, `/organization/list`, `/organization/invite-member` |
| `two-factor` | `/two-factor/enable`, `/two-factor/verify-totp`, `/two-factor/send-otp`, `/two-factor/verify-otp` |
| `admin` | `/admin/list-users`, `/admin/impersonate-user` |
| `open-api` | `/reference` (OpenAPI spec) |

For the full route list with your plugin set, call `GET /client-schema` or
enable the **open-api** plugin.

## Query parameters

| Parameter | Endpoint | Description |
|-----------|----------|-------------|
| `disableRefresh=true` | `/get-session` | Skip session refresh |
| `disableCookieCache=true` | sensitive routes | Force DB session lookup |

## Response format

JSON responses match Better Auth client expectations. Errors return:

```json
{
  "code": "INVALID_EMAIL_OR_PASSWORD",
  "message": "Invalid email or password"
}
```

---

Back to: [Configuration reference](configuration.md) · [Introduction](../introduction.md)
