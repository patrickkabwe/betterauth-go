# Configuration reference

Complete reference for `auth.Config` and nested options. Maps to the TypeScript
`betterAuth({ … })` API.

## Top-level

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Secret` | `string` | — | **Required.** Signs cookies and tokens |
| `OldSecrets` | `[]string` | `nil` | Previous secrets for rotation |
| `BaseURL` | `string` | `""` | Public URL; added to trusted origins |
| `BasePath` | `string` | `"/api/auth"` | Route prefix |
| `Store` | `store.Store` | — | **Required.** Persistence layer |
| `TrustedOrigins` | `[]string` | `nil` | CORS + CSRF; wildcards supported |
| `CookiePrefix` | `string` | `"better-auth"` | Cookie name prefix |
| `UseSecureCookies` | `bool` | `false` | Secure flag + `__Secure-` prefix |
| `DisableSignUp` | `bool` | `false` | Block new registrations |
| `AppName` | `string` | `"Better Auth"` | Shown in emails/UI |
| `Hasher` | `crypto.Hasher` | scrypt | Password hash/verify |
| `Plugins` | `[]Plugin` | `nil` | Enabled plugins |
| `SocialProviders` | `map[string]SocialProvider` | `nil` | Custom provider map |
| `DisabledPaths` | `[]string` | `nil` | Routes to disable |

## EmailAndPassword

| Field | Default | Description |
|-------|---------|-------------|
| `Enabled` | `true`* | Email/password auth |
| `RequireEmailVerification` | `false` | Block sign-in until verified |
| `AutoSignIn` | `true` | Sign in after sign-up |
| `MinPasswordLength` | `8` | Minimum password length |
| `MaxPasswordLength` | `128` | Maximum password length |
| `SendResetPassword` | `nil` | Email callback for reset links |
| `ResetPasswordTokenExpiresIn` | `1h` | Reset token TTL |
| `RevokeSessionsOnPasswordReset` | `false` | Revoke all sessions on reset |

\* Enabled by default unless explicitly disabled without a reset handler.

## EmailVerification

| Field | Default | Description |
|-------|---------|-------------|
| `SendVerificationEmail` | `nil` | Verification email callback |
| `SendOnSignIn` | `false` | Re-send on each sign-in |
| `ExpiresIn` | `1h` | Verification token TTL |

## Session

| Field | Default | Description |
|-------|---------|-------------|
| `ExpiresIn` | `7d` | Session lifetime |
| `UpdateAge` | `24h` | Min interval between DB refreshes |
| `DeferSessionRefresh` | `false` | GET returns `needsRefresh`; POST refreshes |
| `DisableSessionRefresh` | `false` | Never refresh sessions |
| `FreshAge` | `24h` | Fresh session window; `0` disables |
| `CookieCache.Enabled` | `false` | Compact `session_data` cache |
| `CookieCache.MaxAge` | `5m` | Cache cookie TTL |
| `CookieCache.Strategy` | `"compact"` | Cache encoding |

## User

| Field | Description |
|-------|-------------|
| `AdditionalFields` | Custom user fields persisted in JSON `additional` |
| `ChangeEmail` | Change-email flow config |
| `DeleteUser` | Account deletion config |

## Account

| Field | Description |
|-------|-------------|
| `AccountLinking.Enabled` | Allow linking providers (default `true`) |
| `AccountLinking.TrustedProviders` | Providers allowed for linking |
| `AccountLinking.AllowDifferentEmails` | Link providers with different emails |
| `AccountLinking.AllowUnlinkingAll` | Allow removing last linked account |

## Google / GitHub

| Field | Description |
|-------|-------------|
| `ClientID` | OAuth client ID |
| `ClientSecret` | OAuth client secret |
| `Scopes` | Extra OAuth scopes |
| `Disabled` | Disable provider |

## Advanced

| Field | Description |
|-------|-------------|
| `UseSecureCookies` | HTTPS-only cookies |
| `CookiePrefix` | Override top-level prefix |
| `IPAddressHeaders` | Proxy headers for client IP |
| `DisableIPTracking` | Skip IP/UA on sessions |
| `DisableCSRFCheck` | Disable origin CSRF check |
| `SkipTrailingSlashes` | Normalize trailing slashes |
| `GenerateID` | Custom ID generator |
| `CrossSubDomainCookies` | Shared cookie domain |
| `CookieAttributes` | SameSite, Partitioned |
| `Cookies` | Per-cookie name overrides |

## RateLimit

| Field | Default | Description |
|-------|---------|-------------|
| `Enabled` | `false` | Enable rate limiting |
| `Window` | `60s` | Sliding window |
| `Max` | `100` | Max requests per window |
| `Storage` | in-memory | Persistent counter store |
| `CustomRules` | `nil` | Per-path overrides |

## Hooks

| Field | Description |
|-------|-------------|
| `Hooks.Before` | Request middleware; return `false` to abort |
| `Hooks.After` | Post-handler callback |
| `DatabaseHooks.User` | User CRUD hooks |
| `DatabaseHooks.Session` | Session CRUD hooks |

## OnAPIError

| Field | Default | Description |
|-------|---------|-------------|
| `Throw` | `false` | Propagate errors |
| `ErrorURL` | `{BasePath}/error` | Redirect target |
| `OnError` | `nil` | Error callback |

## SecondaryStorage

Optional Redis-like interface for session/cache offload. See
[session management](../concepts/session-management.md).

---

See also: [API endpoints](api-endpoints.md) · [Basic usage](../basic-usage.md)
