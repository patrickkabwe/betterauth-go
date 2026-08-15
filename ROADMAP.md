# Roadmap

Feature parity tracker for the Go Better Auth implementation against the official [Better Auth](https://better-auth.com) TypeScript server (v1.6.x).

**Legend**

| Status | Meaning |
|--------|---------|
| ✅ | Implemented and tested |
| 🟡 | Partially implemented |
| ⬜ | Not started |
| 🔮 | Future / lower priority |

Reference: [Better Auth docs](https://better-auth.com/docs) · [GitHub](https://github.com/better-auth/better-auth)

---

## Progress summary

| Area | Done | Partial | Planned |
|------|------|---------|---------|
| Core email/password auth | 9 | 0 | 0 |
| Session management | 17 | 1 | 0 |
| User & account management | 15 | 0 | 0 |
| Social / OAuth | 21 | 0 | 21 |
| Plugins (core package) | 31 | 0 | 0 |
| Extended packages | 7 | 1 | 2 |
| Infrastructure | 23 | 2 | 5 |
| Client compatibility | 7 | 0 | 2 |

---

## 1. Core authentication

### Email & password

| Feature | Endpoint / API | Status | Notes |
|---------|----------------|--------|-------|
| Sign up with email | `POST /sign-up/email` | ✅ | Name, email, password, image, rememberMe |
| Sign in with email | `POST /sign-in/email` | ✅ | Callback URL redirect header |
| Sign out | `POST /sign-out` | ✅ | Clears session cookie |
| Require email verification on sign-in | — | ✅ | `emailAndPassword.requireEmailVerification` |
| Disable sign-up | — | ✅ | `DisableSignUp` option |
| Auto sign-in after sign-up | — | ✅ | `EmailAndPassword.AutoSignIn` config |
| Custom password hash/verify | — | ✅ | Pluggable `Hasher` interface |
| Password length validation | — | ✅ | Min 8 / max 128 (configurable) |
| Enumeration protection on sign-up | — | ✅ | Synthetic user response for duplicates |

### Email verification

| Feature | Endpoint | Status |
|---------|----------|--------|
| Send verification email | `POST /send-verification-email` | ✅ |
| Verify email | `GET /verify-email` | ✅ |
| Email verification token | — | ✅ | JWT HS256 |

### Password reset

| Feature | Endpoint | Status |
|---------|----------|--------|
| Request password reset | `POST /request-password-reset` | ✅ |
| Reset password callback | `GET /reset-password/:token` | ✅ |
| Reset password | `POST /reset-password` | ✅ |
| Verify password (authenticated) | `POST /verify-password` | ✅ |

---

## 2. Session management

| Feature | Endpoint / behavior | Status | Notes |
|---------|---------------------|--------|-------|
| Get session | `GET /get-session` | ✅ | Returns `{ session, user }` or `null` |
| Get session (POST refresh) | `POST /get-session` | ✅ | Requires `deferSessionRefresh`; refreshes when `needsRefresh` |
| List sessions | `GET /list-sessions` | ✅ | Active sessions only |
| Revoke session | `POST /revoke-session` | ✅ | By token |
| Revoke all sessions | `POST /revoke-sessions` | ✅ | |
| Revoke other sessions | `POST /revoke-other-sessions` | ✅ | Keeps current session |
| Update session | `POST /update-session` | ✅ | Additional session fields |
| Session cookie signing | `better-auth.session_token` | ✅ | HMAC-SHA256, `value.signature` |
| Remember me / dont_remember | `better-auth.dont_remember` | ✅ | Cookie set; session expiry differs |
| Cookie cache (`session_data`) | — | ✅ | Compact strategy (JWT/JWE planned) |
| Session refresh / updateAge | — | ✅ | Throttled DB writes on get-session |
| Defer session refresh | — | ✅ | GET returns `needsRefresh`; POST refreshes |
| Disable session refresh | — | ✅ | Config + `?disableRefresh=true` query |
| Disable cookie cache | — | ✅ | `?disableCookieCache=true` for sensitive ops |
| Fresh session check | — | ✅ | `freshAge` config; enforced on delete-user |
| Multi-session cookies | — | ✅ | Implemented as `multi-session` plugin (see §6) |
| Secondary storage (Redis) | — | 🟡 | `SecondaryStorage` interface defined; wiring optional |
| IP address / user agent tracking | — | ✅ | Stored on create and refreshed on update |

---

## 3. User management

| Feature | Endpoint | Status |
|---------|----------|--------|
| Update user | `POST /update-user` | ✅ |
| Change email | `POST /change-email` | ✅ |
| Change password | `POST /change-password` | ✅ |
| Set password (OAuth-only users) | `POST /set-password` | ✅ |
| Delete user | `POST /delete-user` | ✅ |
| Delete user callback | `GET /delete-user/callback` | ✅ |
| Additional user fields | — | ✅ |
| Custom session response | Plugin: `custom-session` | ✅ |

---

## 4. Account management

| Feature | Endpoint | Status |
|---------|----------|--------|
| List linked accounts | `GET /list-accounts` | ✅ |
| Link social account | `POST /link-social` | ✅ |
| Unlink account | `POST /unlink-account` | ✅ |
| Get access token (provider) | `POST /get-access-token` | ✅ |
| Refresh token (provider) | `POST /refresh-token` | ✅ |
| Account info | `GET /account-info` | ✅ |
| Account linking config | — | ✅ | `trustedProviders`, `allowDifferentEmails`, `allowUnlinkingAll` |

---

## 5. Social / OAuth providers

### Core OAuth flow

| Feature | Endpoint | Status |
|---------|----------|--------|
| Sign in with social | `POST /sign-in/social` | ✅ |
| OAuth callback | `GET /callback/:provider` | ✅ |
| OAuth state (verification store) | — | ✅ |
| OAuth proxy (dev) | Plugin: `oauth-proxy` | ✅ |
| Generic OAuth | Plugin: `generic-oauth` | ✅ |
| Sign in with ID token | `POST /sign-in/social` | ✅ | Native provider `idToken` branch |

### Built-in providers (35)

| Provider | Status |
|----------|--------|
| Apple | ✅ |
| Atlassian | ⬜ |
| AWS Cognito | ⬜ |
| Discord | ✅ |
| Dropbox | ✅ |
| Facebook | ✅ |
| Figma | ✅ |
| GitHub | ✅ |
| GitLab | ✅ |
| Google | ✅ |
| Hugging Face | ⬜ |
| Kakao | ⬜ |
| Kick | ⬜ |
| LINE | ⬜ |
| Linear | ✅ |
| LinkedIn | ✅ |
| Microsoft Entra ID | ✅ |
| Naver | ⬜ |
| Notion | ✅ |
| Paybin | ⬜ |
| PayPal | ⬜ |
| Polar | ⬜ |
| Railway | ⬜ |
| Reddit | ✅ |
| Roblox | ⬜ |
| Salesforce | ⬜ |
| Slack | ✅ |
| Spotify | ✅ |
| TikTok | ⬜ |
| Twitch | ✅ |
| Twitter / X | ✅ |
| Vercel | ✅ |
| VK | ⬜ |
| WeChat | ⬜ |
| Zoom | ⬜ |

---

## 6. Plugins (better-auth package)

| Plugin | ID | Status | Description |
|--------|-----|--------|-------------|
| Admin | `admin` | ✅ | User management, roles, ban, impersonate |
| Anonymous | `anonymous` | ✅ | Guest / anonymous sessions |
| API Key | `api-key` | ✅ | Database-backed keys, verification, optional session auth |
| Bearer | `bearer` | ✅ | Session token via `Authorization` header |
| Captcha | `captcha` | ✅ | Turnstile, reCAPTCHA, hCaptcha, CaptchaFox |
| Custom Session | `custom-session` | ✅ | Transform session response |
| Device Authorization | `device-authorization` | ✅ | OAuth 2.0 device code flow |
| Email OTP | `email-otp` | ✅ | One-time password via email |
| Generic OAuth | `generic-oauth` | ✅ | Custom OIDC/OAuth2 providers |
| Have I Been Pwned | `have-i-been-pwned` | ✅ | Breached password check |
| JWT | `jwt` | ✅ | JWT session tokens + JWKS |
| Last Login Method | `last-login-method` | ✅ | Track how user last signed in |
| Magic Link | `magic-link` | ✅ | Passwordless email link |
| MCP | `mcp` | ✅ | Model Context Protocol auth |
| Multi Session | `multi-session` | ✅ | Multiple concurrent sessions per device |
| OAuth Provider | `oauth-provider` | ✅ | OAuth/OIDC provider metadata, authorization, token, userinfo, and registration routes |
| OAuth Proxy | `oauth-proxy` | ✅ | Dev OAuth callback proxy |
| OIDC Provider | `oidc-provider` | ✅ | Act as OIDC identity provider |
| One Tap | `one-tap` | ✅ | Google One Tap sign-in |
| One-Time Token | `one-time-token` | ✅ | Single-use cross-domain tokens |
| OpenAPI | `open-api` | ✅ | Auto-generated OpenAPI spec |
| Organization | `organization` | ✅ | Teams, members, roles, invitations |
| Phone Number | `phone-number` | ✅ | SMS OTP sign-in |
| SIWE | `siwe` | ✅ | Sign-In with Ethereum |
| Two Factor | `two-factor` | ✅ | TOTP, OTP, backup codes |
| Username | `username` | ✅ | Username + display username |

### Two-factor sub-plugins

| Sub-plugin | ID | Status |
|------------|-----|--------|
| TOTP | `totp` | ✅ |
| OTP (email/SMS) | `otp` | ✅ |
| Backup codes | `backup_code` | ✅ |

---

## 7. Extended packages

Separate npm packages in the Better Auth monorepo.

| Package | Status | Description |
|---------|--------|-------------|
| `@better-auth/passkey` | ✅ | WebAuthn / passkey registration, sign-in, and management |
| `@better-auth/stripe` | ✅ | Checkout, billing portal, subscription routes, webhooks |
| `@better-auth/sso` | ✅ | SAML provider registry, SP metadata, redirect sign-in, ACS session creation |
| `@better-auth/scim` | ✅ | SCIM user provisioning |
| `@better-auth/oauth-provider` | 🟡 | OAuth/OIDC metadata and core authorization-code routes; advanced consent/introspection/revocation pending |
| `@better-auth/api-key` | ✅ | API key management plugin |
| `@better-auth/expo` | ⬜ | React Native / Expo client helpers |
| `@better-auth/electron` | ⬜ | Electron desktop auth |
| `@better-auth/i18n` | ✅ | Translated error messages |
| `@better-auth/cli` | ✅ | `betterauth-go` binary + `cli/core` package: `generate`, `migrate`, `secret`, `info`, `init`; schema is feature-scoped to enabled plugins |

---

## 8. Infrastructure & server features

### Storage & adapters

| Feature | Status | Notes |
|---------|--------|-------|
| Store interface | ✅ | `store.Store` |
| In-memory adapter | ✅ | `store/memory` |
| PostgreSQL adapter | ✅ | `store/sql` (driver-agnostic, `sqlstore.Postgres`) |
| SQLite adapter | ✅ | `store/sql` (`sqlstore.SQLite`); tested with modernc.org/sqlite |
| MySQL adapter | ✅ | `store/sql` (`sqlstore.MySQL`) |
| MongoDB adapter | ⬜ | |
| Redis secondary storage | 🟡 | `SecondaryStorage` + `RateLimitStorage` interfaces; no Redis impl shipped |

### Security & middleware

| Feature | Status | Notes |
|---------|--------|-------|
| CORS (trusted origins) | ✅ | Wildcard patterns (`https://*.example.com`, `*`) |
| CSRF / origin check | ✅ | Origin/Referer check on state-changing requests; `advanced.disableCSRFCheck` |
| Rate limiting | ✅ | Per-path rules + pluggable `RateLimitStorage` (in-memory default) |
| Signed cookies | ✅ | Session + dont_remember |
| Secure cookie prefix | ✅ | `__Secure-` when `useSecureCookies` |
| Cross-subdomain cookies | ✅ | `advanced.crossSubDomainCookies` (shared Domain) |
| Custom cookie names/attrs | ✅ | `advanced.cookies` name overrides + `Partitioned` / SameSite attrs |
| Secret rotation (versioned) | ✅ | `OldSecrets`: sign with primary, verify against any |
| IP tracking headers | ✅ | Configurable `ipAddressHeaders` + `disableIpTracking` |

### Hooks & extensibility

| Feature | Status |
|---------|--------|
| Database hooks (before/after) | ✅ |
| User create/update hooks | ✅ |
| Session create/delete hooks | ✅ |
| Auth middleware hooks | ✅ |
| `onAPIError` custom error page | ✅ |
| Plugin system (Go equivalent) | ✅ |
| Custom ID generator | 🟡 |
| Background tasks | ⬜ |
| Telemetry / OpenTelemetry | ⬜ |

### Server API

| Feature | Status | Notes |
|---------|--------|-------|
| HTTP handler | ✅ | `auth.Handler()` |
| `auth.api.*` server-side API | 🟡 | Helper methods on `*Auth` (`NewSession`, `HashPassword`, verifications…); no full typed route API |
| Framework helpers | ⬜ | `toNodeHandler`, `toNextJsHandler`, etc. |
| Error page (`GET /error`) | ✅ | `handleErrorPage`; `onAPIError.ErrorURL` redirect |
| Health check (`GET /ok`) | ✅ | |

---

## 9. Client compatibility

| Client | Status | Notes |
|--------|--------|-------|
| `better-auth/react` | ✅ | Plugins + bearer + `inferAdditionalFields` in `examples/client` |
| `better-auth/vue` | ✅ | `examples/client-vue` |
| `better-auth/svelte` | ✅ | `examples/client-svelte` |
| `better-auth/solid` | ⬜ | Same endpoints; no example yet |
| `better-auth/client` | ✅ | Go `client` package + TS `better-auth/client` |
| `better-auth/lynx` | ⬜ | |
| Client plugins (infer types) | ✅ | `GET /client-schema` + `scripts/generate-client-types.mjs` |
| Expo client | ✅ | `examples/expo` with bearer + SecureStore |
| Bearer token header | ✅ | `plugins.Bearer`, `set-auth-token`, CORS expose |

### Example apps

| Example | Status |
|---------|--------|
| Go server (`examples/basic`) | ✅ |
| React client (`examples/client`) | ✅ |
| Vue client (`examples/client-vue`) | ✅ |
| Svelte client (`examples/client-svelte`) | ✅ |
| Expo client (`examples/expo`) | ✅ |

---

## 10. Configuration parity

Options from the TypeScript `betterAuth({ ... })` config.

| Option | Status |
|--------|--------|
| `secret` | ✅ |
| `baseURL` | ✅ |
| `basePath` | ✅ | Default `/api/auth`; mount responsibility on user |
| `appName` | ✅ | Exposed in `/client-schema` |
| `database` / `store` | ✅ | Go `Store` interface + `DatabaseConfig` |
| `trustedOrigins` | ✅ |
| `emailAndPassword` | ✅ | Full option surface |
| `socialProviders` | ✅ | Map + Google/GitHub helpers + standard OAuth provider constructors |
| `session` | ✅ | ExpiresIn, updateAge, freshAge, cookieCache, defer refresh |
| `user` / `account` | ✅ | Additional fields, change/delete email, linking |
| `advanced` | ✅ | Cookie prefix/names/attrs, secure cookies, cross-subdomain, IP headers, CSRF, trailing slashes |
| `rateLimit` | ✅ | Enforced; per-path rules + pluggable storage |
| `secondaryStorage` | 🟡 | Interface defined; wiring optional |
| `plugins` | ✅ | `Config.Plugins []Plugin` |
| `hooks` | ✅ | `HooksConfig` before/after on `Context` |
| `databaseHooks` | ✅ | Invoked around user/session create/update/delete via store wrapper |
| `onAPIError` | ✅ | `OnError` callback on `WriteError` |
| `disabledPaths` | ✅ | Per-path 404 |

---

## Suggested implementation phases

### Phase 1 — Core parity ✅ (complete)

- [x] Email sign-up / sign-in / sign-out
- [x] Get session + session listing / revocation
- [x] Signed cookies + scrypt passwords
- [x] CORS + example React client
- [x] Email verification
- [x] Password reset flow
- [x] Update user / change password / delete user
- [x] Session management (cookie cache, defer refresh, freshAge)

### Phase 2 — Production readiness ✅ (complete)

- [x] PostgreSQL / SQLite / MySQL adapters (`store/sql`, driver-agnostic)
- [x] CSRF + origin validation (with wildcard trusted origins)
- [x] Rate limiting (per-path rules + pluggable storage)
- [x] Cookie cache (`session_data`)
- [x] Session refresh / `updateAge`
- [x] Database hooks (user + session, before/after)
- [x] Bearer + JWT plugins (for non-cookie clients)
- [x] Secret rotation, cross-subdomain & custom cookies, configurable IP headers

### Phase 3 — OAuth & passwordless

- [x] OAuth core (`/sign-in/social`, `/callback/:provider`)
- [x] Google + GitHub providers (highest demand)
- [x] Standard OAuth providers: Discord, Dropbox, Figma, GitLab, LinkedIn, Microsoft Entra ID, Notion, Slack, Spotify, Twitch, Vercel
- [x] Generic OAuth plugin
- [x] Magic link
- [x] Email OTP

### Phase 4 — Advanced auth

- [x] Two-factor (TOTP + backup codes)
- [x] Passkeys (WebAuthn)
- [x] Username plugin
- [x] Phone number OTP
- [x] Anonymous sessions

### Phase 5 — Multi-tenant & enterprise

- [x] Organization plugin (teams, invites, roles)
- [x] Admin plugin
- [x] SSO (SAML + OIDC)
- [x] OIDC provider
- [x] SCIM provisioning

### Phase 6 — Ecosystem

- [x] API keys (separate `@better-auth/api-key` package)
- [x] Stripe billing
- [x] MCP auth
- [x] i18n error messages
- [x] OpenAPI spec generation
- [x] CLI (`generate` / `migrate` / `secret` / `info` / `init`)
- [ ] Go server-side `api` object (typed handlers)

---

## How to contribute

1. Pick an item marked ⬜ from the current phase.
2. Match the TypeScript endpoint path, request/response shape, and cookie behavior exactly — clients depend on it.
3. Add tests in `auth/handler_test.go` (or package-specific tests).
4. Update this file: change status and add notes.

When in doubt, read the reference implementation:

```
https://github.com/better-auth/better-auth/tree/main/packages/better-auth/src/api/routes
```

---

*Last updated: 2026-08-16 · Better Auth reference version: 1.6.x · Current focus: Go server-side `api` object, MongoDB & Redis adapters, and remaining long-tail OAuth providers.*
