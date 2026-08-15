# Migrating from TypeScript Better Auth

Use this guide when replacing a Node `better-auth` server with better-auth.go
while keeping existing clients.

## What stays the same

- **Client SDKs** — `better-auth/react`, `/vue`, `/svelte`, `/client` unchanged
- **Wire format** — same endpoints, JSON shapes, cookie names, signing
- **Password hashes** — scrypt `salt:key` compatible
- **Session cookies** — HMAC-SHA256 `value.signature` format
- **24 core plugins** — same IDs and routes (when enabled)
- **CLI workflow** — `generate`, `migrate`, `secret`, `init`, `info`

## What changes

| TypeScript | Go |
|------------|-----|
| `betterAuth({ … })` | `auth.New(auth.Config{ … })` |
| Kysely / Drizzle / Prisma adapter | `store/sql` or custom `Store` |
| Plugin fields as DB columns | Same JS-compatible columns for supported plugins |
| `npx @better-auth/cli --config auth.ts` | Embed `core.Run` with `*auth.Auth` |
| 35+ built-in OAuth providers | Google, GitHub, Discord, Dropbox, Figma, GitLab, LinkedIn, Microsoft, Notion, Slack, Spotify, Twitch, Vercel + generic-oauth plugin |
| `auth.api.*` typed routes | Partial helpers on `*auth.Auth` |
| Framework handlers (`toNextJsHandler`) | Mount `http.Handler` manually |

## Migration steps

### 1. Match your config

Map each `betterAuth({ … })` option to `auth.Config` — see the
[configuration reference](../reference/configuration.md).

### 2. Migrate data

Export users, accounts, sessions, and verification rows from your existing DB.
The SQL schema uses Better Auth JS table and column names with unix-ms
timestamps. Supported plugin columns are generated when the matching plugins are
enabled.

### 3. Enable the same plugins

```go
Plugins: []auth.Plugin{
    plugins.Organization(plugins.OrganizationOptions{}),
    plugins.TwoFactor(plugins.TwoFactorOptions{}),
    // match your TS plugins array
},
```

Generate schema for your plugin set:

```bash
betterauth-go generate --plugins organization,two-factor --dialect postgres
```

### 4. Point clients at Go

Change only `baseURL` in `createAuthClient` — no client code changes otherwise.

### 5. Verify parity

Check the [ROADMAP](../../ROADMAP.md) for features not yet implemented and
remaining long-tail OAuth providers.

## Config mapping cheat sheet

| TS option | Go field |
|-----------|----------|
| `secret` | `Secret` |
| `baseURL` | `BaseURL` |
| `basePath` | `BasePath` |
| `trustedOrigins` | `TrustedOrigins` |
| `emailAndPassword` | `EmailAndPassword` |
| `emailVerification` | `EmailVerification` |
| `session` | `Session` |
| `socialProviders.google` | `Google` |
| `socialProviders.github` | `GitHub` |
| `account.accountLinking` | `Account.AccountLinking` |
| `advanced` | `Advanced` |
| `rateLimit` | `RateLimit` |
| `databaseHooks` | `DatabaseHooks` |
| `hooks` | `Hooks` |
| `plugins` | `Plugins` |
| `disabledPaths` | `DisabledPaths` |

Back to: [Introduction](../introduction.md)
