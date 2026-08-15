# better-auth.go documentation

A Go server implementation compatible with [Better Auth](https://better-auth.com)
clients. These docs mirror the structure of the
[official Better Auth documentation](https://better-auth.com/docs), mapped to
the Go API.

> **Docs viewer:** [`guide/`](guide/) — rendered documentation with sidebar,
> search, syntax highlighting, and the same dark theme as the landing page.
> Raw markdown files remain in this folder for editing and GitHub.

> **Landing page:** [`index.html`](index.html) — hero, setup snippets, feature
> grid, and CLI overview.

## Get started

- [Introduction](introduction.md) — what this is and how it compares
- [Installation](installation.md) — add the module, pick a store
- [Basic usage](basic-usage.md) — your first auth server

## Authentication

- [Email & password](authentication/email-password.md)
- [Social providers](authentication/social-providers.md) — Google, GitHub, generic OAuth
- [User management](authentication/user-management.md) — update, change email/password, delete
- [Account management](authentication/account-management.md) — link/unlink providers, tokens

## Concepts

- [Database & adapters](concepts/database.md) — `Store`, SQL adapter, ORMs
- [Session management](concepts/session-management.md)
- [Cookies](concepts/cookies.md) — signing, prefixes, cross-subdomain, custom names
- [Client schema & additional fields](concepts/client-schema.md) — type inference, custom user fields
- [Server-side API](concepts/server-api.md) — `NewSession`, passwords, verifications
- [Hooks](concepts/hooks.md) — request hooks & database hooks
- [Rate limiting](concepts/rate-limit.md)
- [Security & middleware](concepts/security.md) — CORS, CSRF, secret rotation, IP tracking
- [Errors](concepts/errors.md) — API error format
- [CLI](concepts/cli.md) — `go install github.com/patrickkabwe/betterauth-go@latest`; `generate`, `migrate`, `secret`, `info`, `init`

## Plugins

- [Plugin overview](plugins/overview.md) — all 25 core plugins
- [Bearer](plugins/bearer.md)
- [Organization](plugins/organization.md)
- [Two-factor](plugins/two-factor.md)
- [Admin](plugins/admin.md)
- [Magic link](plugins/magic-link.md)
- [Username](plugins/username.md)
- [Email OTP](plugins/email-otp.md)
- [OIDC provider](plugins/oidc-provider.md)
- [Other plugins](plugins/other-plugins.md) — anonymous, JWT, SIWE, MCP, …

## Integrations

- [Frameworks](integrations/frameworks.md) — net/http, chi, Gin, Echo, Fiber
- [Clients](integrations/clients.md) — React, Vue, Svelte, Expo
- [Go client](integrations/go-client.md) — server-side HTTP client for Go

## Guides

- [Production checklist](guides/production.md) — env vars, HTTPS, deployment
- [Examples](guides/examples.md) — runnable server + client demos
- [Testing](guides/testing.md) — unit and integration tests with memory/SQLite
- [Migrating from TypeScript](guides/migrating-from-typescript.md) — parity and config mapping

## Reference

- [Configuration](reference/configuration.md) — every `auth.Config` option
- [API endpoints](reference/api-endpoints.md) — core route table
- [Store interface](reference/store-interface.md) — `Store` + `ExtStore` methods
- [Error codes](reference/error-codes.md) — full API error code list

## Also see

- [ROADMAP](../ROADMAP.md) — feature parity tracker vs TypeScript server
- [README](../README.md) — project overview

---

## View locally

```bash
python3 -m http.server 4321 --directory docs
```

| URL | What |
|-----|------|
| [http://localhost:4321](http://localhost:4321) | Landing page |
| [http://localhost:4321/guide/](http://localhost:4321/guide/) | **Documentation viewer** — Better Auth–style layout, Geist font, light/dark |

The viewer loads the markdown files from this directory — no build step. Edit
`.md` files and refresh the browser.

Deploy with GitHub Actions (`.github/workflows/docs.yml`): push to `main`, or run
**Actions → Deploy Docs → Run workflow**. In **Settings → Pages**, set source to
**GitHub Actions**. Docs URL: `https://<user>.github.io/betterauth/` — link to
`/guide/` for the documentation viewer.
