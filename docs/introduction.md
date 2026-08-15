# Introduction

**better-auth.go** is a Go server that speaks the same wire protocol as
[Better Auth](https://better-auth.com). Drop it into any Go HTTP server and
point an official Better Auth client (`better-auth/react`, `/vue`, `/svelte`,
Expo, or the framework-agnostic client) at it — the endpoints, request/response
shapes, and cookie behavior match, so the client doesn't know (or care) that the
backend is Go.

## Why

- **Use your Go stack.** Keep auth in the same binary, deployment, and database
  as the rest of your Go services — no separate Node process.
- **Client compatibility.** Reuse the mature Better Auth client SDKs and their
  React/Vue/Svelte hooks.
- **Batteries included.** Email/password, sessions, social OAuth, 24 plugins,
  SQL adapters, production middleware (CORS, CSRF, rate limiting), and a CLI.

## How it compares to the TypeScript server

| | TS (`better-auth`) | Go (`better-auth.go`) |
|---|---|---|
| Language / runtime | Node / Bun / Deno | Go |
| Client SDKs | ✅ official | ✅ same SDKs, unchanged |
| Email/password, sessions | ✅ | ✅ |
| Social OAuth | 35+ providers | Google, GitHub built-in + generic OAuth plugin |
| Plugins | many | 24 core plugins |
| Adapters | Kysely, Drizzle, Prisma, … | driver-agnostic SQL (Postgres/SQLite/MySQL) + `Store` interface |
| Plugin/extra fields | dedicated columns | plugin columns + JSON custom fields |
| CLI | `@better-auth/cli` | `betterauth-go` binary + `cli/core` package |

See the [ROADMAP](../ROADMAP.md) for the full parity tracker.

**Guides:** [Production](guides/production.md) · [Examples](guides/examples.md) ·
[Testing](guides/testing.md) · [Migrating from TypeScript](guides/migrating-from-typescript.md)

## Mental model

```
 ┌─────────────┐   HTTP (Better Auth wire format)   ┌──────────────────────┐
 │ Better Auth │ ─────────────────────────────────▶ │ auth.Handler()       │
 │ client      │ ◀───────────────────────────────── │ mounted at /api/auth │
 └─────────────┘     cookies / JSON / bearer         └──────────┬───────────┘
                                                                │
                                                       ┌────────▼────────┐
                                                       │ store.Store      │
                                                       │ (memory / SQL /  │
                                                       │  your ORM)       │
                                                       └─────────────────┘
```

Next: [Installation →](installation.md)
