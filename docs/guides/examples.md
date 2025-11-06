# Examples

The repository includes runnable examples for the server and each client
framework.

## Go server

**[`examples/basic/`](../../examples/basic/main.go)** — full-featured reference
server with:

- In-memory or SQLite store (`DATABASE_PATH`)
- Rate limiting, database hooks, origin CSRF
- Google + GitHub OAuth (env vars)
- Bearer, username, and organization plugins

```bash
go run ./examples/basic
# → http://localhost:8080/api/auth/*
```

## Client examples

| Example | Path | Stack |
|---------|------|-------|
| React | [`examples/react/`](../../examples/react/README.md) | Vite + `better-auth/react` |
| Vue | [`examples/vue/`](../../examples/vue/) | Vite + `better-auth/vue` |
| Svelte | [`examples/svelte/`](../../examples/svelte/) | Vite + `better-auth/svelte` |
| Expo | [`examples/expo/`](../../examples/expo/README.md) | Expo + SecureStore |

Each client example points at `http://localhost:8080` by default.

### Run React + Go together

```bash
# Terminal 1
go run ./examples/basic

# Terminal 2
cd examples/react && npm install && npm run dev
# → http://localhost:5173
```

The React example demonstrates:

- `organizationClient`, `usernameClient`
- Bearer token via `set-auth-token`
- `inferAdditionalFields<Auth>()` type inference

## Type generation

From the repo root:

```bash
go run ./examples/basic &
node scripts/generate-client-types.mjs http://localhost:8080
```

Writes `examples/react/src/lib/auth-types.ts`.

Next: [Migrating from TypeScript →](migrating-from-typescript.md)
