# Client integration

Use the official Better Auth client SDKs unchanged — point `baseURL` at your Go
server.

## React

```ts
import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient({
  baseURL: "http://localhost:8080",
});

export const { signIn, signUp, signOut, useSession, getSession } = authClient;
```

Full example: [`examples/react/`](../../examples/react/README.md).

## Vue

```ts
import { createAuthClient } from "better-auth/vue";

export const authClient = createAuthClient({
  baseURL: "http://localhost:8080",
});
```

Example: [`examples/vue/`](../../examples/vue/).

## Svelte

```ts
import { createAuthClient } from "better-auth/svelte";

export const authClient = createAuthClient({
  baseURL: "http://localhost:8080",
});
```

Example: [`examples/svelte/`](../../examples/svelte/).

## Expo / React Native

Use SecureStore for token persistence. Example: [`examples/expo/`](../../examples/expo/README.md).

```ts
import { createAuthClient } from "better-auth/react";
import * as SecureStore from "expo-secure-store";

export const authClient = createAuthClient({
  baseURL: "https://api.example.com",
  storage: SecureStore,
});
```

## Framework-agnostic client

```ts
import { createAuthClient } from "better-auth/client";

export const authClient = createAuthClient({
  baseURL: "http://localhost:8080",
});
```

## Bearer tokens

Enable the **bearer** plugin on the server, then configure the client to read
`set-auth-token`:

```ts
export const authClient = createAuthClient({
  baseURL: "http://localhost:8080",
  fetchOptions: {
    onSuccess(ctx) {
      const token = ctx.response.headers.get("set-auth-token");
      if (token) sessionStorage.setItem("better-auth.bearer-token", token);
    },
    auth: {
      type: "Bearer",
      token: () => sessionStorage.getItem("better-auth.bearer-token") ?? undefined,
    },
  },
  plugins: [/* match server plugins */],
});
```

## Type inference

The Go server exposes `GET /client-schema` for client-side type inference:

```ts
import { inferAdditionalFields } from "better-auth/client/plugins";
import type { Auth } from "./auth-types";

createAuthClient({
  plugins: [inferAdditionalFields<Auth>()],
});
```

Generate `auth-types.ts` with `node scripts/generate-client-types.mjs` (see
React example README).

## CORS and origins

Add your frontend origin to `TrustedOrigins` on the server. The client sends
`Origin` on cross-origin requests; the server validates it for CSRF and CORS.

## Compatibility

| Client | Status |
|--------|--------|
| `better-auth/react` | ✅ |
| `better-auth/vue` | ✅ |
| `better-auth/svelte` | ✅ |
| `better-auth/client` | ✅ |
| Expo (SecureStore) | ✅ |

See the [ROADMAP](../../ROADMAP.md) for ongoing parity work.

Next: [Configuration reference →](../reference/configuration.md)
