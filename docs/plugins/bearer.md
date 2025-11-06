# Bearer plugin

Authenticate via `Authorization: Bearer` instead of (or alongside) session
cookies. Essential for mobile apps, API clients, and SSR services.

## Enable

```go
import "github.com/patrickkabwe/betterauth-go/plugins"

Plugins: []auth.Plugin{
    plugins.Bearer(plugins.BearerOptions{
        RequireSignature: false, // require signed token format when true
    }),
},
```

## How it works

The plugin reads `Authorization: Bearer <token>` on each request and resolves
the session from the raw or signed token.

Successful sign-in responses include a `set-auth-token` header with the bearer
token. Expose it to clients via CORS:

```go
TrustedOrigins: []string{"http://localhost:5173"},
// CORS handler exposes set-auth-token automatically
```

## Client setup

```ts
createAuthClient({
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
});
```

## Go server-side usage

```go
import "github.com/patrickkabwe/betterauth-go/client"

c := client.New("http://localhost:8080",
    client.WithBearerToken(token),
)
sess, err := c.GetSession(ctx)
```

No client plugin import needed on the server — bearer is server-side only.

Back to: [Plugin overview](overview.md)
