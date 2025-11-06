# Magic link plugin

Passwordless sign-in via email link.

## Enable

```go
Plugins: []auth.Plugin{
    plugins.MagicLink(plugins.MagicLinkOptions{
        SendMagicLink: func(ctx context.Context, email, link, token string) error {
            // send `link` to the user
            return nil
        },
        ExpiresIn:     5 * time.Minute,
        DisableSignUp: false,
    }),
},
```

`SendMagicLink` is **required** — without it, requests return
`MAGIC_LINK_DISABLED`.

## Client

```ts
import { magicLinkClient } from "better-auth/client/plugins";

createAuthClient({ plugins: [magicLinkClient()] });

await authClient.signIn.magicLink({
  email: "user@example.com",
  callbackURL: "/dashboard",
});
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/sign-in/magic-link` | Send magic link email |
| GET | `/magic-link/verify` | Verify token and create session |

Verification URL format:

```
{BaseURL}{BasePath}/magic-link/verify?token=…&callbackURL=…
```

Back to: [Plugin overview](overview.md)
