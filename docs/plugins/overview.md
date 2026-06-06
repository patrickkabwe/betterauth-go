# Plugin overview

Plugins extend Better Auth with routes, middleware, and optional database tables.
Enable them via `auth.Config.Plugins`.

## Enable plugins

```go
import "github.com/patrickkabwe/betterauth-go/plugins"

a, err := auth.New(auth.Config{
    Secret: "your-secret-at-least-32-chars-long",
    Store:  myStore, // must implement store.ExtStore for most plugins

    Plugins: []auth.Plugin{
        plugins.Bearer(plugins.BearerOptions{}),
        plugins.Username(plugins.UsernameOptions{}),
        plugins.Organization(plugins.OrganizationOptions{}),
        plugins.TwoFactor(plugins.TwoFactorOptions{}),
    },
})
```

Or enable everything at once:

```go
Plugins: plugins.All(plugins.AllOptions{ /* per-plugin options */ }),
```

## All 24 core plugins

| ID | Package | Description |
|----|---------|-------------|
| `bearer` | `plugins.Bearer` | Bearer token auth — [guide](bearer.md) |
| `magic-link` | `plugins.MagicLink` | Passwordless email links — [guide](magic-link.md) |
| `anonymous` | `plugins.Anonymous` | Anonymous / guest users — [other](other-plugins.md) |
| `username` | `plugins.Username` | Username sign-in — [guide](username.md) |
| `email-otp` | `plugins.EmailOTP` | Email OTP — [guide](email-otp.md) |
| `one-time-token` | `plugins.OneTimeToken` | Short-lived single-use tokens |
| `jwt` | `plugins.JWT` | JWT session tokens |
| `multi-session` | `plugins.MultiSession` | Multiple concurrent sessions |
| `custom-session` | `plugins.CustomSession` | Customize session payload |
| `last-login-method` | `plugins.LastLoginMethod` | Track last sign-in method |
| `have-i-been-pwned` | `plugins.HaveIBeenPwned` | Reject breached passwords |
| `captcha` | `plugins.Captcha` | Captcha verification |
| `oauth-proxy` | `plugins.OAuthProxy` | OAuth proxy for dev/staging |
| `generic-oauth` | `plugins.GenericOAuth` | Additional OAuth providers |
| `one-tap` | `plugins.OneTap` | Google One Tap |
| `open-api` | `plugins.OpenAPI` | OpenAPI spec endpoint |
| `device-authorization` | `plugins.DeviceAuthorization` | Device code flow |
| `phone-number` | `plugins.PhoneNumber` | Phone OTP sign-in |
| `siwe` | `plugins.SIWE` | Sign-In with Ethereum |
| `two-factor` | `plugins.TwoFactor` | TOTP / backup codes — [guide](two-factor.md) |
| `admin` | `plugins.Admin` | Admin APIs, bans, impersonation — [guide](admin.md) |
| `organization` | `plugins.Organization` | Orgs, teams, invites — [guide](organization.md) |
| `oidc-provider` | `plugins.OIDCProvider` | Act as OIDC identity provider — [guide](oidc-provider.md) |
| `mcp` | `plugins.MCP` | MCP OAuth integration |

## Client plugins

Mirror server plugins on the client side. Example from `examples/react`:

```ts
import { createAuthClient } from "better-auth/react";
import { organizationClient, usernameClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: "http://localhost:8080",
  plugins: [usernameClient(), organizationClient()],
});
```

Server and client plugin sets should match for full functionality.

## ExtStore requirement

Plugins that persist extra entities (organization, two-factor, OIDC, etc.)
require `store.ExtStore`. The SQL and memory adapters implement it; a minimal
custom `Store` without `ExtStore` returns `EXT_STORE_REQUIRED` for those routes.

## Schema generation

Plugin tables are included in CLI output when the plugin is enabled:

```bash
betterauth-go generate --plugins organization,two-factor --dialect postgres
```

See [CLI →](../concepts/cli.md), [Other plugins](other-plugins.md), and the
[ROADMAP](../../ROADMAP.md) for parity details vs. the TypeScript server.

Next: [Frameworks →](../integrations/frameworks.md)
