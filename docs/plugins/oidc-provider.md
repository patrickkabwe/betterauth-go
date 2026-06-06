# OIDC provider plugin

Make your auth server act as an **OpenID Connect identity provider** for
third-party applications.

## Enable

```go
Plugins: []auth.Plugin{
    plugins.OIDCProvider(plugins.OIDCProviderOptions{
        // login/consent configuration
    }),
},
```

Requires `store.ExtStore`. Generates OIDC-related tables:

```bash
betterauth-go generate --plugins oidc-provider --dialect postgres
```

## Use cases

- Single sign-on for multiple apps you operate
- OAuth 2.0 / OIDC clients consuming your user directory
- MCP and agent auth flows (often paired with the **mcp** plugin)

## Key concepts

- Register OAuth clients in the database (via admin or migration)
- Users authenticate through your existing Better Auth flows
- Clients receive authorization codes and exchange them for tokens

## Related plugins

| Plugin | Purpose |
|--------|---------|
| `jwt` | JWT session tokens + JWKS |
| `mcp` | Model Context Protocol OAuth |
| `device-authorization` | Device code flow for TV/CLI apps |

For endpoint details, enable the **open-api** plugin or inspect
`GET /client-schema`.

See also: [Better Auth OIDC provider docs](https://better-auth.com/docs/plugins/oidc-provider).

Back to: [Plugin overview](overview.md)
