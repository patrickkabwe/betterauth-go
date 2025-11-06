# Account management

Manage linked OAuth providers, list connected accounts, and refresh provider
tokens.

## List accounts

```bash
curl http://localhost:8080/api/auth/list-accounts \
  -H 'Cookie: better-auth.session_token=…'
```

Returns all provider accounts linked to the current user (Google, GitHub,
credential, etc.).

## Account info

```bash
curl 'http://localhost:8080/api/auth/account-info?providerId=google' \
  -H 'Cookie: better-auth.session_token=…'
```

## Link a provider

Start a linking flow for an authenticated user:

```ts
await authClient.linkSocial({
  provider: "github",
  callbackURL: "/settings/accounts",
});
```

Server endpoint: `POST /link-social` with `{ provider, callbackURL }`.

Account linking is controlled by `Account.AccountLinking`:

```go
Account: auth.AccountConfig{
    AccountLinking: auth.AccountLinkingConfig{
        Enabled:              boolPtr(true),
        TrustedProviders:     []string{"google", "github"},
        AllowDifferentEmails: false,
        AllowUnlinkingAll:    false,
    },
},
```

## Unlink a provider

```bash
curl -X POST http://localhost:8080/api/auth/unlink-account \
  -H 'Content-Type: application/json' \
  -H 'Cookie: better-auth.session_token=…' \
  -d '{"providerId":"github"}'
```

Cannot unlink the last remaining account unless
`AllowUnlinkingAll` is enabled.

## OAuth tokens

Retrieve or refresh stored provider tokens:

```bash
# Get access token
curl -X POST http://localhost:8080/api/auth/get-access-token \
  -H 'Content-Type: application/json' \
  -H 'Cookie: better-auth.session_token=…' \
  -d '{"providerId":"google"}'

# Refresh access token
curl -X POST http://localhost:8080/api/auth/refresh-token \
  -H 'Content-Type: application/json' \
  -H 'Cookie: better-auth.session_token=…' \
  -d '{"providerId":"google"}'
```

Next: [Session management →](../concepts/session-management.md)
