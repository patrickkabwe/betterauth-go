# Social providers

Social sign-in uses OAuth 2.0. Google and GitHub have top-level config helpers.
Additional built-in constructors are available for Discord, Dropbox, Figma,
GitLab, Notion, Slack, Spotify, and Vercel.

## Google

```go
a, err := auth.New(auth.Config{
    Secret:  "your-secret-at-least-32-chars-long",
    BaseURL: "https://api.example.com",
    Store:   myStore,

    Google: auth.GoogleProviderConfig{
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        Scopes:       []string{}, // optional extra scopes
        Disabled:     false,
    },
})
```

Set `Disabled: true` to turn off Google without removing credentials.

## GitHub

```go
GitHub: auth.GitHubProviderConfig{
    ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
    ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
    Scopes:       []string{"read:user", "user:email"},
},
```

## Additional built-in providers

Use the `SocialProviders` map for the standard OAuth constructors:

```go
import (
    "github.com/patrickkabwe/betterauth-go/auth"
    "github.com/patrickkabwe/betterauth-go/provider"
    "github.com/patrickkabwe/betterauth-go/provider/oauth2provider"
)

a, err := auth.New(auth.Config{
    Secret:  "your-secret-at-least-32-chars-long",
    BaseURL: "https://api.example.com",
    Store:   myStore,
    SocialProviders: map[string]provider.SocialProvider{
        oauth2provider.ProviderDiscord: oauth2provider.Discord(oauth2provider.Options{
            ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
            ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
        }),
        oauth2provider.ProviderSpotify: oauth2provider.Spotify(oauth2provider.Options{
            ClientID:     os.Getenv("SPOTIFY_CLIENT_ID"),
            ClientSecret: os.Getenv("SPOTIFY_CLIENT_SECRET"),
        }),
    },
})
```

The constructors share Better Auth's provider IDs and profile mappings for:
`discord`, `dropbox`, `figma`, `gitlab`, `notion`, `slack`, `spotify`, and
`vercel`.

## Sign in with social

From a Better Auth client:

```ts
await authClient.signIn.social({
  provider: "google", // or "github"
  callbackURL: "/dashboard",
});
```

Or call the API directly:

```bash
curl -X POST http://localhost:8080/api/auth/sign-in/social \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d '{"provider":"google","callbackURL":"/"}'
```

The response includes a redirect URL. After the user completes OAuth, the
provider redirects to `GET /callback/{provider}` on your server.

Native clients can also sign in with a provider ID token when the provider
supports token verification:

```bash
curl -X POST http://localhost:8080/api/auth/sign-in/social \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d '{"provider":"google","idToken":{"token":"<id-token>","accessToken":"<access-token>"}}'
```

This returns `{ "redirect": false, "token": "...", "user": ... }` and sets the
session cookie, matching the TypeScript server's native ID-token branch.

## Account linking

Link additional providers to an existing account:

```go
Account: auth.AccountConfig{
    AccountLinking: auth.AccountLinkingConfig{
        Enabled:              boolPtr(true), // default when nil
        TrustedProviders:     []string{"google", "github"},
        AllowDifferentEmails: false,
        AllowUnlinkingAll:    false,
    },
},
```

| Endpoint | Description |
|----------|-------------|
| POST `/link-social` | Start linking flow for authenticated user |
| POST `/unlink-account` | Remove a linked provider |
| GET `/list-accounts` | List linked accounts |
| GET `/account-info` | Account details for a provider |

## Token management

| Endpoint | Description |
|----------|-------------|
| POST `/get-access-token` | Retrieve stored OAuth access token |
| POST `/refresh-token` | Refresh an expired access token |

## Generic OAuth plugin

For providers beyond Google and GitHub, enable the generic-oauth plugin:

```go
import "github.com/patrickkabwe/betterauth-go/plugins"

auth.Config{
    Plugins: []auth.Plugin{
        plugins.GenericOAuth(plugins.GenericOAuthOptions{
            // provider definitions
        }),
    },
}
```

See the [plugin overview](../plugins/overview.md) and the
[ROADMAP](../../ROADMAP.md) for the full provider parity list (35+ in the
TypeScript server).

## Callback URL

OAuth redirect URIs must match your `BaseURL` and mount path:

```
{BaseURL}{BasePath}/callback/google
{BaseURL}{BasePath}/callback/github
```

With defaults: `http://localhost:8080/api/auth/callback/google`.

Next: [Account management →](account-management.md)
