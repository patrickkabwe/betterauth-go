# Other plugins

Brief reference for plugins without dedicated guides. All are enabled via
`auth.Config.Plugins` and listed in [Plugin overview](overview.md).

| Plugin | ID | Notes |
|--------|-----|-------|
| Anonymous | `anonymous` | Guest sessions without email |
| JWT | `jwt` | JWT tokens + JWKS endpoint |
| Multi-session | `multi-session` | Multiple concurrent sessions |
| Custom session | `custom-session` | Transform session API response |
| Last login method | `last-login-method` | Track sign-in method in cookie |
| Have I Been Pwned | `have-i-been-pwned` | Reject breached passwords |
| Captcha | `captcha` | Turnstile, reCAPTCHA, hCaptcha |
| OAuth proxy | `oauth-proxy` | Dev OAuth callback proxy |
| Generic OAuth | `generic-oauth` | Custom OAuth2/OIDC providers |
| One Tap | `one-tap` | Google One Tap sign-in |
| OpenAPI | `open-api` | Auto-generated OpenAPI spec at `/reference` |
| Device authorization | `device-authorization` | OAuth 2.0 device code flow |
| Phone number | `phone-number` | Phone password sign-in, SMS OTP verification, phone password reset, `phoneNumberValidator`, `callbackOnVerification`, and `signUpOnVerification` |
| SIWE | `siwe` | Sign-In with Ethereum |
| One-time token | `one-time-token` | Single-use cross-domain tokens |
| MCP | `mcp` | Model Context Protocol OAuth |

## Enable any plugin

```go
plugins.All(plugins.AllOptions{
    MagicLink: plugins.MagicLinkOptions{ /* … */ },
    JWT:       plugins.JWTOptions{},
    // …
})
```

Or pick individually:

```go
Plugins: []auth.Plugin{
    plugins.JWT(plugins.JWTOptions{}),
    plugins.OpenAPI(plugins.OpenAPIOptions{}),
},
```

## Schema

Include plugin tables in migrations:

```bash
betterauth-go generate --plugins jwt,siwe,device-authorization --dialect sqlite
```

## Client pairing

Each plugin has a matching `*Client()` export in `better-auth/client/plugins`.
Match server and client plugin arrays. Discover pairings via
`GET /client-schema`.

## Dedicated guides

- [Bearer](bearer.md)
- [Organization](organization.md)
- [Two-factor](two-factor.md)
- [Admin](admin.md)
- [Magic link](magic-link.md)
- [Username](username.md)
- [Email OTP](email-otp.md)
- [OIDC provider](oidc-provider.md)

Back to: [Plugin overview](overview.md)
