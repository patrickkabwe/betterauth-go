# Two-factor plugin

TOTP authenticator apps, email/SMS OTP, and backup codes.

## Enable

```go
Plugins: []auth.Plugin{
    plugins.TwoFactor(plugins.TwoFactorOptions{
        Issuer: "My App", // shown in authenticator apps
    }),
},
```

Requires `store.ExtStore`.

## Client

```ts
import { twoFactorClient } from "better-auth/client/plugins";

createAuthClient({ plugins: [twoFactorClient()] });
```

## Schema

```bash
betterauth-go generate --plugins two-factor --dialect sqlite
```

## Flow

1. **Enable** — `POST /two-factor/enable` → returns `totpURI` for QR code
2. **Verify TOTP** — `POST /two-factor/verify-totp` with `{ code }`
3. **Sign in with 2FA** — after password sign-in, verify via TOTP/OTP/backup
4. **Disable** — `POST /two-factor/disable`

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/two-factor/enable` | Start 2FA setup |
| POST | `/two-factor/verify-totp` | Confirm TOTP code |
| POST | `/two-factor/get-totp-uri` | Re-fetch TOTP URI |
| POST | `/two-factor/send-otp` | Send email/SMS OTP |
| POST | `/two-factor/verify-otp` | Verify OTP |
| POST | `/two-factor/generate-backup-codes` | Generate backup codes |
| POST | `/two-factor/verify-backup-code` | Use backup code |
| POST | `/two-factor/disable` | Turn off 2FA |

User flag `twoFactorEnabled` is stored in user `additional` JSON.

Back to: [Plugin overview](overview.md)
