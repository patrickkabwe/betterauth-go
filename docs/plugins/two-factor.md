# Two-factor plugin

TOTP authenticator apps, email/SMS OTP, and backup codes.

## Enable

```go
Plugins: []auth.Plugin{
    plugins.TwoFactor(plugins.TwoFactorOptions{
        Issuer: "My App", // shown in authenticator apps
        SendOTP: func(ctx context.Context, user *types.User, otp string) error {
            // send OTP to email or phone
            return nil
        },
        OTPExpiresIn: time.Minute * 3,
        OTPLength: 6,
        OTPAllowedAttempts: 5,
        AllowPasswordless: false,
        TrustDeviceMaxAge: time.Hour * 24 * 30,
        TOTPDigits: 6,
        TOTPPeriod: time.Second * 30,
        SkipVerificationOnEnable: false,
        AccountLockout: &plugins.TwoFactorAccountLockoutOptions{
            MaxFailedAttempts: 10,
            Duration: time.Minute * 15,
        },
    }),
},
```

Requires `store.ExtStore`. `SendOTP` is required for `/two-factor/send-otp`.
When omitted, OTP sending returns `OTP_NOT_CONFIGURED`.
`/two-factor/enable`, `/two-factor/disable`, `/two-factor/get-totp-uri`, and
`/two-factor/generate-backup-codes` require `password` when the user has a
credential password. This matches Better Auth's `allowPasswordless` behavior.
During sign-in challenges, failed second-factor verifications are counted across
OTP, TOTP, and backup codes. The account is temporarily locked after the
configured number of consecutive failures and the count resets after success.
TOTP and backup-code sign-in challenges also enforce the same five-attempt
per-challenge budget used by Better Auth.
`TOTPDigits` accepts 6 or 8 digits, and `TOTPPeriod` controls the TOTP time
step. `SkipVerificationOnEnable` immediately marks the two-factor row verified
and sets `twoFactorEnabled` after `/two-factor/enable`.

## Client

```ts
import { twoFactorClient } from "better-auth/client/plugins";

createAuthClient({ plugins: [twoFactorClient()] });
```

## Schema

```bash
betterauth generate --plugins two-factor --dialect sqlite
```

## Flow

1. **Enable** — `POST /two-factor/enable` → returns `totpURI` for QR code and 10 backup codes
2. **Verify TOTP** — `POST /two-factor/verify-totp` with `{ code }`
3. **Send OTP** — `POST /two-factor/send-otp` sends a one-time code through `SendOTP`
4. **Verify OTP** — `POST /two-factor/verify-otp` with `{ code }`
5. **Sign in with 2FA** — credential sign-in returns `{ twoFactorRedirect: true, twoFactorMethods }` and a signed `better-auth.two_factor` challenge cookie instead of a session token
6. **Disable** — `POST /two-factor/disable`

During a two-factor sign-in challenge, call `/two-factor/send-otp`,
`/two-factor/verify-otp`, `/two-factor/verify-totp`, or
`/two-factor/verify-backup-code` with the challenge cookie. Successful
verification consumes the challenge and returns `{ token, user }`.
Pass `trustDevice: true` to a successful verify request to set a signed
`better-auth.trust_device` cookie. Later credential sign-ins on that device
skip the two-factor redirect while the server-side trust record is valid.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/two-factor/enable` | Start 2FA setup and generate backup codes |
| POST | `/two-factor/verify-totp` | Confirm TOTP code |
| POST | `/two-factor/get-totp-uri` | Re-fetch TOTP URI |
| POST | `/two-factor/send-otp` | Send email/SMS OTP |
| POST | `/two-factor/verify-otp` | Verify OTP |
| POST | `/two-factor/generate-backup-codes` | Generate backup codes |
| POST | `/two-factor/verify-backup-code` | Use backup code |
| POST | `/two-factor/disable` | Turn off 2FA |

User flag `twoFactorEnabled` is stored on the user table when the two-factor
plugin schema is generated, and is exposed through user `Additional`.

Back to: [Plugin overview](overview.md)
