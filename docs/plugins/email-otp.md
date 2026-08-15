# Email OTP plugin

One-time passwords sent via email for sign-in and verification flows.

## Enable

```go
Plugins: []auth.Plugin{
    plugins.EmailOTP(plugins.EmailOTPOptions{
        SendOTP: func(ctx context.Context, email, otp, typ string) error {
            // send OTP to email
            return nil
        },
        ExpiresIn: time.Minute * 5,
        AllowedAttempts: 3,
    }),
},
```

## Client

```ts
import { emailOTPClient } from "better-auth/client/plugins";

createAuthClient({ plugins: [emailOTPClient()] });
```

## OTP types

| Type | Use |
|------|-----|
| `email-verification` | Verify email address |
| `sign-in` | Sign in or sign up with email OTP |
| `forget-password` | Password reset via OTP |
| `email-change` | Confirm new email |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/email-otp/send-verification-otp` | Send OTP with `type` |
| POST | `/email-otp/check-verification-otp` | Check OTP without consuming it |
| POST | `/sign-in/email-otp` | Sign in with email + OTP |
| POST | `/email-otp/verify-email` | Verify email with OTP |
| POST | `/email-otp/request-password-reset` | Start password reset |
| POST | `/forget-password/email-otp` | Start password reset |
| POST | `/email-otp/reset-password` | Reset with `password` + OTP |
| POST | `/email-otp/request-email-change` | Send OTP to a new email |
| POST | `/email-otp/change-email` | Confirm email change |

Back to: [Plugin overview](overview.md)
