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
| `forget-password` | Password reset via OTP |
| `email-change` | Confirm new email |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/email-otp/send-verification-otp` | Send OTP |
| POST | `/sign-in/email-otp` | Sign in with email + OTP |
| POST | `/email-otp/verify-email` | Verify email with OTP |
| POST | `/forget-password/email-otp` | Start password reset |
| POST | `/email-otp/reset-password` | Reset with OTP |

Back to: [Plugin overview](overview.md)
