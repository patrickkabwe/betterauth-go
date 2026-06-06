# Email & password

Email and password authentication is enabled by default. Configure it through
`auth.Config.EmailAndPassword` and related email verification settings.

## Enable and configure

```go
a, err := auth.New(auth.Config{
    Secret: "your-secret-at-least-32-chars-long",
    Store:  myStore,

    EmailAndPassword: auth.EmailAndPasswordConfig{
        Enabled:                  true, // default when unset
        RequireEmailVerification: false,
        AutoSignIn:               boolPtr(true), // default: true when nil
        MinPasswordLength:        8,           // default
        MaxPasswordLength:        128,         // default
        RevokeSessionsOnPasswordReset: true,

        // Required for password reset emails:
        SendResetPassword: func(ctx context.Context, data types.ResetPasswordEmailData) error {
            // send data.URL to the user
            return nil
        },
        ResetPasswordTokenExpiresIn: time.Hour,
    },

    EmailVerification: auth.EmailVerificationConfig{
        SendVerificationEmail: func(ctx context.Context, data types.VerificationEmailData) error {
            return nil
        },
        SendOnSignIn: false,
        ExpiresIn:    time.Hour,
    },
})
```

Set `RequireEmailVerification: true` to block sign-in until the user verifies
their email. Wire `SendVerificationEmail` and use `POST /send-verification-email`
and `GET /verify-email`.

Helper for optional bool pointers:

```go
func boolPtr(v bool) *bool { return &v }
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/sign-up/email` | Register with name, email, password |
| POST | `/sign-in/email` | Sign in with email and password |
| POST | `/send-verification-email` | Send verification link |
| GET | `/verify-email` | Verify email from link token |
| POST | `/request-password-reset` | Start password reset flow |
| GET | `/reset-password/{token}` | Password reset landing page redirect |
| POST | `/reset-password` | Set a new password |
| POST | `/verify-password` | Verify current password (authenticated) |

All paths are relative to your mount point (default `/api/auth`).

## Sign up

```bash
curl -X POST http://localhost:8080/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -d '{"name":"Jane","email":"jane@example.com","password":"password123"}'
```

The response includes the user and session. A signed session cookie is set
automatically for browser clients.

**Enumeration protection:** duplicate sign-ups return a synthetic success
response instead of revealing that the email already exists.

## Sign in

```bash
curl -X POST http://localhost:8080/api/auth/sign-in/email \
  -H 'Content-Type: application/json' \
  -d '{"email":"jane@example.com","password":"password123","rememberMe":true}'
```

Pass `rememberMe: false` to use a shorter session lifetime (24 hours by
default). The server sets a `dont_remember` cookie when the user opts out of
persistent sessions.

## Password hashing

Passwords are hashed with **scrypt** (`N=16384, r=16, p=1, dkLen=64`) in the
`salt:key` format compatible with the TypeScript Better Auth server.

Override hashing with a custom `Hasher`:

```go
auth.Config{
    Hasher: myCustomHasher{}, // implements crypto.Hasher
}
```

## Disable sign-up

```go
auth.Config{DisableSignUp: true}
```

Sign-in continues to work; new registrations receive
`EMAIL_PASSWORD_SIGN_UP_DISABLED`.

## Client usage

```ts
import { createAuthClient } from "better-auth/react";

const authClient = createAuthClient({ baseURL: "http://localhost:8080" });

await authClient.signUp.email({
  name: "Jane",
  email: "jane@example.com",
  password: "password123",
});

await authClient.signIn.email({
  email: "jane@example.com",
  password: "password123",
});
```

Next: [User management →](user-management.md) · [Social providers →](social-providers.md)
