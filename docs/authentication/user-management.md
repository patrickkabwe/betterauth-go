# User management

Authenticated users can update their profile, change email or password, set a
password (for OAuth-only accounts), and delete their account.

## Update profile

```bash
curl -X POST http://localhost:8080/api/auth/update-user \
  -H 'Content-Type: application/json' \
  -H 'Cookie: better-auth.session_token=…' \
  -d '{"name":"Jane Doe","image":"https://example.com/avatar.png"}'
```

| Field | Description |
|-------|-------------|
| `name` | Display name |
| `image` | Avatar URL (pass `null` to clear) |

Custom fields defined in `User.AdditionalFields` can be included in the body.

## Change password

Requires an active session:

```bash
curl -X POST http://localhost:8080/api/auth/change-password \
  -H 'Content-Type: application/json' \
  -H 'Cookie: better-auth.session_token=…' \
  -d '{"currentPassword":"oldpass","newPassword":"newpass123"}'
```

## Set password

For users who signed up via OAuth and have no credential account:

```bash
curl -X POST http://localhost:8080/api/auth/set-password \
  -H 'Content-Type: application/json' \
  -H 'Cookie: better-auth.session_token=…' \
  -d '{"newPassword":"newpass123"}'
```

## Change email

Enable via `User.ChangeEmail`:

```go
User: auth.UserConfig{
    ChangeEmail: auth.ChangeEmailConfig{
        Enabled: true,
        SendChangeEmailConfirmation: func(ctx context.Context, data types.ChangeEmailData) error {
            // send confirmation link to data.NewEmail
            return nil
        },
    },
},
```

```bash
curl -X POST http://localhost:8080/api/auth/change-email \
  -H 'Content-Type: application/json' \
  -H 'Cookie: better-auth.session_token=…' \
  -d '{"newEmail":"new@example.com"}'
```

Set `UpdateEmailWithoutVerification: true` to skip the confirmation step (not
recommended in production).

## Delete account

Configure deletion callbacks:

```go
User: auth.UserConfig{
    DeleteUser: auth.DeleteUserConfig{
        Enabled: boolPtr(true),
        SendDeleteAccountURL: func(ctx context.Context, user types.User, url, token string) error {
            // email user the confirmation link
            return nil
        },
        BeforeDelete: func(ctx context.Context, user types.User) error { return nil },
        AfterDelete:  func(ctx context.Context, user types.User) error { return nil },
    },
},
```

```bash
# Request deletion (sends confirmation email when configured)
curl -X POST http://localhost:8080/api/auth/delete-user \
  -H 'Cookie: better-auth.session_token=…'

# Confirm via link → GET /delete-user/callback?token=…
```

Deletion requires a **fresh session** by default (`Session.FreshAge`).

## Client usage

```ts
await authClient.updateUser({ name: "Jane Doe" });
await authClient.changePassword({ currentPassword: "old", newPassword: "new" });
await authClient.changeEmail({ newEmail: "new@example.com" });
await authClient.deleteUser();
```

Next: [Account management →](account-management.md)
