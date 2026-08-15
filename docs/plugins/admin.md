# Admin plugin

User administration: roles, bans, impersonation, and session management.

## Enable

```go
Plugins: []auth.Plugin{
    plugins.Admin(plugins.AdminOptions{
        AdminRoles: []string{"admin"}, // default
    }),
},
```

Admin access is determined by the user's `role` field (a SQL column when the
admin plugin schema is generated; exposed through `Additional` in the store
interface). Default role: `user`.

## Client

```ts
import { adminClient } from "better-auth/client/plugins";

createAuthClient({ plugins: [adminClient()] });
```

## Grant admin role

Set role via database hook, migration, or the admin API itself:

```go
a.SetUserAdditional(ctx, userID, map[string]any{"role": "admin"})
```

## Key endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/list-users` | Paginated user list |
| GET | `/admin/get-user` | User by ID |
| POST | `/admin/create-user` | Create user |
| POST | `/admin/update-user` | Update user |
| POST | `/admin/remove-user` | Delete user |
| POST | `/admin/set-role` | Change user role |
| POST | `/admin/ban-user` | Ban user |
| POST | `/admin/unban-user` | Unban user |
| POST | `/admin/impersonate-user` | Start impersonation |
| POST | `/admin/stop-impersonating` | End impersonation |
| POST | `/admin/list-user-sessions` | User's sessions |
| POST | `/admin/revoke-user-session` | Revoke one session |
| POST | `/admin/revoke-user-sessions` | Revoke all sessions |
| POST | `/admin/set-user-password` | Set password for user |
| POST | `/admin/has-permission` | Check admin permission |

Impersonation stores `impersonatedBy` on the session (a SQL column when the
admin plugin schema is generated; exposed through session `Additional`).

Back to: [Plugin overview](overview.md)
