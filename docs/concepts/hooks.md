# Hooks

Hooks let you intercept requests and database operations — the Go equivalent of
Better Auth's `hooks` and `databaseHooks` options.

## Request hooks

Run middleware before and after every matched route:

```go
Hooks: auth.HooksConfig{
    Before: func(c *auth.Context) bool {
        // return false to stop processing (you must write the response)
        return true
    },
    After: func(c *auth.Context) {
        // runs after the handler (via defer)
    },
},
```

`auth.Context` exposes the request, response writer, resolved session/user, and
route variables.

## Database hooks

Callbacks around core store operations:

```go
DatabaseHooks: auth.DatabaseHooksConfig{
    User: &auth.UserDatabaseHooks{
        BeforeCreate: func(ctx context.Context, u *types.User) (bool, error) {
            // return false to abort creation
            return true, nil
        },
        AfterCreate: func(ctx context.Context, u *types.User) error {
            // e.g. create Stripe customer
            return nil
        },
        BeforeUpdate: func(ctx context.Context, u *types.User, patch store.UserUpdate) (bool, error) {
            return true, nil
        },
        AfterUpdate:  func(ctx context.Context, u *types.User) error { return nil },
        BeforeDelete: func(ctx context.Context, u *types.User) (bool, error) { return true, nil },
        AfterDelete:  func(ctx context.Context, u *types.User) error { return nil },
    },
    Session: &auth.SessionDatabaseHooks{
        AfterCreate: func(ctx context.Context, s *types.Session) error {
            log.Printf("session for %s from %s", s.UserID, s.IPAddress)
            return nil
        },
    },
},
```

Return `false` from a `Before*` hook to abort the operation.

## Plugin hooks

Each plugin can register `Before` and `After` middleware via `PluginHooks`.
Plugin hooks run alongside config hooks for every request.

## User lifecycle hooks

Account deletion also supports config-level callbacks on `UserConfig.DeleteUser`:

```go
User: auth.UserConfig{
    DeleteUser: auth.DeleteUserConfig{
        BeforeDelete: func(ctx context.Context, user types.User) error { return nil },
        AfterDelete:  func(ctx context.Context, user types.User) error { return nil },
    },
},
```

Next: [Rate limiting →](rate-limit.md)
