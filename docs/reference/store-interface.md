# Store interface

Implement `store.Store` to plug in any database or ORM. Plugins that need
extra tables require `store.ExtStore`.

## store.Store

```go
type Store interface {
    // User
    CreateUser(ctx context.Context, user *types.User) error
    UpdateUser(ctx context.Context, id string, update UserUpdate) (*types.User, error)
    FindUserByEmail(ctx context.Context, email string) (*types.User, error)
    FindUserByID(ctx context.Context, id string) (*types.User, error)
    DeleteUser(ctx context.Context, id string) error
    ListUsers(ctx context.Context, opts ListUsersOpts) ([]types.User, error)

    // Account (credential + OAuth)
    CreateAccount(ctx context.Context, account *types.Account) error
    UpdateAccount(ctx context.Context, id string, update AccountUpdate) (*types.Account, error)
    UpdateAccountPassword(ctx context.Context, userID, providerID, password string) error
    FindAccountByUserAndProvider(ctx context.Context, userID, providerID string) (*types.Account, error)
    FindAccountByProviderAndAccountID(ctx context.Context, providerID, accountID string) (*types.Account, error)
    ListAccountsByUserID(ctx context.Context, userID string) ([]types.Account, error)
    DeleteAccount(ctx context.Context, id string) error

    // Session
    CreateSession(ctx context.Context, session *types.Session) error
    UpdateSession(ctx context.Context, token string, update SessionUpdate) (*types.Session, error)
    FindSessionByToken(ctx context.Context, token string) (*types.Session, *types.User, error)
    ListSessionsByUserID(ctx context.Context, userID string) ([]types.Session, error)
    DeleteSession(ctx context.Context, token string) error
    DeleteSessionsByUserID(ctx context.Context, userID string, exceptToken string) error
    DeleteAllSessionsByUserID(ctx context.Context, userID string) error

    // Verification (email verify, reset, OAuth state, OTP, …)
    CreateVerification(ctx context.Context, v *types.Verification) error
    FindVerificationByIdentifier(ctx context.Context, identifier string) (*types.Verification, error)
    DeleteVerificationByIdentifier(ctx context.Context, identifier string) error
}
```

## Update types

```go
type UserUpdate struct {
    Name, Email *string
    EmailVerified *bool
    Image **string
    Additional map[string]any
}

type SessionUpdate struct {
    ExpiresAt, UpdatedAt *time.Time
    IPAddress, UserAgent *string
    Additional map[string]any
}

type AccountUpdate struct {
    AccessToken, RefreshToken, IDToken, Scope *string
    AccessTokenExpiresAt, RefreshTokenExpiresAt *time.Time
}
```

## store.ExtStore

Extended interface for plugin entities (organizations, 2FA, OIDC clients, etc.).
See `store/extstore.go` for the full method list.

Built-in implementations:

| Package | Implements |
|---------|------------|
| `store/memory` | `Store` + `ExtStore` |
| `store/sql` | `Store` + `ExtStore` |

## Additional fields

User and session plugin data lives in JSON `additional` columns/maps — not
separate columns per field. Use `UserUpdate.Additional` and
`SessionUpdate.Additional` for partial updates.

## Database hooks wrapper

When `DatabaseHooks` is configured, the store is wrapped transparently. Plugins
access the underlying store via `auth.ExtStore(a.Store())`.

## SQL schema reference

Core tables: `ba_user`, `ba_account`, `ba_session`, `ba_verification`.

Generate full schema:

```bash
betterauth-go generate --all --dialect postgres -o schema.sql
```

See [Database & adapters](../concepts/database.md).

Back to: [Configuration](configuration.md)
