package store

import (
	"context"
	"time"

	"github.com/patrickkabwe/betterauth-go/types"
)

// Store is the persistence layer for Better Auth data.
type Store interface {
	// User
	CreateUser(ctx context.Context, user *types.User) error
	UpdateUser(ctx context.Context, id string, update UserUpdate) (*types.User, error)
	FindUserByEmail(ctx context.Context, email string) (*types.User, error)
	FindUserByID(ctx context.Context, id string) (*types.User, error)
	DeleteUser(ctx context.Context, id string) error

	// Account
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

	// Verification
	CreateVerification(ctx context.Context, v *types.Verification) error
	FindVerificationByIdentifier(ctx context.Context, identifier string) (*types.Verification, error)
	DeleteVerificationByIdentifier(ctx context.Context, identifier string) error

	// Users (admin / plugins)
	ListUsers(ctx context.Context, opts ListUsersOpts) ([]types.User, error)
}

// UserAdditionalFinder optionally provides an indexed lookup for user fields
// exposed through User.Additional.
type UserAdditionalFinder interface {
	FindUserByAdditional(ctx context.Context, key string, value any) (*types.User, error)
}

// UserUpdate contains mutable user fields.
type UserUpdate struct {
	Name          *string
	Email         *string
	EmailVerified *bool
	Image         **string
	Additional    map[string]any
}

// AccountUpdate contains mutable account fields.
type AccountUpdate struct {
	AccessToken           *string
	RefreshToken          *string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	IDToken               *string
	Scope                 *string
}

// SessionUpdate contains mutable session fields.
type SessionUpdate struct {
	ExpiresAt  *time.Time
	UpdatedAt  *time.Time
	IPAddress  *string
	UserAgent  *string
	Additional map[string]any
}

// ListUsersOpts filters user listing.
type ListUsersOpts struct {
	Search string
	Limit  int
	Offset int
}
