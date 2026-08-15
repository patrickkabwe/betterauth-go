package auth_test

import (
	"context"

	berrors "github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/internal/crypto"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/store/memory"
	"github.com/patrickkabwe/betterauth-go/types"
)

type failStore struct {
	inner  *memory.Store
	failOn string
}

func wrapStore(failOn string) store.Store {
	return &failStore{inner: memory.New(), failOn: failOn}
}

func (f *failStore) CreateUser(ctx context.Context, user *types.User) error {
	if f.failOn == "CreateUser" {
		return berrors.ErrInjected
	}
	return f.inner.CreateUser(ctx, user)
}

func (f *failStore) UpdateUser(ctx context.Context, id string, update store.UserUpdate) (*types.User, error) {
	if f.failOn == "UpdateUser" {
		return nil, berrors.ErrInjected
	}
	return f.inner.UpdateUser(ctx, id, update)
}

func (f *failStore) FindUserByEmail(ctx context.Context, email string) (*types.User, error) {
	if f.failOn == "FindUserByEmail" {
		return nil, berrors.ErrInjected
	}
	return f.inner.FindUserByEmail(ctx, email)
}

func (f *failStore) FindUserByID(ctx context.Context, id string) (*types.User, error) {
	return f.inner.FindUserByID(ctx, id)
}

func (f *failStore) DeleteUser(ctx context.Context, id string) error {
	if f.failOn == "DeleteUser" {
		return berrors.ErrInjected
	}
	return f.inner.DeleteUser(ctx, id)
}

func (f *failStore) CreateAccount(ctx context.Context, account *types.Account) error {
	if f.failOn == "CreateAccount" {
		return berrors.ErrInjected
	}
	return f.inner.CreateAccount(ctx, account)
}

func (f *failStore) UpdateAccount(ctx context.Context, id string, update store.AccountUpdate) (*types.Account, error) {
	if f.failOn == "UpdateAccount" {
		return nil, berrors.ErrInjected
	}
	return f.inner.UpdateAccount(ctx, id, update)
}

func (f *failStore) UpdateAccountPassword(ctx context.Context, userID, providerID, password string) error {
	if f.failOn == "UpdateAccountPassword" {
		return berrors.ErrInjected
	}
	return f.inner.UpdateAccountPassword(ctx, userID, providerID, password)
}

func (f *failStore) FindAccountByUserAndProvider(ctx context.Context, userID, providerID string) (*types.Account, error) {
	if f.failOn == "FindAccountByUserAndProvider" {
		return nil, berrors.ErrInjected
	}
	return f.inner.FindAccountByUserAndProvider(ctx, userID, providerID)
}

func (f *failStore) FindAccountByProviderAndAccountID(ctx context.Context, providerID, accountID string) (*types.Account, error) {
	return f.inner.FindAccountByProviderAndAccountID(ctx, providerID, accountID)
}

func (f *failStore) ListAccountsByUserID(ctx context.Context, userID string) ([]types.Account, error) {
	if f.failOn == "ListAccounts" {
		return nil, berrors.ErrInjected
	}
	return f.inner.ListAccountsByUserID(ctx, userID)
}

func (f *failStore) DeleteAccount(ctx context.Context, id string) error {
	if f.failOn == "DeleteAccount" {
		return berrors.ErrInjected
	}
	return f.inner.DeleteAccount(ctx, id)
}

func (f *failStore) CreateSession(ctx context.Context, session *types.Session) error {
	if f.failOn == "CreateSession" {
		return berrors.ErrInjected
	}
	return f.inner.CreateSession(ctx, session)
}

func (f *failStore) UpdateSession(ctx context.Context, token string, update store.SessionUpdate) (*types.Session, error) {
	if f.failOn == "UpdateSession" {
		return nil, berrors.ErrInjected
	}
	return f.inner.UpdateSession(ctx, token, update)
}

func (f *failStore) FindSessionByToken(ctx context.Context, token string) (*types.Session, *types.User, error) {
	return f.inner.FindSessionByToken(ctx, token)
}

func (f *failStore) ListSessionsByUserID(ctx context.Context, userID string) ([]types.Session, error) {
	if f.failOn == "ListSessions" {
		return nil, berrors.ErrInjected
	}
	return f.inner.ListSessionsByUserID(ctx, userID)
}

func (f *failStore) DeleteSession(ctx context.Context, token string) error {
	if f.failOn == "DeleteSession" {
		return berrors.ErrInjected
	}
	return f.inner.DeleteSession(ctx, token)
}

func (f *failStore) DeleteSessionsByUserID(ctx context.Context, userID, exceptToken string) error {
	if f.failOn == "DeleteSessionsByUserID" {
		return berrors.ErrInjected
	}
	return f.inner.DeleteSessionsByUserID(ctx, userID, exceptToken)
}

func (f *failStore) DeleteAllSessionsByUserID(ctx context.Context, userID string) error {
	if f.failOn == "DeleteAllSessionsByUserID" {
		return berrors.ErrInjected
	}
	return f.inner.DeleteAllSessionsByUserID(ctx, userID)
}

func (f *failStore) CreateVerification(ctx context.Context, v *types.Verification) error {
	if f.failOn == "CreateVerification" {
		return berrors.ErrInjected
	}
	return f.inner.CreateVerification(ctx, v)
}

func (f *failStore) FindVerificationByIdentifier(ctx context.Context, identifier string) (*types.Verification, error) {
	return f.inner.FindVerificationByIdentifier(ctx, identifier)
}

func (f *failStore) DeleteVerificationByIdentifier(ctx context.Context, identifier string) error {
	if f.failOn == "DeleteVerificationByIdentifier" {
		return berrors.ErrInjected
	}
	return f.inner.DeleteVerificationByIdentifier(ctx, identifier)
}

func (f *failStore) ListUsers(ctx context.Context, opts store.ListUsersOpts) ([]types.User, error) {
	return f.inner.ListUsers(ctx, opts)
}

type errorHasher struct{}

func (errorHasher) Hash(_ string) (string, error) { return "", berrors.ErrHashFail }
func (errorHasher) Verify(hash, password string) (bool, error) {
	return crypto.ScryptHasher{}.Verify(hash, password)
}

type verifyErrorHasher struct{}

func (verifyErrorHasher) Hash(password string) (string, error) {
	return crypto.ScryptHasher{}.Hash(password)
}

func (verifyErrorHasher) Verify(_ string, _ string) (bool, error) {
	return false, berrors.ErrInjected
}
