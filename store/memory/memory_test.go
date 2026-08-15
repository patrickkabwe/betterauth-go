package memory_test

import (
	"context"
	"testing"
	"time"

	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/store/memory"
	"github.com/patrickkabwe/betterauth-go/types"
)

func TestUserCRUD(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	now := time.Now()
	u := &types.User{ID: "u1", Name: "A", Email: "a@b.com", CreatedAt: now, UpdatedAt: now}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, u); err != memory.ErrAlreadyExists {
		t.Fatal("expected duplicate")
	}
	found, err := s.FindUserByEmail(ctx, "a@b.com")
	if err != nil || found.ID != "u1" {
		t.Fatal("find by email failed")
	}
	name := "B"
	updated, err := s.UpdateUser(ctx, "u1", store.UserUpdate{Name: &name})
	if err != nil || updated.Name != "B" {
		t.Fatal("update failed")
	}
	if err := s.DeleteUser(ctx, "u1"); err != nil {
		t.Fatal("delete failed")
	}
}

func TestSessionAndVerification(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	now := time.Now()
	_ = s.CreateUser(ctx, &types.User{ID: "u1", Name: "A", Email: "a@b.com", CreatedAt: now, UpdatedAt: now})
	_ = s.CreateSession(ctx, &types.Session{
		ID: "s1", Token: "tok", UserID: "u1", ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	})
	sess, user, err := s.FindSessionByToken(ctx, "tok")
	if err != nil || sess.Token != "tok" || user.ID != "u1" {
		t.Fatal("session lookup failed")
	}
	_ = s.CreateVerification(ctx, &types.Verification{
		ID: "v1", Identifier: "id1", Value: "u1", ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	})
	v, err := s.FindVerificationByIdentifier(ctx, "id1")
	if err != nil || v.Value != "u1" {
		t.Fatal("verification failed")
	}
	_ = s.DeleteVerificationByIdentifier(ctx, "id1")
}

func TestFindUserByIDAndNotFound(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	now := time.Now()
	_ = s.CreateUser(ctx, &types.User{ID: "u1", Name: "A", Email: "a@b.com", CreatedAt: now, UpdatedAt: now})
	found, err := s.FindUserByID(ctx, "u1")
	if err != nil || found.ID != "u1" {
		t.Fatal("find by id failed")
	}
	if _, err := s.FindUserByID(ctx, "missing"); err != memory.ErrNotFound {
		t.Fatal("expected not found")
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	now := time.Now()
	_ = s.CreateUser(ctx, &types.User{ID: "u1", Name: "A", Email: "a@b.com", CreatedAt: now, UpdatedAt: now})
	exp := now.Add(time.Hour)
	_ = s.CreateSession(ctx, &types.Session{
		ID: "s1", Token: "t1", UserID: "u1", ExpiresAt: exp, CreatedAt: now, UpdatedAt: now,
	})
	_ = s.CreateSession(ctx, &types.Session{
		ID: "s2", Token: "t2", UserID: "u1", ExpiresAt: exp, CreatedAt: now, UpdatedAt: now,
	})

	list, err := s.ListSessionsByUserID(ctx, "u1")
	if err != nil || len(list) != 2 {
		t.Fatal("list sessions failed")
	}

	newExp := now.Add(2 * time.Hour)
	ip := "1.2.3.4"
	updated, err := s.UpdateSession(ctx, "t1", store.SessionUpdate{ExpiresAt: &newExp, IPAddress: &ip})
	if err != nil || !updated.ExpiresAt.Equal(newExp) {
		t.Fatal("update session failed")
	}

	if err := s.DeleteSession(ctx, "t1"); err != nil {
		t.Fatal("delete session failed")
	}
	if err := s.DeleteSessionsByUserID(ctx, "u1", "t2"); err != nil {
		t.Fatal("delete other sessions failed")
	}
	if _, _, err := s.FindSessionByToken(ctx, "t2"); err != nil {
		t.Fatal("t2 should remain")
	}

	_ = s.CreateSession(ctx, &types.Session{
		ID: "s3", Token: "t3", UserID: "u1", ExpiresAt: exp, CreatedAt: now, UpdatedAt: now,
	})
	if err := s.DeleteAllSessionsByUserID(ctx, "u1"); err != nil {
		t.Fatal("delete all sessions failed")
	}
}

func TestSessionIndexesTrackOverwriteAndDelete(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	now := time.Now()
	_ = s.CreateUser(ctx, &types.User{ID: "u1", Name: "A", Email: "a@b.com", CreatedAt: now, UpdatedAt: now})
	_ = s.CreateUser(ctx, &types.User{ID: "u2", Name: "B", Email: "b@b.com", CreatedAt: now, UpdatedAt: now})
	exp := now.Add(time.Hour)

	_ = s.CreateSession(ctx, &types.Session{
		ID: "s1", Token: "t1", UserID: "u1", ExpiresAt: exp, CreatedAt: now, UpdatedAt: now,
	})
	_ = s.CreateSession(ctx, &types.Session{
		ID: "s1", Token: "t1", UserID: "u2", ExpiresAt: exp, CreatedAt: now, UpdatedAt: now,
	})

	oldUserSessions, err := s.ListSessionsByUserID(ctx, "u1")
	if err != nil || len(oldUserSessions) != 0 {
		t.Fatal("old session index should be removed after overwrite")
	}
	newUserSessions, err := s.ListSessionsByUserID(ctx, "u2")
	if err != nil || len(newUserSessions) != 1 {
		t.Fatal("new session index should be added after overwrite")
	}
	if err := s.DeleteSessionsByUserID(ctx, "u1", ""); err != nil {
		t.Fatal(err)
	}
	_, user, err := s.FindSessionByToken(ctx, "t1")
	if err != nil || user.ID != "u2" {
		t.Fatal("deleting old user's sessions should not delete overwritten session")
	}
	if err := s.DeleteAllSessionsByUserID(ctx, "u2"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.FindSessionByToken(ctx, "t1"); err != memory.ErrNotFound {
		t.Fatal("session should be removed from token index")
	}
}

func TestUpdateUserEmail(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	now := time.Now()
	_ = s.CreateUser(ctx, &types.User{ID: "u1", Name: "A", Email: "old@b.com", CreatedAt: now, UpdatedAt: now})
	newEmail := "new@b.com"
	updated, err := s.UpdateUser(ctx, "u1", store.UserUpdate{Email: &newEmail})
	if err != nil || updated.Email != newEmail {
		t.Fatal("email update failed")
	}
	if _, err := s.FindUserByEmail(ctx, "new@b.com"); err != nil {
		t.Fatal("find by new email failed")
	}
}

func TestDeleteUserCleansSessions(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	now := time.Now()
	_ = s.CreateUser(ctx, &types.User{ID: "u1", Name: "A", Email: "a@b.com", CreatedAt: now, UpdatedAt: now})
	_ = s.CreateSession(ctx, &types.Session{
		ID: "s1", Token: "t1", UserID: "u1", ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	})
	if err := s.DeleteUser(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.FindSessionByToken(ctx, "t1"); err == nil {
		t.Fatal("sessions should be deleted with user")
	}
}

func TestDeleteAccount(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	now := time.Now()
	_ = s.CreateUser(ctx, &types.User{ID: "u1", Name: "A", Email: "a@b.com", CreatedAt: now, UpdatedAt: now})
	_ = s.CreateAccount(ctx, &types.Account{
		ID: "a1", AccountID: "ext", ProviderID: "github", UserID: "u1", CreatedAt: now, UpdatedAt: now,
	})
	if err := s.DeleteAccount(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAccount(ctx, "missing"); err != memory.ErrNotFound {
		t.Fatal("expected not found")
	}
}

func TestAccounts(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	now := time.Now()
	_ = s.CreateUser(ctx, &types.User{ID: "u1", Name: "A", Email: "a@b.com", CreatedAt: now, UpdatedAt: now})
	_ = s.CreateAccount(ctx, &types.Account{
		ID: "a1", AccountID: "u1", ProviderID: "credential", UserID: "u1", Password: "hash", CreatedAt: now, UpdatedAt: now,
	})
	list, err := s.ListAccountsByUserID(ctx, "u1")
	if err != nil || len(list) != 1 {
		t.Fatal("list accounts failed")
	}
	_ = s.UpdateAccountPassword(ctx, "u1", "credential", "newhash")
	acc, _ := s.FindAccountByUserAndProvider(ctx, "u1", "credential")
	if acc.Password != "newhash" {
		t.Fatal("password not updated")
	}

	exp := now.Add(time.Hour)
	updated, err := s.UpdateAccount(ctx, "a1", store.AccountUpdate{
		AccessToken:          strPtr("at"),
		RefreshToken:         strPtr("rt"),
		AccessTokenExpiresAt: &exp,
	})
	if err != nil || updated.AccessToken != "at" || updated.RefreshToken != "rt" {
		t.Fatalf("update account tokens failed: %+v err=%v", updated, err)
	}
}

func TestAccountIndexesTrackOverwriteAndDelete(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	now := time.Now()

	_ = s.CreateAccount(ctx, &types.Account{
		ID: "a1", AccountID: "old", ProviderID: "credential", UserID: "u1", CreatedAt: now, UpdatedAt: now,
	})
	_ = s.CreateAccount(ctx, &types.Account{
		ID: "a1", AccountID: "new", ProviderID: "github", UserID: "u2", CreatedAt: now, UpdatedAt: now,
	})

	if _, err := s.FindAccountByProviderAndAccountID(ctx, "credential", "old"); err != memory.ErrNotFound {
		t.Fatal("old provider/account index should be removed after overwrite")
	}
	if _, err := s.FindAccountByUserAndProvider(ctx, "u1", "credential"); err != memory.ErrNotFound {
		t.Fatal("old user/provider index should be removed after overwrite")
	}
	oldUserAccounts, err := s.ListAccountsByUserID(ctx, "u1")
	if err != nil || len(oldUserAccounts) != 0 {
		t.Fatal("old user account index should be removed after overwrite")
	}
	newUserAccounts, err := s.ListAccountsByUserID(ctx, "u2")
	if err != nil || len(newUserAccounts) != 1 {
		t.Fatal("new user account index should be added after overwrite")
	}
	if err := s.DeleteAccount(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindAccountByProviderAndAccountID(ctx, "github", "new"); err != memory.ErrNotFound {
		t.Fatal("provider/account index should be removed after delete")
	}
}

func strPtr(s string) *string { return &s }
