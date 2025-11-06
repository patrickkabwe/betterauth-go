package auth

import (
	"context"

	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

// hookedStore wraps a store.Store and invokes the configured DatabaseHooks
// around user and session create/update/delete operations. All other methods
// delegate unchanged. ExtStore support is preserved via Unwrap (see ExtStore).
type hookedStore struct {
	store.Store
	user    *UserDatabaseHooks
	session *SessionDatabaseHooks
}

// hasDatabaseHooks reports whether any database hook is configured.
func hasDatabaseHooks(cfg DatabaseHooksConfig) bool {
	return cfg.User != nil || cfg.Session != nil
}

// wrapWithHooks wraps base with database-hook invocation when any hook is set.
func wrapWithHooks(base store.Store, cfg DatabaseHooksConfig) store.Store {
	if base == nil || !hasDatabaseHooks(cfg) {
		return base
	}
	return &hookedStore{Store: base, user: cfg.User, session: cfg.Session}
}

// Unwrap exposes the underlying store so ExtStore detection can see through the
// wrapper.
func (h *hookedStore) Unwrap() store.Store { return h.Store }

// --- User hooks ---

func (h *hookedStore) CreateUser(ctx context.Context, user *types.User) error {
	if h.user != nil && h.user.BeforeCreate != nil {
		proceed, err := h.user.BeforeCreate(ctx, user)
		if err != nil {
			return err
		}
		if !proceed {
			return nil
		}
	}
	if err := h.Store.CreateUser(ctx, user); err != nil {
		return err
	}
	if h.user != nil && h.user.AfterCreate != nil {
		if err := h.user.AfterCreate(ctx, user); err != nil {
			return err
		}
	}
	return nil
}

func (h *hookedStore) UpdateUser(ctx context.Context, id string, update store.UserUpdate) (*types.User, error) {
	if h.user != nil && h.user.BeforeUpdate != nil {
		current, err := h.Store.FindUserByID(ctx, id)
		if err != nil {
			return nil, err
		}
		proceed, err := h.user.BeforeUpdate(ctx, current, update)
		if err != nil {
			return nil, err
		}
		if !proceed {
			return current, nil
		}
	}
	updated, err := h.Store.UpdateUser(ctx, id, update)
	if err != nil {
		return nil, err
	}
	if h.user != nil && h.user.AfterUpdate != nil {
		if err := h.user.AfterUpdate(ctx, updated); err != nil {
			return updated, err
		}
	}
	return updated, nil
}

func (h *hookedStore) DeleteUser(ctx context.Context, id string) error {
	var current *types.User
	if h.user != nil && (h.user.BeforeDelete != nil || h.user.AfterDelete != nil) {
		if u, err := h.Store.FindUserByID(ctx, id); err == nil {
			current = u
		}
	}
	if h.user != nil && h.user.BeforeDelete != nil && current != nil {
		proceed, err := h.user.BeforeDelete(ctx, current)
		if err != nil {
			return err
		}
		if !proceed {
			return nil
		}
	}
	if err := h.Store.DeleteUser(ctx, id); err != nil {
		return err
	}
	if h.user != nil && h.user.AfterDelete != nil && current != nil {
		if err := h.user.AfterDelete(ctx, current); err != nil {
			return err
		}
	}
	return nil
}

// --- Session hooks ---

func (h *hookedStore) CreateSession(ctx context.Context, session *types.Session) error {
	if h.session != nil && h.session.BeforeCreate != nil {
		proceed, err := h.session.BeforeCreate(ctx, session)
		if err != nil {
			return err
		}
		if !proceed {
			return nil
		}
	}
	if err := h.Store.CreateSession(ctx, session); err != nil {
		return err
	}
	if h.session != nil && h.session.AfterCreate != nil {
		if err := h.session.AfterCreate(ctx, session); err != nil {
			return err
		}
	}
	return nil
}

func (h *hookedStore) UpdateSession(ctx context.Context, token string, update store.SessionUpdate) (*types.Session, error) {
	if h.session != nil && h.session.BeforeUpdate != nil {
		current, _, err := h.Store.FindSessionByToken(ctx, token)
		if err != nil {
			return nil, err
		}
		proceed, err := h.session.BeforeUpdate(ctx, current)
		if err != nil {
			return nil, err
		}
		if !proceed {
			return current, nil
		}
	}
	updated, err := h.Store.UpdateSession(ctx, token, update)
	if err != nil {
		return nil, err
	}
	if h.session != nil && h.session.AfterUpdate != nil {
		if err := h.session.AfterUpdate(ctx, updated); err != nil {
			return updated, err
		}
	}
	return updated, nil
}

func (h *hookedStore) DeleteSession(ctx context.Context, token string) error {
	return h.deleteSessionWithHooks(ctx, token)
}

// deleteSessionWithHooks deletes a single session, invoking before/after hooks.
func (h *hookedStore) deleteSessionWithHooks(ctx context.Context, token string) error {
	var current *types.Session
	if h.session != nil && (h.session.BeforeDelete != nil || h.session.AfterDelete != nil) {
		if s, _, err := h.Store.FindSessionByToken(ctx, token); err == nil {
			current = s
		}
	}
	if h.session != nil && h.session.BeforeDelete != nil && current != nil {
		proceed, err := h.session.BeforeDelete(ctx, current)
		if err != nil {
			return err
		}
		if !proceed {
			return nil
		}
	}
	if err := h.Store.DeleteSession(ctx, token); err != nil {
		return err
	}
	if h.session != nil && h.session.AfterDelete != nil && current != nil {
		if err := h.session.AfterDelete(ctx, current); err != nil {
			return err
		}
	}
	return nil
}

func (h *hookedStore) sessionDeleteHooksActive() bool {
	return h.session != nil && (h.session.BeforeDelete != nil || h.session.AfterDelete != nil)
}

func (h *hookedStore) DeleteSessionsByUserID(ctx context.Context, userID, exceptToken string) error {
	if !h.sessionDeleteHooksActive() {
		return h.Store.DeleteSessionsByUserID(ctx, userID, exceptToken)
	}
	sessions, err := h.Store.ListSessionsByUserID(ctx, userID)
	if err != nil {
		return err
	}
	for _, s := range sessions {
		if s.Token == exceptToken {
			continue
		}
		if err := h.deleteSessionWithHooks(ctx, s.Token); err != nil {
			return err
		}
	}
	return nil
}

func (h *hookedStore) DeleteAllSessionsByUserID(ctx context.Context, userID string) error {
	if !h.sessionDeleteHooksActive() {
		return h.Store.DeleteAllSessionsByUserID(ctx, userID)
	}
	sessions, err := h.Store.ListSessionsByUserID(ctx, userID)
	if err != nil {
		return err
	}
	for _, s := range sessions {
		if err := h.deleteSessionWithHooks(ctx, s.Token); err != nil {
			return err
		}
	}
	return nil
}
