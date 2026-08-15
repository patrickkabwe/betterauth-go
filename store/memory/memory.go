package memory

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/patrickkabwe/betterauth-go/errors"
	"github.com/patrickkabwe/betterauth-go/store"
	"github.com/patrickkabwe/betterauth-go/types"
)

// ErrNotFound is re-exported for backward compatibility.
var ErrNotFound = errors.ErrNotFound

// ErrAlreadyExists is re-exported for backward compatibility.
var ErrAlreadyExists = errors.ErrAlreadyExists

// Store is an in-memory Store implementation.
type Store struct {
	mu            sync.RWMutex
	users         map[string]*types.User
	usersByEmail  map[string]string
	accounts      map[string]*types.Account
	sessions      map[string]*types.Session
	verifications map[string]*types.Verification

	orgs              map[string]*types.Organization
	orgsBySlug        map[string]string
	members           map[string]*types.Member
	invitations       map[string]*types.Invitation
	teams             map[string]*types.Team
	teamMembers       map[string]*types.TeamMember
	organizationRoles map[string]*types.OrganizationRole
	twoFactor         map[string]*types.TwoFactorRecord
	deviceCodes       map[string]*types.DeviceCode
	deviceCodesByUser map[string]string
	jwks              map[string]*types.JWKSRecord
	oauthApps         map[string]*types.OAuthApplication
	wallets           map[string]*types.WalletAddress
}

// New creates a new in-memory store.
func New() *Store {
	return &Store{
		users:             make(map[string]*types.User),
		usersByEmail:      make(map[string]string),
		accounts:          make(map[string]*types.Account),
		sessions:          make(map[string]*types.Session),
		verifications:     make(map[string]*types.Verification),
		orgs:              make(map[string]*types.Organization),
		orgsBySlug:        make(map[string]string),
		members:           make(map[string]*types.Member),
		invitations:       make(map[string]*types.Invitation),
		teams:             make(map[string]*types.Team),
		teamMembers:       make(map[string]*types.TeamMember),
		organizationRoles: make(map[string]*types.OrganizationRole),
		twoFactor:         make(map[string]*types.TwoFactorRecord),
		deviceCodes:       make(map[string]*types.DeviceCode),
		deviceCodesByUser: make(map[string]string),
		jwks:              make(map[string]*types.JWKSRecord),
		oauthApps:         make(map[string]*types.OAuthApplication),
		wallets:           make(map[string]*types.WalletAddress),
	}
}

func (s *Store) CreateUser(_ context.Context, user *types.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.usersByEmail[user.Email]; ok {
		return ErrAlreadyExists
	}
	u := *user
	s.users[user.ID] = &u
	s.usersByEmail[user.Email] = user.ID
	return nil
}

func (s *Store) UpdateUser(_ context.Context, id string, update store.UserUpdate) (*types.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	if update.Name != nil {
		u.Name = *update.Name
	}
	if update.Email != nil {
		delete(s.usersByEmail, u.Email)
		u.Email = *update.Email
		s.usersByEmail[u.Email] = id
	}
	if update.EmailVerified != nil {
		u.EmailVerified = *update.EmailVerified
	}
	if update.Image != nil {
		u.Image = *update.Image
	}
	if len(update.Additional) > 0 {
		if u.Additional == nil {
			u.Additional = make(map[string]any)
		}
		for k, v := range update.Additional {
			u.Additional[k] = v
		}
	}
	u.UpdatedAt = time.Now()
	copy := *u
	return &copy, nil
}

func (s *Store) FindUserByEmail(_ context.Context, email string) (*types.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.usersByEmail[email]
	if !ok {
		return nil, ErrNotFound
	}
	u := *s.users[id]
	return &u, nil
}

func (s *Store) FindUserByID(_ context.Context, id string) (*types.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	copy := *u
	return &copy, nil
}

func (s *Store) DeleteUser(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.usersByEmail, u.Email)
	delete(s.users, id)
	for accID, a := range s.accounts {
		if a.UserID == id {
			delete(s.accounts, accID)
		}
	}
	for token, sess := range s.sessions {
		if sess.UserID == id {
			delete(s.sessions, token)
		}
	}
	return nil
}

func (s *Store) CreateAccount(_ context.Context, account *types.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := *account
	s.accounts[account.ID] = &a
	return nil
}

func (s *Store) UpdateAccount(_ context.Context, id string, update store.AccountUpdate) (*types.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[id]
	if !ok {
		return nil, ErrNotFound
	}
	if update.AccessToken != nil {
		a.AccessToken = *update.AccessToken
	}
	if update.RefreshToken != nil {
		a.RefreshToken = *update.RefreshToken
	}
	if update.AccessTokenExpiresAt != nil {
		a.AccessTokenExpiresAt = update.AccessTokenExpiresAt
	}
	if update.RefreshTokenExpiresAt != nil {
		a.RefreshTokenExpiresAt = update.RefreshTokenExpiresAt
	}
	if update.IDToken != nil {
		a.IDToken = *update.IDToken
	}
	if update.Scope != nil {
		a.Scope = *update.Scope
	}
	a.UpdatedAt = time.Now()
	copy := *a
	return &copy, nil
}

func (s *Store) UpdateAccountPassword(_ context.Context, userID, providerID, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.UserID == userID && a.ProviderID == providerID {
			a.Password = password
			a.UpdatedAt = time.Now()
			return nil
		}
	}
	return ErrNotFound
}

func (s *Store) FindAccountByProviderAndAccountID(_ context.Context, providerID, accountID string) (*types.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.accounts {
		if a.ProviderID == providerID && a.AccountID == accountID {
			copy := *a
			return &copy, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) FindAccountByUserAndProvider(_ context.Context, userID, providerID string) (*types.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.accounts {
		if a.UserID == userID && a.ProviderID == providerID {
			copy := *a
			return &copy, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) ListAccountsByUserID(_ context.Context, userID string) ([]types.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var accounts []types.Account
	for _, a := range s.accounts {
		if a.UserID == userID {
			accounts = append(accounts, *a)
		}
	}
	return accounts, nil
}

func (s *Store) DeleteAccount(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[id]; !ok {
		return ErrNotFound
	}
	delete(s.accounts, id)
	return nil
}

func (s *Store) CreateSession(_ context.Context, session *types.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := *session
	s.sessions[session.Token] = &sess
	return nil
}

func (s *Store) UpdateSession(_ context.Context, token string, update store.SessionUpdate) (*types.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return nil, ErrNotFound
	}
	if update.ExpiresAt != nil {
		sess.ExpiresAt = *update.ExpiresAt
	}
	if update.UpdatedAt != nil {
		sess.UpdatedAt = *update.UpdatedAt
	}
	if update.IPAddress != nil {
		sess.IPAddress = *update.IPAddress
	}
	if update.UserAgent != nil {
		sess.UserAgent = *update.UserAgent
	}
	if len(update.Additional) > 0 {
		if sess.Additional == nil {
			sess.Additional = make(map[string]any)
		}
		for k, v := range update.Additional {
			sess.Additional[k] = v
		}
	}
	copy := *sess
	return &copy, nil
}

func (s *Store) ListUsers(_ context.Context, opts store.ListUsersOpts) ([]types.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	search := strings.ToLower(opts.Search)
	var out []types.User
	for _, u := range s.users {
		if search != "" {
			if !strings.Contains(strings.ToLower(u.Email), search) &&
				!strings.Contains(strings.ToLower(u.Name), search) {
				continue
			}
		}
		out = append(out, *u)
	}
	if opts.Offset >= len(out) {
		return []types.User{}, nil
	}
	end := opts.Offset + limit
	if end > len(out) {
		end = len(out)
	}
	slice := out[opts.Offset:end]
	return slice, nil
}

func (s *Store) FindSessionByToken(_ context.Context, token string) (*types.Session, *types.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[token]
	if !ok {
		return nil, nil, ErrNotFound
	}
	user, ok := s.users[sess.UserID]
	if !ok {
		return nil, nil, ErrNotFound
	}
	sCopy := *sess
	uCopy := *user
	return &sCopy, &uCopy, nil
}

func (s *Store) ListSessionsByUserID(_ context.Context, userID string) ([]types.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var sessions []types.Session
	for _, sess := range s.sessions {
		if sess.UserID == userID {
			sessions = append(sessions, *sess)
		}
	}
	return sessions, nil
}

func (s *Store) DeleteSession(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
	return nil
}

func (s *Store) DeleteSessionsByUserID(_ context.Context, userID, exceptToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, sess := range s.sessions {
		if sess.UserID == userID && token != exceptToken {
			delete(s.sessions, token)
		}
	}
	return nil
}

func (s *Store) DeleteAllSessionsByUserID(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, token)
		}
	}
	return nil
}

func (s *Store) CreateVerification(_ context.Context, v *types.Verification) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := *v
	s.verifications[v.Identifier] = &copy
	return nil
}

func (s *Store) FindVerificationByIdentifier(_ context.Context, identifier string) (*types.Verification, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.verifications[identifier]
	if !ok {
		return nil, ErrNotFound
	}
	copy := *v
	return &copy, nil
}

func (s *Store) DeleteVerificationByIdentifier(_ context.Context, identifier string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.verifications[identifier]; !ok {
		return ErrNotFound
	}
	delete(s.verifications, identifier)
	return nil
}
