package crypto

// Hasher hashes and verifies passwords.
type Hasher interface {
	Hash(password string) (string, error)
	Verify(hash, password string) (bool, error)
}

// ScryptHasher uses scrypt (Better Auth default).
type ScryptHasher struct{}

func (ScryptHasher) Hash(password string) (string, error) {
	return HashPassword(password)
}

func (ScryptHasher) Verify(hash, password string) (bool, error) {
	return VerifyPassword(hash, password)
}

// FuncHasher wraps custom hash/verify functions.
type FuncHasher struct {
	HashFn   func(password string) (string, error)
	VerifyFn func(hash, password string) (bool, error)
}

func (f FuncHasher) Hash(password string) (string, error) {
	return f.HashFn(password)
}

func (f FuncHasher) Verify(hash, password string) (bool, error) {
	return f.VerifyFn(hash, password)
}
