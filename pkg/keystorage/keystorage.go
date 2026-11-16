package keystorage

import (
	"context"
	"errors"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

var (
	errKeyNoExist = errors.New("key not found")
	errKeyExists  = errors.New("key already exists")
)

// keyID returns the key's `kid` for use in log fields, or an empty string if unset
func keyID(key jwk.Key) string {
	kid, _ := key.KeyID()
	return kid
}

// KeyStorage is an interface for persisting signing keys
type KeyStorage interface {
	// Load loads the signing key from storage
	// If the key doesn't exist, returns an error for which IsKeyNotExistError returns true
	Load(ctx context.Context) (jwk.Key, error)
	// Store saves a new signing key to storage, if the storage doesn't contain a key yet
	// If it does, returns an error for which IsKeyExistError returns true, so instances that start at the same time end up using the same key
	// Storage backends that can't check this atomically overwrite the existing key instead
	Store(ctx context.Context, key jwk.Key) error
}

// IsKeyNotExistError returns true if the error indicates that the storage doesn't contain a key
func IsKeyNotExistError(err error) bool {
	return errors.Is(err, errKeyNoExist)
}

// IsKeyExistError returns true if the error indicates that the storage already contains a key
func IsKeyExistError(err error) bool {
	return errors.Is(err, errKeyExists)
}
