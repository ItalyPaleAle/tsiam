package keystorage

import (
	"context"
	"errors"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

var errKeyNoExist = errors.New("key not found")

// KeyStorage is an interface for persisting signing keys
type KeyStorage interface {
	// Load loads the signing key from storage
	// If the key doesn't exist, returns errKeyNoExit
	Load(ctx context.Context) (jwk.Key, error)
	// Store saves the signing key to storage
	Store(ctx context.Context, key jwk.Key) error
}

func IsKeyNotExistError(err error) bool {
	return errors.Is(err, errKeyNoExist)
}
