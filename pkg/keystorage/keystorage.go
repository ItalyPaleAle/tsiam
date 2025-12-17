package keystorage

import (
	"context"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// KeyStorage is an interface for persisting signing keys
type KeyStorage interface {
	// Load loads the signing key from storage
	Load(ctx context.Context) (jwk.Key, error)
	// Store saves the signing key to storage
	Store(ctx context.Context, key jwk.Key) error
}


