package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/tsiam/pkg/jwks"
	"github.com/italypaleale/tsiam/pkg/keystorage"
)

// Wraps a key storage to run a function before Store, which can simulate another instance storing its key first
type racingKeyStorage struct {
	keystorage.KeyStorage

	beforeStore func()
}

func (r racingKeyStorage) Store(ctx context.Context, key jwk.Key) error {
	r.beforeStore()
	return r.KeyStorage.Store(ctx, key) //nolint:wrapcheck // loadOrCreateKey must see the storage's error unchanged
}

func TestLoadOrCreateKey(t *testing.T) {
	newStorage := func(t *testing.T, path string) keystorage.KeyStorage {
		t.Helper()
		ks, err := keystorage.NewFileKeyStorage(path)
		require.NoError(t, err)
		return ks
	}
	kid := func(key jwk.Key) string {
		kid, _ := key.KeyID()
		return kid
	}

	t.Run("loads an existing key", func(t *testing.T) {
		ks := newStorage(t, filepath.Join(t.TempDir(), "key.json"))
		existing, err := jwks.NewSigningKey("ES256", "")
		require.NoError(t, err)
		err = ks.Store(t.Context(), existing)
		require.NoError(t, err)

		key, err := loadOrCreateKey(t.Context(), ks)
		require.NoError(t, err)
		assert.Equal(t, kid(existing), kid(key))
	})

	t.Run("creates and stores a new key", func(t *testing.T) {
		ks := newStorage(t, filepath.Join(t.TempDir(), "key.json"))

		key, err := loadOrCreateKey(t.Context(), ks)
		require.NoError(t, err)

		stored, err := ks.Load(t.Context())
		require.NoError(t, err)
		assert.Equal(t, kid(key), kid(stored))
	})

	t.Run("uses the key stored by another instance", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key.json")
		other, err := jwks.NewSigningKey("ES256", "")
		require.NoError(t, err)

		ks := racingKeyStorage{
			KeyStorage: newStorage(t, path),
			beforeStore: func() {
				err := newStorage(t, path).Store(t.Context(), other)
				require.NoError(t, err)
			},
		}

		key, err := loadOrCreateKey(t.Context(), ks)
		require.NoError(t, err)
		assert.Equal(t, kid(other), kid(key))

		stored, err := ks.Load(t.Context())
		require.NoError(t, err)
		assert.Equal(t, kid(other), kid(stored))
	})
}
