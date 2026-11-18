package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/tsiam/pkg/jwks"
	"github.com/italypaleale/tsiam/pkg/keystorage"
)

// Wraps KeyStorage to run a hook before Store
type racingKeyStorage struct {
	keystorage.KeyStorage

	beforeStore func()
}

func (r racingKeyStorage) Store(ctx context.Context, key jwk.Key) error {
	r.beforeStore()
	return r.KeyStorage.Store(ctx, key) //nolint:wrapcheck
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

func TestGetAzureKeyVaultCredentials(t *testing.T) {
	t.Run("client secret", func(t *testing.T) {
		creds, err := getAzureKeyVaultCredentials("00000000-0000-0000-0000-000000000000", "client", "secret")
		require.NoError(t, err)
		assert.IsType(t, &azidentity.ClientSecretCredential{}, creds)
	})

	t.Run("client ID selects a user-assigned managed identity", func(t *testing.T) {
		t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")

		creds, err := getAzureKeyVaultCredentials("", "client", "")
		require.NoError(t, err)
		assert.IsType(t, &azidentity.ManagedIdentityCredential{}, creds)
	})

	t.Run("client ID selects workload identity when the federated token file is set", func(t *testing.T) {
		t.Setenv("AZURE_FEDERATED_TOKEN_FILE", filepath.Join(t.TempDir(), "token"))

		creds, err := getAzureKeyVaultCredentials("00000000-0000-0000-0000-000000000000", "client", "")
		require.NoError(t, err)
		assert.IsType(t, &azidentity.WorkloadIdentityCredential{}, creds)
	})

	t.Run("no client ID uses the default credentials", func(t *testing.T) {
		creds, err := getAzureKeyVaultCredentials("00000000-0000-0000-0000-000000000000", "", "")
		require.NoError(t, err)
		assert.IsType(t, &azidentity.DefaultAzureCredential{}, creds)
	})
}
