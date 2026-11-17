package keystorage

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/tsiam/pkg/jwks"
)

func TestFileKeyStorage(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test-key.pem")

	// Create storage
	storage, err := NewFileKeyStorage(keyPath)
	require.NoError(t, err, "Failed to create file storage")

	// Test loading non-existent key
	key, err := storage.Load(t.Context())
	require.ErrorIs(t, err, errKeyNoExist, "Loading non-existent key should return errKeyNoExist")
	require.Nil(t, key, "Expected nil key for non-existent file")

	// Generate a test key
	signingKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err, "Failed to generate test key")

	originalKeyID, ok := signingKey.KeyID()
	require.True(t, ok)
	require.NotNil(t, originalKeyID)

	// Store the key
	err = storage.Store(t.Context(), signingKey)
	require.NoError(t, err, "Failed to store key")

	// Verify file exists
	_, err = os.Stat(keyPath)
	require.NoError(t, err, "Key file was not created")

	// Load the key back
	loadedKey, err := storage.Load(t.Context())
	require.NoError(t, err, "Failed to load stored key")
	require.NotNil(t, loadedKey, "Loaded key is nil")

	// Verify key properties
	kid, ok := loadedKey.KeyID()
	require.True(t, ok, "Loaded key has no key ID")
	assert.Equal(t, originalKeyID, kid, "Key ID mismatch")

	alg, ok := loadedKey.Algorithm()
	require.True(t, ok, "Loaded key has no algorithm")
	assert.Equal(t, jwa.ES256(), alg, "Algorithm mismatch")
}

func TestFileKeyStorage_StoreExisting(t *testing.T) {
	storage, err := NewFileKeyStorage(filepath.Join(t.TempDir(), "key.json"))
	require.NoError(t, err)

	firstKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err)
	err = storage.Store(t.Context(), firstKey)
	require.NoError(t, err)

	// Another instance stored its key first, so this one isn't saved
	secondKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err)
	err = storage.Store(t.Context(), secondKey)
	require.Error(t, err)
	assert.True(t, IsKeyExistError(err))

	loadedKey, err := storage.Load(t.Context())
	require.NoError(t, err)
	expectedKid, _ := firstKey.KeyID()
	kid, _ := loadedKey.KeyID()
	assert.Equal(t, expectedKid, kid)
}

func TestFileKeyStorage_InvalidPath(t *testing.T) {
	// Try to create storage with invalid path
	_, err := NewFileKeyStorage("/invalid/nonexistent/path/key.pem")
	require.Error(t, err, "Expected error for invalid path")
}

func TestFileKeyStorage_LoadWarnings(t *testing.T) {
	newStoredKey := func(t *testing.T) *FileKeyStorage {
		t.Helper()
		storage, err := NewFileKeyStorage(filepath.Join(t.TempDir(), "key.json"))
		require.NoError(t, err)
		signingKey, err := jwks.NewSigningKey("ES256", "")
		require.NoError(t, err)
		err = storage.Store(t.Context(), signingKey)
		require.NoError(t, err)
		return storage
	}

	t.Run("Empty file is treated as missing, with a warning", func(t *testing.T) {
		storage, err := NewFileKeyStorage(filepath.Join(t.TempDir(), "key.json"))
		require.NoError(t, err)
		err = os.WriteFile(storage.path, nil, 0600)
		require.NoError(t, err)

		logs := captureLogs(t)
		key, err := storage.Load(t.Context())
		require.ErrorIs(t, err, errKeyNoExist)
		require.Nil(t, key)
		assert.Contains(t, logs.String(), "level=WARN")
		assert.Contains(t, logs.String(), "Signing key file is empty")
	})

	t.Run("No warning for a key file with mode 0600", func(t *testing.T) {
		storage := newStoredKey(t)

		logs := captureLogs(t)
		_, err := storage.Load(t.Context())
		require.NoError(t, err)
		assert.NotContains(t, logs.String(), "level=WARN")
	})

	for _, mode := range []os.FileMode{0o640, 0o604, 0o620, 0o644} {
		t.Run("Warns about a key file with mode "+mode.String(), func(t *testing.T) {
			// Permission bits are not meaningful on Windows
			if runtime.GOOS == "windows" {
				t.Skip("skipping permission check on Windows")
			}
			storage := newStoredKey(t)
			err := os.Chmod(storage.path, mode)
			require.NoError(t, err)

			logs := captureLogs(t)
			_, err = storage.Load(t.Context())
			require.NoError(t, err)
			assert.Contains(t, logs.String(), "level=WARN")
			assert.Contains(t, logs.String(), "can be accessed by users other than its owner")
		})
	}

	t.Run("Checks the file that a symlink points to", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping permission check on Windows")
		}
		storage := newStoredKey(t)

		// Kubernetes mounts Secrets as symlinks, which must keep working
		link := filepath.Join(t.TempDir(), "link.json")
		err := os.Symlink(storage.path, link)
		require.NoError(t, err)
		err = os.Chmod(storage.path, 0o644) // #nosec G302 -- The test needs a key file that other users can read
		require.NoError(t, err)
		linked, err := NewFileKeyStorage(link)
		require.NoError(t, err)

		logs := captureLogs(t)
		_, err = linked.Load(t.Context())
		require.NoError(t, err)
		assert.Contains(t, logs.String(), "can be accessed by users other than its owner")
	})
}
