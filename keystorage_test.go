package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err, "Failed to load non-existent key")
	assert.Nil(t, key, "Expected nil key for non-existent file")

	// Generate a test key
	err = generateSigningKey("ES256", "")
	require.NoError(t, err, "Failed to generate test key")
	originalKeyID := keyID

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

func TestFileKeyStorage_InvalidPath(t *testing.T) {
	// Try to create storage with invalid path
	_, err := NewFileKeyStorage("/invalid/nonexistent/path/key.pem")
	require.Error(t, err, "Expected error for invalid path")
}
