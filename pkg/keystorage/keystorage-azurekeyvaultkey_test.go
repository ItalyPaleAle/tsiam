package keystorage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/tsiam/pkg/jwks"
)

// MockAzureKeyVaultKeyClient is a mock implementation of AzureKeyVaultKeyClient
type MockAzureKeyVaultKeyClient struct {
	mock.Mock
}

func (m *MockAzureKeyVaultKeyClient) WrapKey(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	args := m.Called(ctx, keyName, keyVersion, parameters, options)
	return args.Get(0).(azkeys.WrapKeyResponse), args.Error(1) //nolint:forcetypeassert,wrapcheck
}

func (m *MockAzureKeyVaultKeyClient) UnwrapKey(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	args := m.Called(ctx, keyName, keyVersion, parameters, options)
	return args.Get(0).(azkeys.UnwrapKeyResponse), args.Error(1) //nolint:forcetypeassert,wrapcheck
}

func TestNewAzureKeyVaultKeyStorageWithClient(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "wrapped-key.bin")
	mockClient := &MockAzureKeyVaultKeyClient{}

	// Test with valid parameters
	storage, err := NewAzureKeyVaultKeyStorageWithClient(mockClient, "test-key", keyPath)
	require.NoError(t, err, "Failed to create storage with valid parameters")
	assert.NotNil(t, storage, "Storage should not be nil")
	assert.Equal(t, "test-key", storage.keyName, "Key name should match")
	assert.Equal(t, keyPath, storage.storagePath, "Storage path should match")

	// Test with nil client
	_, err = NewAzureKeyVaultKeyStorageWithClient(nil, "test-key", keyPath)
	require.Error(t, err, "Expected error with nil client")
	require.ErrorContains(t, err, "client cannot be nil")

	// Test with empty key name
	_, err = NewAzureKeyVaultKeyStorageWithClient(mockClient, "", keyPath)
	require.Error(t, err, "Expected error with empty key name")
	require.ErrorContains(t, err, "keyName cannot be empty")

	// Test with empty storage path
	_, err = NewAzureKeyVaultKeyStorageWithClient(mockClient, "test-key", "")
	require.Error(t, err, "Expected error with empty storage path")
	require.ErrorContains(t, err, "storagePath cannot be empty")
}

func TestAzureKeyVaultKeyStorage_LoadNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "wrapped-key.bin")
	mockClient := &MockAzureKeyVaultKeyClient{}

	storage, err := NewAzureKeyVaultKeyStorageWithClient(mockClient, "test-key", keyPath)
	require.NoError(t, err)

	// Test loading non-existent key (no file on disk)
	key, err := storage.Load(t.Context())
	require.ErrorIs(t, err, errKeyNoExist, "Loading non-existent key should return errKeyNoExist")
	require.Nil(t, key, "Expected nil key for non-existent file")

	// No mock expectations needed since file doesn't exist
}

func TestAzureKeyVaultKeyStorage_LoadExisting(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "wrapped-key.bin")
	mockClient := &MockAzureKeyVaultKeyClient{}

	storage, err := NewAzureKeyVaultKeyStorageWithClient(mockClient, "test-key", keyPath)
	require.NoError(t, err)

	// Generate a test key
	signingKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err, "Failed to generate test key")

	originalKeyID, ok := signingKey.KeyID()
	require.True(t, ok)

	// Marshal the key to JSON (this is what would be unwrapped)
	keyJSON, err := json.Marshal(signingKey)
	require.NoError(t, err)

	// Simulate wrapped data on disk
	wrappedData := []byte("wrapped-key-data-simulation")
	err = os.WriteFile(keyPath, wrappedData, 0600)
	require.NoError(t, err)

	// Mock UnwrapKey to return the original key
	mockClient.
		On(
			"UnwrapKey",
			mock.Anything,
			"test-key",
			"",
			mock.MatchedBy(func(params azkeys.KeyOperationParameters) bool {
				return params.Value != nil && string(params.Value) == string(wrappedData)
			}),
			mock.Anything,
		).
		Return(azkeys.UnwrapKeyResponse{
			KeyOperationResult: azkeys.KeyOperationResult{
				Result: keyJSON,
			},
		}, nil)

	// Load the key
	loadedKey, err := storage.Load(t.Context())
	require.NoError(t, err, "Failed to load key")
	require.NotNil(t, loadedKey, "Loaded key should not be nil")

	// Verify key properties
	kid, ok := loadedKey.KeyID()
	require.True(t, ok, "Loaded key should have a key ID")
	assert.Equal(t, originalKeyID, kid, "Key ID should match")

	alg, ok := loadedKey.Algorithm()
	require.True(t, ok, "Loaded key should have an algorithm")
	assert.Equal(t, jwa.ES256(), alg, "Algorithm should match")

	mockClient.AssertExpectations(t)
}

func TestAzureKeyVaultKeyStorage_LoadUnwrapError(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "wrapped-key.bin")
	mockClient := &MockAzureKeyVaultKeyClient{}

	storage, err := NewAzureKeyVaultKeyStorageWithClient(mockClient, "test-key", keyPath)
	require.NoError(t, err)

	// Write some wrapped data to disk
	wrappedData := []byte("wrapped-key-data")
	err = os.WriteFile(keyPath, wrappedData, 0600)
	require.NoError(t, err)

	// Mock UnwrapKey to return an error
	mockErr := errors.New("mock unwrap error")
	mockClient.On("UnwrapKey", mock.Anything, "test-key", "", mock.Anything, mock.Anything).Return(azkeys.UnwrapKeyResponse{}, mockErr)

	// Load should return error
	_, err = storage.Load(t.Context())
	require.Error(t, err, "Expected error when UnwrapKey fails")
	require.ErrorContains(t, err, "failed to unwrap key with Azure Key Vault")

	mockClient.AssertExpectations(t)
}

func TestAzureKeyVaultKeyStorage_Store(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "wrapped-key.bin")
	mockClient := &MockAzureKeyVaultKeyClient{}

	storage, err := NewAzureKeyVaultKeyStorageWithClient(mockClient, "test-key", keyPath)
	require.NoError(t, err)

	// Generate a test key
	signingKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err, "Failed to generate test key")

	// Mock WrapKey to return wrapped data
	wrappedData := []byte("wrapped-key-result")
	mockClient.
		On(
			"WrapKey",
			mock.Anything,
			"test-key",
			"",
			mock.MatchedBy(func(params azkeys.KeyOperationParameters) bool {
				// Verify that the value can be parsed as a JWK
				if params.Value == nil {
					return false
				}
				_, err := jwk.ParseKey(params.Value)
				return err == nil
			}),
			mock.Anything,
		).
		Return(azkeys.WrapKeyResponse{
			KeyOperationResult: azkeys.KeyOperationResult{
				Result: wrappedData,
			},
		}, nil)

	// Store the key
	err = storage.Store(t.Context(), signingKey)
	require.NoError(t, err, "Failed to store key")

	// Verify file exists and contains wrapped data
	storedData, err := os.ReadFile(keyPath) //nolint:gosec
	require.NoError(t, err, "Failed to read stored file")
	assert.Equal(t, wrappedData, storedData, "Stored data should match wrapped data")

	mockClient.AssertExpectations(t)
}

func TestAzureKeyVaultKeyStorage_StoreWrapError(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "wrapped-key.bin")
	mockClient := &MockAzureKeyVaultKeyClient{}

	storage, err := NewAzureKeyVaultKeyStorageWithClient(mockClient, "test-key", keyPath)
	require.NoError(t, err)

	// Generate a test key
	signingKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err, "Failed to generate test key")

	// Mock WrapKey to return an error
	mockErr := errors.New("mock wrap error")
	mockClient.On("WrapKey", mock.Anything, "test-key", "", mock.Anything, mock.Anything).Return(azkeys.WrapKeyResponse{}, mockErr)

	// Store should return error
	err = storage.Store(t.Context(), signingKey)
	require.Error(t, err, "Expected error when WrapKey fails")
	require.ErrorContains(t, err, "failed to wrap key with Azure Key Vault")

	mockClient.AssertExpectations(t)
}

func TestAzureKeyVaultKeyStorage_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "wrapped-key.bin")
	mockClient := &MockAzureKeyVaultKeyClient{}

	storage, err := NewAzureKeyVaultKeyStorageWithClient(mockClient, "test-key", keyPath)
	require.NoError(t, err)

	// Generate a test key
	signingKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err, "Failed to generate test key")

	originalKeyID, ok := signingKey.KeyID()
	require.True(t, ok)

	// Mock WrapKey to capture the original data and return wrapped data
	var originalKeyData []byte
	wrappedData := []byte("wrapped-key-simulation")
	mockClient.
		On("WrapKey", mock.Anything, "test-key", "", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			params := args.Get(3).(azkeys.KeyOperationParameters) //nolint:forcetypeassert
			if params.Value != nil {
				originalKeyData = make([]byte, len(params.Value))
				copy(originalKeyData, params.Value)
			}
		}).
		Return(azkeys.WrapKeyResponse{
			KeyOperationResult: azkeys.KeyOperationResult{
				Result: wrappedData,
			},
		}, nil)

	// Store the key
	err = storage.Store(t.Context(), signingKey)
	require.NoError(t, err, "Failed to store key")
	require.NotEmpty(t, originalKeyData, "Original key data should be captured")

	// Verify wrapped data is on disk
	storedData, err := os.ReadFile(keyPath) //nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, wrappedData, storedData)

	// Mock UnwrapKey to return the original data
	mockClient.
		On(
			"UnwrapKey",
			mock.Anything,
			"test-key",
			"",
			mock.MatchedBy(func(params azkeys.KeyOperationParameters) bool {
				return params.Value != nil && string(params.Value) == string(wrappedData)
			}),
			mock.Anything,
		).
		Return(azkeys.UnwrapKeyResponse{
			KeyOperationResult: azkeys.KeyOperationResult{
				Result: originalKeyData,
			},
		}, nil)

	// Load the key back
	loadedKey, err := storage.Load(t.Context())
	require.NoError(t, err, "Failed to load stored key")
	require.NotNil(t, loadedKey, "Loaded key should not be nil")

	// Verify key properties
	kid, ok := loadedKey.KeyID()
	require.True(t, ok, "Loaded key should have a key ID")
	assert.Equal(t, originalKeyID, kid, "Key ID should match")

	alg, ok := loadedKey.Algorithm()
	require.True(t, ok, "Loaded key should have an algorithm")
	assert.Equal(t, jwa.ES256(), alg, "Algorithm should match")

	mockClient.AssertExpectations(t)
}

func TestAzureKeyVaultKeyStorage_InvalidPath(t *testing.T) {
	mockClient := &MockAzureKeyVaultKeyClient{}

	// Try to create storage with invalid path
	_, err := NewAzureKeyVaultKeyStorageWithClient(mockClient, "test-key", "/invalid/nonexistent/deeply/nested/path/key.bin")
	require.Error(t, err, "Expected error for invalid path")
}
