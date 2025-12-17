package keystorage

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/tsiam/pkg/jwks"
)

// MockAzureKeyVaultSecretClient is a mock implementation of AzureKeyVaultSecretClient
type MockAzureKeyVaultSecretClient struct {
	mock.Mock
}

func (m *MockAzureKeyVaultSecretClient) GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	args := m.Called(ctx, name, version, options)
	return args.Get(0).(azsecrets.GetSecretResponse), args.Error(1)
}

func (m *MockAzureKeyVaultSecretClient) SetSecret(ctx context.Context, name string, parameters azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
	args := m.Called(ctx, name, parameters, options)
	return args.Get(0).(azsecrets.SetSecretResponse), args.Error(1)
}

func TestNewAzureKeyVaultSecretStorageWithClient(t *testing.T) {
	mockClient := new(MockAzureKeyVaultSecretClient)

	// Test with valid parameters
	storage, err := NewAzureKeyVaultSecretStorageWithClient(mockClient, "test-secret")
	require.NoError(t, err, "Failed to create storage with valid parameters")
	assert.NotNil(t, storage, "Storage should not be nil")
	assert.Equal(t, "test-secret", storage.secretName, "Secret name should match")

	// Test with nil client
	_, err = NewAzureKeyVaultSecretStorageWithClient(nil, "test-secret")
	require.Error(t, err, "Expected error with nil client")
	assert.Contains(t, err.Error(), "client cannot be nil")

	// Test with empty secret name
	_, err = NewAzureKeyVaultSecretStorageWithClient(mockClient, "")
	require.Error(t, err, "Expected error with empty secret name")
	assert.Contains(t, err.Error(), "secretName cannot be empty")
}

func TestAzureKeyVaultSecretStorage_LoadNonExistent(t *testing.T) {
	mockClient := new(MockAzureKeyVaultSecretClient)
	storage, err := NewAzureKeyVaultSecretStorageWithClient(mockClient, "test-secret")
	require.NoError(t, err)

	// Mock GetSecret to return 404 error
	respErr := &azcore.ResponseError{
		StatusCode: 404,
	}
	mockClient.On("GetSecret", mock.Anything, "test-secret", "", mock.Anything).Return(azsecrets.GetSecretResponse{}, respErr)

	// Test loading non-existent key
	key, err := storage.Load(context.Background())
	require.NoError(t, err, "Loading non-existent key should not return error")
	assert.Nil(t, key, "Expected nil key for non-existent secret")

	mockClient.AssertExpectations(t)
}

func TestAzureKeyVaultSecretStorage_LoadExisting(t *testing.T) {
	mockClient := new(MockAzureKeyVaultSecretClient)
	storage, err := NewAzureKeyVaultSecretStorageWithClient(mockClient, "test-secret")
	require.NoError(t, err)

	// Generate a test key
	signingKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err, "Failed to generate test key")

	originalKeyID, ok := signingKey.KeyID()
	require.True(t, ok)

	// Marshal the key to JSON
	keyJSON, err := json.Marshal(signingKey)
	require.NoError(t, err)

	// Mock GetSecret to return the key
	secretValue := string(keyJSON)
	mockClient.On("GetSecret", mock.Anything, "test-secret", "", mock.Anything).Return(azsecrets.GetSecretResponse{
		Secret: azsecrets.Secret{
			Value: &secretValue,
		},
	}, nil)

	// Load the key
	loadedKey, err := storage.Load(context.Background())
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

func TestAzureKeyVaultSecretStorage_LoadError(t *testing.T) {
	mockClient := new(MockAzureKeyVaultSecretClient)
	storage, err := NewAzureKeyVaultSecretStorageWithClient(mockClient, "test-secret")
	require.NoError(t, err)

	// Mock GetSecret to return an error
	mockErr := errors.New("mock error")
	mockClient.On("GetSecret", mock.Anything, "test-secret", "", mock.Anything).Return(azsecrets.GetSecretResponse{}, mockErr)

	// Load should return error
	_, err = storage.Load(context.Background())
	require.Error(t, err, "Expected error when GetSecret fails")
	assert.Contains(t, err.Error(), "failed to get secret from Azure Key Vault")

	mockClient.AssertExpectations(t)
}

func TestAzureKeyVaultSecretStorage_Store(t *testing.T) {
	mockClient := new(MockAzureKeyVaultSecretClient)
	storage, err := NewAzureKeyVaultSecretStorageWithClient(mockClient, "test-secret")
	require.NoError(t, err)

	// Generate a test key
	signingKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err, "Failed to generate test key")

	// Mock SetSecret to succeed
	mockClient.On("SetSecret", mock.Anything, "test-secret", mock.MatchedBy(func(params azsecrets.SetSecretParameters) bool {
		// Verify that the secret value can be parsed as a JWK
		if params.Value == nil {
			return false
		}
		_, err := jwk.ParseKey([]byte(*params.Value))
		return err == nil
	}), mock.Anything).Return(azsecrets.SetSecretResponse{}, nil)

	// Store the key
	err = storage.Store(context.Background(), signingKey)
	require.NoError(t, err, "Failed to store key")

	mockClient.AssertExpectations(t)
}

func TestAzureKeyVaultSecretStorage_StoreError(t *testing.T) {
	mockClient := new(MockAzureKeyVaultSecretClient)
	storage, err := NewAzureKeyVaultSecretStorageWithClient(mockClient, "test-secret")
	require.NoError(t, err)

	// Generate a test key
	signingKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err, "Failed to generate test key")

	// Mock SetSecret to return an error
	mockErr := errors.New("mock error")
	mockClient.On("SetSecret", mock.Anything, "test-secret", mock.Anything, mock.Anything).Return(azsecrets.SetSecretResponse{}, mockErr)

	// Store should return error
	err = storage.Store(context.Background(), signingKey)
	require.Error(t, err, "Expected error when SetSecret fails")
	assert.Contains(t, err.Error(), "failed to set secret in Azure Key Vault")

	mockClient.AssertExpectations(t)
}

func TestAzureKeyVaultSecretStorage_RoundTrip(t *testing.T) {
	mockClient := new(MockAzureKeyVaultSecretClient)
	storage, err := NewAzureKeyVaultSecretStorageWithClient(mockClient, "test-secret")
	require.NoError(t, err)

	// Generate a test key
	signingKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err, "Failed to generate test key")

	originalKeyID, ok := signingKey.KeyID()
	require.True(t, ok)

	// Mock SetSecret to capture the stored value
	var storedValue string
	mockClient.On("SetSecret", mock.Anything, "test-secret", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			params := args.Get(2).(azsecrets.SetSecretParameters)
			if params.Value != nil {
				storedValue = *params.Value
			}
		}).
		Return(azsecrets.SetSecretResponse{}, nil)

	// Store the key
	err = storage.Store(context.Background(), signingKey)
	require.NoError(t, err, "Failed to store key")
	require.NotEmpty(t, storedValue, "Stored value should not be empty")

	// Mock GetSecret to return the stored value
	mockClient.On("GetSecret", mock.Anything, "test-secret", "", mock.Anything).Return(azsecrets.GetSecretResponse{
		Secret: azsecrets.Secret{
			Value: &storedValue,
		},
	}, nil)

	// Load the key back
	loadedKey, err := storage.Load(context.Background())
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
