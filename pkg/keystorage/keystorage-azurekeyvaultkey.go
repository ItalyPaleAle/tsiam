package keystorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// AzureKeyVaultKeyClient is an interface for the Azure Key Vault Keys client
// This allows for mocking in tests
type AzureKeyVaultKeyClient interface {
	WrapKey(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error)
	UnwrapKey(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error)
}

// AzureKeyVaultKeyStorage implements KeyStorage using Azure Key Vault Keys for wrapping
// The signing key is stored on disk in wrapped (encrypted) form and unwrapped on load
type AzureKeyVaultKeyStorage struct {
	client    AzureKeyVaultKeyClient
	keyName   string
	storagePath string
	algorithm azkeys.EncryptionAlgorithm
}

// NewAzureKeyVaultKeyStorage creates a new Azure Key Vault Key-based key storage
// The key is stored on disk in wrapped form and unwrapped using Azure Key Vault on load
func NewAzureKeyVaultKeyStorage(vaultURL string, keyName string, storagePath string, credential azcore.TokenCredential) (*AzureKeyVaultKeyStorage, error) {
	if vaultURL == "" {
		return nil, errors.New("vaultURL cannot be empty")
	}
	if keyName == "" {
		return nil, errors.New("keyName cannot be empty")
	}
	if storagePath == "" {
		return nil, errors.New("storagePath cannot be empty")
	}
	if credential == nil {
		return nil, errors.New("credential cannot be nil")
	}

	// Ensure directory exists
	dir := filepath.Dir(storagePath)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to create key storage directory: %w", err)
	}

	client, err := azkeys.NewClient(vaultURL, credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure Key Vault client: %w", err)
	}

	return &AzureKeyVaultKeyStorage{
		client:      client,
		keyName:     keyName,
		storagePath: storagePath,
		algorithm:   azkeys.EncryptionAlgorithmRSAOAEP256,
	}, nil
}

// NewAzureKeyVaultKeyStorageWithClient creates a new Azure Key Vault Key-based key storage with a custom client
// This is primarily used for testing with mock clients
func NewAzureKeyVaultKeyStorageWithClient(client AzureKeyVaultKeyClient, keyName string, storagePath string) (*AzureKeyVaultKeyStorage, error) {
	if client == nil {
		return nil, errors.New("client cannot be nil")
	}
	if keyName == "" {
		return nil, errors.New("keyName cannot be empty")
	}
	if storagePath == "" {
		return nil, errors.New("storagePath cannot be empty")
	}

	// Ensure directory exists
	dir := filepath.Dir(storagePath)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to create key storage directory: %w", err)
	}

	return &AzureKeyVaultKeyStorage{
		client:      client,
		keyName:     keyName,
		storagePath: storagePath,
		algorithm:   azkeys.EncryptionAlgorithmRSAOAEP256,
	}, nil
}

// Load loads the signing key from disk and unwraps it using Azure Key Vault
func (a *AzureKeyVaultKeyStorage) Load(ctx context.Context) (jwk.Key, error) {
	// Read the wrapped key from disk
	wrappedData, err := os.ReadFile(a.storagePath)
	if err != nil {
		if os.IsNotExist(err) {
			// Key doesn't exist yet
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read wrapped key file: %w", err)
	}

	// Unwrap the key using Azure Key Vault
	params := azkeys.KeyOperationParameters{
		Algorithm: &a.algorithm,
		Value:     wrappedData,
	}

	resp, err := a.client.UnwrapKey(ctx, a.keyName, "", params, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key with Azure Key Vault: %w", err)
	}

	if resp.Result == nil {
		return nil, errors.New("unwrapped key result is nil")
	}

	// Parse the JWK from the unwrapped data
	key, err := jwk.ParseKey(resp.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse unwrapped key: %w", err)
	}

	return key, nil
}

// Store saves the signing key to disk in wrapped (encrypted) form using Azure Key Vault
func (a *AzureKeyVaultKeyStorage) Store(ctx context.Context, key jwk.Key) error {
	// Marshal the key to JSON
	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to encode key: %w", err)
	}

	// Wrap the key using Azure Key Vault
	params := azkeys.KeyOperationParameters{
		Algorithm: &a.algorithm,
		Value:     data,
	}

	resp, err := a.client.WrapKey(ctx, a.keyName, "", params, nil)
	if err != nil {
		return fmt.Errorf("failed to wrap key with Azure Key Vault: %w", err)
	}

	if resp.Result == nil {
		return errors.New("wrapped key result is nil")
	}

	// Write the wrapped key to disk with restricted permissions
	err = os.WriteFile(a.storagePath, resp.Result, 0600)
	if err != nil {
		return fmt.Errorf("failed to write wrapped key file: %w", err)
	}

	return nil
}
