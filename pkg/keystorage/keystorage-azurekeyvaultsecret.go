package keystorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// AzureKeyVaultSecretClient is an interface for the Azure Key Vault Secrets client
// This allows for mocking in tests
type AzureKeyVaultSecretClient interface {
	GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
	SetSecret(ctx context.Context, name string, parameters azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error)
}

// AzureKeyVaultSecretStorage implements KeyStorage using Azure Key Vault Secrets
type AzureKeyVaultSecretStorage struct {
	client     AzureKeyVaultSecretClient
	secretName string
}

// NewAzureKeyVaultSecretStorage creates a new Azure Key Vault Secret-based key storage
func NewAzureKeyVaultSecretStorage(vaultURL string, secretName string, credential azcore.TokenCredential) (*AzureKeyVaultSecretStorage, error) {
	if vaultURL == "" {
		return nil, errors.New("vaultURL cannot be empty")
	}
	if secretName == "" {
		return nil, errors.New("secretName cannot be empty")
	}
	if credential == nil {
		return nil, errors.New("credential cannot be nil")
	}

	client, err := azsecrets.NewClient(vaultURL, credential, &azsecrets.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Telemetry: policy.TelemetryOptions{
				Disabled: true,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure Key Vault client: %w", err)
	}

	return &AzureKeyVaultSecretStorage{
		client:     client,
		secretName: secretName,
	}, nil
}

// NewAzureKeyVaultSecretStorageWithClient creates a new Azure Key Vault Secret-based key storage with a custom client
// This is primarily used for testing with mock clients
func NewAzureKeyVaultSecretStorageWithClient(client AzureKeyVaultSecretClient, secretName string) (*AzureKeyVaultSecretStorage, error) {
	if client == nil {
		return nil, errors.New("client cannot be nil")
	}
	if secretName == "" {
		return nil, errors.New("secretName cannot be empty")
	}

	return &AzureKeyVaultSecretStorage{
		client:     client,
		secretName: secretName,
	}, nil
}

// Load loads the signing key from Azure Key Vault
func (a *AzureKeyVaultSecretStorage) Load(ctx context.Context) (jwk.Key, error) {
	// Get the secret from Azure Key Vault (empty version gets the latest)
	resp, err := a.client.GetSecret(ctx, a.secretName, "", nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
			// Secret doesn't exist yet
			return nil, errKeyNoExist
		}
		return nil, fmt.Errorf("failed to get secret from Azure Key Vault: %w", err)
	}

	if resp.Value == nil {
		return nil, errors.New("secret value is nil")
	}

	// Parse the JWK from the secret value
	key, err := jwk.ParseKey([]byte(*resp.Value))
	if err != nil {
		return nil, fmt.Errorf("failed to parse key from secret: %w", err)
	}

	return key, nil
}

// Store saves the signing key to Azure Key Vault
func (a *AzureKeyVaultSecretStorage) Store(ctx context.Context, key jwk.Key) error {
	// Marshal the key to JSON
	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to encode key: %w", err)
	}

	// Store as secret value
	secretValue := string(data)
	params := azsecrets.SetSecretParameters{
		Value: &secretValue,
	}

	_, err = a.client.SetSecret(ctx, a.secretName, params, nil)
	if err != nil {
		return fmt.Errorf("failed to set secret in Azure Key Vault: %w", err)
	}

	return nil
}
