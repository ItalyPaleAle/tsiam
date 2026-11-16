package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/italypaleale/tsiam/pkg/config"
	"github.com/italypaleale/tsiam/pkg/jwks"
	"github.com/italypaleale/tsiam/pkg/keystorage"
)

func getKey(ctx context.Context) (jwk.Key, error) {
	cfg := config.Get()

	// Get the key storage
	ks, err := getKeyStorage()
	if err != nil {
		return nil, fmt.Errorf("failed to get key storage: %w", err)
	}

	// If key storage is nil, we are using an in-memory storage
	if ks == nil {
		return newSigningKey()
	}

	key, err := loadOrCreateKey(ctx, ks)
	if err != nil {
		return nil, err
	}

	keyAlgorithm := jwks.KeyAlgorithm(key)
	if keyAlgorithm != cfg.SigningKey.Algorithm {
		slog.WarnContext(ctx, "Stored signing key doesn't use the algorithm set in 'signingKey.algorithm', so tokens are signed with the stored key's algorithm - to switch, delete the stored key and restart tsiam",
			slog.String("keyAlgorithm", keyAlgorithm),
			slog.String("configuredAlgorithm", cfg.SigningKey.Algorithm),
		)
	}

	return key, nil
}

// Loads the key from storage, or generates and stores a new one if the storage doesn't contain a key yet
func loadOrCreateKey(ctx context.Context, ks keystorage.KeyStorage) (jwk.Key, error) {
	key, err := ks.Load(ctx)
	switch {
	case err == nil:
		return key, nil
	case !keystorage.IsKeyNotExistError(err):
		return nil, fmt.Errorf("failed to load existing key: %w", err)
	}

	// Key doesn't exist - need to generate a new one
	key, err = newSigningKey()
	if err != nil {
		return nil, err
	}

	// Persist the new key
	err = ks.Store(ctx, key)
	switch {
	case err == nil:
		return key, nil
	case keystorage.IsKeyExistError(err):
		// Another instance stored its key in the meantime, so use that one instead
		slog.InfoContext(ctx, "Another instance stored a signing key first, using that key instead")
		key, err = ks.Load(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to load key stored by another instance: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("failed to store newly-generated key: %w", err)
	}
}

func getKeyStorage() (s keystorage.KeyStorage, err error) {
	var creds azcore.TokenCredential
	cfg := config.Get()
	switch cfg.SigningKey.Storage {
	case "file":
		s, err = keystorage.NewFileKeyStorage(cfg.SigningKey.File.StoragePath)
	case "memory":
		// No-op
		s = nil
	case "azurekeyvaultkeys":
		akvk := cfg.SigningKey.AzureKeyVaultKeys
		creds, err = getAzureKeyVaultCredentials(akvk.TenantID, akvk.ClientID, akvk.ClientSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to get Azure credentials object: %w", err)
		}
		s, err = keystorage.NewAzureKeyVaultKeyStorage(akvk.VaultURL, akvk.KeyName, akvk.KeyVersion, akvk.StoragePath, creds)
	case "azurekeyvaultsecrets":
		akvs := cfg.SigningKey.AzureKeyVaultSecrets
		creds, err = getAzureKeyVaultCredentials(akvs.TenantID, akvs.ClientID, akvs.ClientSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to get Azure credentials object: %w", err)
		}
		s, err = keystorage.NewAzureKeyVaultSecretStorage(akvs.VaultURL, akvs.SecretName, creds)
	default:
		// Should never happen...
		return nil, fmt.Errorf("invalid value for key storage type: %s", cfg.SigningKey.Storage)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to init key storage '%s': %w", cfg.SigningKey.Storage, err)
	}
	return s, nil
}

func newSigningKey() (jwk.Key, error) {
	cfg := config.Get()
	key, err := jwks.NewSigningKey(cfg.SigningKey.Algorithm, cfg.SigningKey.Curve)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new signing key: %w", err)
	}

	kid, _ := key.KeyID()
	slog.Info("Generated new token signing key", "keyId", kid)

	return key, nil
}

func getAzureKeyVaultCredentials(tenantId string, clientId string, clientSecret string) (azcore.TokenCredential, error) {
	clientOpts := azcore.ClientOptions{
		Telemetry: policy.TelemetryOptions{
			Disabled: true,
		},
	}
	if tenantId != "" && clientId != "" && clientSecret != "" {
		slog.Debug("Initializing Azure Key Vault with client secret credentials")

		// Use client credentials
		creds, err := azidentity.NewClientSecretCredential(tenantId, clientId, clientSecret, &azidentity.ClientSecretCredentialOptions{
			ClientOptions: clientOpts,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create client secret credential object: %w", err)
		}
		return creds, nil
	}

	// Use the default credentials
	slog.Debug("Initializing Azure Key Vault with default credentials")

	creds, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		ClientOptions: clientOpts,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create default credential object: %w", err)
	}
	return creds, nil
}
