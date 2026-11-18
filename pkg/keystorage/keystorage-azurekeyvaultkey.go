package keystorage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/italypaleale/go-kit/fsutil"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

const (
	wrappedKeyEnvelopeVersion = 1
	wrappedKeyEnvelopeAAD     = "tsiam/AzureKeyVaultKeys/v1"
)

// AzureKeyVaultKeyClient is an interface for the Azure Key Vault Keys client
// This allows for mocking in tests
type AzureKeyVaultKeyClient interface {
	WrapKey(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error)
	UnwrapKey(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error)
}

// AzureKeyVaultKeyStorage implements KeyStorage using envelope encryption with Azure Key Vault Keys
// The signing key is encrypted locally with AES-256-GCM using a random DEK, and the DEK is wrapped with the Key Vault key using RSA-OAEP-256
type AzureKeyVaultKeyStorage struct {
	client      AzureKeyVaultKeyClient
	keyName     string
	keyVersion  string
	storagePath string
}

type wrappedKeyEnvelope struct {
	Version    int    `json:"v"`
	KeyVersion string `json:"keyVersion"`
	WrappedKey []byte `json:"wrappedKey"`
	Ciphertext []byte `json:"ciphertext"`
}

func isAzureKeyVaultKeyVersionUnpinned(keyVersion string) bool {
	return keyVersion == "" || strings.ToLower(keyVersion) == "latest"
}

// NewAzureKeyVaultKeyStorage creates a new Azure Key Vault Key-based key storage
func NewAzureKeyVaultKeyStorage(vaultURL string, keyName string, keyVersion string, storagePath string, credential azcore.TokenCredential) (*AzureKeyVaultKeyStorage, error) {
	if vaultURL == "" {
		return nil, errors.New("vaultURL cannot be empty")
	}
	if credential == nil {
		return nil, errors.New("credential cannot be nil")
	}

	client, err := azkeys.NewClient(vaultURL, credential, &azkeys.ClientOptions{
		Telemetry: policy.TelemetryOptions{
			Disabled: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure Key Vault client: %w", err)
	}

	return NewAzureKeyVaultKeyStorageWithClient(client, keyName, keyVersion, storagePath)
}

// NewAzureKeyVaultKeyStorageWithClient creates a new Azure Key Vault Key-based key storage with a custom client
// This is primarily used for testing with mock clients
func NewAzureKeyVaultKeyStorageWithClient(client AzureKeyVaultKeyClient, keyName string, keyVersion string, storagePath string) (*AzureKeyVaultKeyStorage, error) {
	if client == nil {
		return nil, errors.New("client cannot be nil")
	}
	if keyName == "" {
		return nil, errors.New("keyName cannot be empty")
	}
	if storagePath == "" {
		return nil, errors.New("storagePath cannot be empty")
	}

	if isAzureKeyVaultKeyVersionUnpinned(keyVersion) {
		keyVersion = ""
	}

	err := ensureKeyDir(storagePath)
	if err != nil {
		return nil, err
	}

	return &AzureKeyVaultKeyStorage{
		client:      client,
		keyName:     keyName,
		keyVersion:  keyVersion,
		storagePath: storagePath,
	}, nil
}

// Load loads the signing key from disk and unwraps it using Azure Key Vault
func (a *AzureKeyVaultKeyStorage) Load(ctx context.Context) (jwk.Key, error) {
	// Read the wrapped key from disk
	data, err := os.ReadFile(a.storagePath)
	if errors.Is(err, fs.ErrNotExist) {
		// Key doesn't exist yet
		slog.DebugContext(ctx, "No wrapped signing key found in Azure Key Vault key storage", slog.String("path", a.storagePath))
		return nil, errKeyNoExist
	} else if err != nil {
		return nil, fmt.Errorf("failed to read wrapped key file: %w", err)
	}

	// Treat an empty file as missing
	if len(data) == 0 {
		slog.WarnContext(ctx, "Wrapped signing key file is empty, so a new signing key is generated and replaces it", slog.String("path", a.storagePath))
		return nil, errKeyNoExist
	}

	// Legacy files (tsiam v0.5.0 and earlier) contain raw RSA-OAEP ciphertext rather than JSON
	var (
		key        jwk.Key
		keyVersion string
	)
	if json.Valid(data) {
		key, keyVersion, err = a.loadEnvelope(ctx, data)
	} else {
		key, err = a.loadLegacy(ctx, data)
	}
	if err != nil {
		return nil, err
	}

	slog.InfoContext(ctx, "Loaded signing key from Azure Key Vault key storage",
		slog.String("keyName", a.keyName),
		slog.String("keyVersion", keyVersion),
		slog.String("path", a.storagePath),
		slog.String("keyId", keyID(key)),
	)

	// Rewrite legacy or unpinned files so the key version is recorded
	if isAzureKeyVaultKeyVersionUnpinned(keyVersion) {
		slog.WarnContext(ctx, "Wrapped signing key file is not pinned to a version of the Azure Key Vault key, so it would fail to unwrap after the key is rotated - rewriting it",
			slog.String("path", a.storagePath),
		)

		err = a.store(ctx, key, true)
		if err != nil {
			slog.WarnContext(ctx, "Failed to rewrite wrapped signing key file", slog.String("path", a.storagePath), slog.Any("error", err))
		}
	}

	return key, nil
}

func (a *AzureKeyVaultKeyStorage) loadEnvelope(ctx context.Context, data []byte) (jwk.Key, string, error) {
	var env wrappedKeyEnvelope
	err := json.Unmarshal(data, &env)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse wrapped key file: %w", err)
	}
	if env.Version != wrappedKeyEnvelopeVersion {
		return nil, "", fmt.Errorf("unsupported wrapped key file format version: %d", env.Version)
	}

	keyVersion := env.KeyVersion
	if isAzureKeyVaultKeyVersionUnpinned(keyVersion) {
		keyVersion = a.keyVersion
	}

	// Unwrap the DEK
	dek, err := a.unwrap(ctx, keyVersion, env.WrappedKey)
	if err != nil {
		return nil, "", err
	}
	defer clear(dek)
	if len(dek) != 32 {
		return nil, "", fmt.Errorf("unwrapped data encryption key has invalid length: %d", len(dek))
	}

	// Decrypt the signing key
	plaintext, err := decryptWithDEK(dek, env.Ciphertext)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decrypt signing key: %w", err)
	}
	defer clear(plaintext)

	key, err := jwk.ParseKey(plaintext)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse unwrapped key: %w", err)
	}

	return key, env.KeyVersion, nil
}

// Loads a legacy key file (tsiam v0.5.0 and earlier) where the JWK was wrapped directly with RSA-OAEP
func (a *AzureKeyVaultKeyStorage) loadLegacy(ctx context.Context, data []byte) (jwk.Key, error) {
	plaintext, err := a.unwrap(ctx, a.keyVersion, data)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)

	key, err := jwk.ParseKey(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to parse unwrapped key: %w", err)
	}

	return key, nil
}

func (a *AzureKeyVaultKeyStorage) unwrap(ctx context.Context, keyVersion string, data []byte) ([]byte, error) {
	params := azkeys.KeyOperationParameters{
		Algorithm: new(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     data,
	}
	resp, err := a.client.UnwrapKey(ctx, a.keyName, keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key with Azure Key Vault: %w", err)
	}

	if resp.Result == nil {
		return nil, errors.New("unwrapped key result is nil")
	}
	return resp.Result, nil
}

// Store saves the wrapped signing key to disk if the file does not already exist
func (a *AzureKeyVaultKeyStorage) Store(ctx context.Context, key jwk.Key) error {
	return a.store(ctx, key, false)
}

func (a *AzureKeyVaultKeyStorage) store(ctx context.Context, key jwk.Key, overwrite bool) error {
	// Marshal the key to JSON
	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to encode key: %w", err)
	}
	defer clear(data)

	// Encrypt the signing key with a random DEK
	dek := make([]byte, 32)
	_, err = rand.Read(dek)
	if err != nil {
		return fmt.Errorf("failed to generate data encryption key: %w", err)
	}
	defer clear(dek)

	ciphertext, err := encryptWithDEK(dek, data)
	if err != nil {
		return fmt.Errorf("failed to encrypt signing key: %w", err)
	}

	// Wrap the DEK using Azure Key Vault
	params := azkeys.KeyOperationParameters{
		Algorithm: new(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     dek,
	}
	resp, err := a.client.WrapKey(ctx, a.keyName, a.keyVersion, params, nil)
	if err != nil {
		return fmt.Errorf("failed to wrap key with Azure Key Vault: %w", err)
	}
	if resp.Result == nil {
		return errors.New("wrapped key result is nil")
	}

	var keyVersion string
	if resp.KID != nil {
		keyVersion = resp.KID.Version()
	}
	if keyVersion == "" {
		return errors.New("response from Azure Key Vault does not include the version of the key used for wrapping")
	}

	out, err := json.Marshal(wrappedKeyEnvelope{
		Version:    wrappedKeyEnvelopeVersion,
		KeyVersion: keyVersion,
		WrappedKey: resp.Result,
		Ciphertext: ciphertext,
	})
	if err != nil {
		return fmt.Errorf("failed to encode wrapped key file: %w", err)
	}

	if overwrite {
		err = fsutil.WriteFile(a.storagePath, out, keyFileMode)
	} else {
		err = fsutil.CreateFile(a.storagePath, out, keyFileMode, fsutil.WithReplaceEmpty())
	}
	if errors.Is(err, fs.ErrExist) {
		return errKeyExists
	} else if err != nil {
		return fmt.Errorf("failed to write wrapped key file: %w", err)
	}

	slog.InfoContext(ctx, "Stored signing key to Azure Key Vault key storage",
		slog.String("keyName", a.keyName),
		slog.String("keyVersion", keyVersion),
		slog.String("path", a.storagePath),
		slog.String("keyId", keyID(key)),
	)

	return nil
}

func encryptWithDEK(dek []byte, plaintext []byte) ([]byte, error) {
	aead, err := newDEKCipher(dek)
	if err != nil {
		return nil, err
	}

	// #nosec G407
	ciphertext := aead.Seal(nil, nil, plaintext, []byte(wrappedKeyEnvelopeAAD))
	return ciphertext, nil
}

func decryptWithDEK(dek []byte, ciphertext []byte) ([]byte, error) {
	aead, err := newDEKCipher(dek)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nil, ciphertext, []byte(wrappedKeyEnvelopeAAD))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

func newDEKCipher(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM cipher: %w", err)
	}

	return aead, nil
}
