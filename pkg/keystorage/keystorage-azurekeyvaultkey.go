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
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

const (
	// Format version of the wrapped key file
	wrappedKeyEnvelopeVersion = 1

	// Additional authenticated data for AES-GCM, which ties the ciphertext to this file format
	wrappedKeyEnvelopeAAD = "tsiam/AzureKeyVaultKeys/v1"
)

// AzureKeyVaultKeyClient is an interface for the Azure Key Vault Keys client
// This allows for mocking in tests
type AzureKeyVaultKeyClient interface {
	WrapKey(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error)
	UnwrapKey(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error)
}

// AzureKeyVaultKeyStorage implements KeyStorage using Azure Key Vault Keys for wrapping
// The signing key is stored on disk in encrypted form and decrypted on load
// The signing key is encrypted locally with a random data encryption key (DEK) using AES-256-GCM, and only the DEK is wrapped with the Key Vault key using RSA-OAEP-256
// RSA-OAEP can only encrypt a few hundred bytes, which is less than a serialized private JWK for most algorithms
type AzureKeyVaultKeyStorage struct {
	client      AzureKeyVaultKeyClient
	keyName     string
	keyVersion  string
	storagePath string
}

// On-disk format of the wrapped signing key
type wrappedKeyEnvelope struct {
	// Format version
	Version int `json:"v"`
	// Version of the Key Vault key that wrapped the DEK
	// Unwrapping uses this version, so the file can still be read after the key is rotated in Key Vault
	KeyVersion string `json:"keyVersion"`
	// DEK wrapped with the Key Vault key using RSA-OAEP-256
	WrappedKey []byte `json:"wrappedKey"`
	// Signing key (JWK as JSON) encrypted with the DEK using AES-256-GCM, with the nonce prepended
	Ciphertext []byte `json:"ciphertext"`
}

// isAzureKeyVaultKeyVersionUnpinned returns true if keyVersion is empty or "latest"
func isAzureKeyVaultKeyVersionUnpinned(keyVersion string) bool {
	return keyVersion == "" || strings.ToLower(keyVersion) == "latest"
}

// NewAzureKeyVaultKeyStorage creates a new Azure Key Vault Key-based key storage
// The key is stored on disk in wrapped form and unwrapped using Azure Key Vault on load
// keyVersion is the version of the Key Vault key used to wrap new signing keys
// If keyVersion is empty or "latest", the latest version is used
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

	// The Key Vault API selects the latest version when the version is empty
	if isAzureKeyVaultKeyVersionUnpinned(keyVersion) {
		keyVersion = ""
	}

	// Ensure directory exists with restrictive permissions
	// MkdirAll only honors the mode on creation, so an existing dir with looser bits would silently remain world-readable, the explicit Chmod enforces 0700 on every run
	dir := filepath.Dir(storagePath)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to create key storage directory: %w", err)
	}
	err = os.Chmod(dir, 0700) //nolint:gosec // directory needs the execute bit, gosec only knows about files
	if err != nil {
		return nil, fmt.Errorf("failed to chmod key storage directory: %w", err)
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

	// A zero-byte file is treated as missing rather than an unwrap error
	if len(data) == 0 {
		slog.DebugContext(ctx, "Ignoring empty wrapped signing key file in Azure Key Vault key storage", slog.String("path", a.storagePath))
		return nil, errKeyNoExist
	}

	// Files written by tsiam v0.5.0 and earlier contain the raw RSA-OAEP ciphertext of the JWK, which is never valid JSON
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

	// Files that don't record the key version are unwrapped with the configured or latest version, and would stop unwrapping once the key is rotated
	// The unwrap succeeded, so rewrite the file now to record the version
	if isAzureKeyVaultKeyVersionUnpinned(keyVersion) {
		slog.WarnContext(ctx, "Wrapped signing key file is not pinned to a version of the Azure Key Vault key, so it would fail to unwrap after the key is rotated - rewriting it",
			slog.String("path", a.storagePath),
		)

		err = a.Store(ctx, key)
		if err != nil {
			slog.WarnContext(ctx, "Failed to rewrite wrapped signing key file", slog.String("path", a.storagePath), slog.Any("error", err))
		}
	}

	return key, nil
}

// Loads a key from a versioned envelope
// Returns the key and the Key Vault key version recorded in the envelope
func (a *AzureKeyVaultKeyStorage) loadEnvelope(ctx context.Context, data []byte) (jwk.Key, string, error) {
	var env wrappedKeyEnvelope
	err := json.Unmarshal(data, &env)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse wrapped key file: %w", err)
	}
	if env.Version != wrappedKeyEnvelopeVersion {
		return nil, "", fmt.Errorf("unsupported wrapped key file format version: %d", env.Version)
	}

	// The recorded version should always be set, unless the file was modified by hand
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

// Loads a key stored in the format used by tsiam v0.5.0 and earlier, where the JWK was wrapped directly with the Key Vault key
// These files don't record the version of the Key Vault key, so they're unwrapped with the configured version, or the latest one
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

// Unwraps data with the Key Vault key using RSA-OAEP-256
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

// Store saves the signing key to disk in wrapped (encrypted) form using Azure Key Vault
func (a *AzureKeyVaultKeyStorage) Store(ctx context.Context, key jwk.Key) error {
	// Marshal the key to JSON
	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to encode key: %w", err)
	}
	defer clear(data)

	// Encrypt the signing key with a new, random DEK
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

	// Record the exact key version that Key Vault used, which matters when the configured version is empty (latest)
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

	// Atomic write so a torn write cannot leave an unrecoverable wrapped-ciphertext blob on disk
	err = writeFileAtomic(a.storagePath, out)
	if err != nil {
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

// Encrypts plaintext with AES-256-GCM using a random nonce, which is prepended to the returned ciphertext
func encryptWithDEK(dek []byte, plaintext []byte) ([]byte, error) {
	aead, err := newDEKCipher(dek)
	if err != nil {
		return nil, err
	}

	// #nosec G407 -- NewGCMWithRandomNonce generates the nonce, so the nonce argument must be nil
	ciphertext := aead.Seal(nil, nil, plaintext, []byte(wrappedKeyEnvelopeAAD))
	return ciphertext, nil
}

// Decrypts ciphertext produced by encryptWithDEK
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

	// The DEK is used for a single encryption, so a random nonce is safe
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM cipher: %w", err)
	}

	return aead, nil
}
