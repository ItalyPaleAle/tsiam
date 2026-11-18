package keystorage

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/tsiam/pkg/jwks"
)

const testAKVKeyName = "test-key"

// In-memory fake for Azure Key Vault Keys using RSA-OAEP-256
type fakeKeyVault struct {
	versions map[string]*rsa.PrivateKey
	latest   string

	wrapVersions   []string
	unwrapVersions []string

	wrapErr   error
	unwrapErr error
	omitKID   bool
}

func newFakeKeyVault(t *testing.T) *fakeKeyVault {
	t.Helper()

	f := &fakeKeyVault{
		versions: map[string]*rsa.PrivateKey{},
	}
	f.rotate(t)
	return f
}

func (f *fakeKeyVault) rotate(t *testing.T) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	version := fmt.Sprintf("version%d", len(f.versions)+1)
	f.versions[version] = priv
	f.latest = version
}

func (f *fakeKeyVault) resolve(keyName string, keyVersion string) (string, *rsa.PrivateKey, error) {
	if keyName != testAKVKeyName {
		return "", nil, fmt.Errorf("key not found: %s", keyName)
	}
	if keyVersion == "" {
		keyVersion = f.latest
	}
	priv, ok := f.versions[keyVersion]
	if !ok {
		return "", nil, fmt.Errorf("key version not found: %s", keyVersion)
	}
	return keyVersion, priv, nil
}

func (f *fakeKeyVault) WrapKey(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	f.wrapVersions = append(f.wrapVersions, keyVersion)
	if f.wrapErr != nil {
		return azkeys.WrapKeyResponse{}, f.wrapErr
	}
	if parameters.Algorithm == nil || *parameters.Algorithm != azkeys.EncryptionAlgorithmRSAOAEP256 {
		return azkeys.WrapKeyResponse{}, errors.New("unexpected algorithm")
	}

	version, priv, err := f.resolve(keyName, keyVersion)
	if err != nil {
		return azkeys.WrapKeyResponse{}, err
	}
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, parameters.Value, nil)
	if err != nil {
		return azkeys.WrapKeyResponse{}, fmt.Errorf("wrap failed: %w", err)
	}

	res := azkeys.WrapKeyResponse{Result: ct}
	if !f.omitKID {
		res.KID = new(azkeys.ID("https://fake.vault.azure.net/keys/" + keyName + "/" + version))
	}
	return res, nil
}

func (f *fakeKeyVault) UnwrapKey(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	f.unwrapVersions = append(f.unwrapVersions, keyVersion)
	if f.unwrapErr != nil {
		return azkeys.UnwrapKeyResponse{}, f.unwrapErr
	}
	if parameters.Algorithm == nil || *parameters.Algorithm != azkeys.EncryptionAlgorithmRSAOAEP256 {
		return azkeys.UnwrapKeyResponse{}, errors.New("unexpected algorithm")
	}

	version, priv, err := f.resolve(keyName, keyVersion)
	if err != nil {
		return azkeys.UnwrapKeyResponse{}, err
	}
	pt, err := rsa.DecryptOAEP(sha256.New(), nil, priv, parameters.Value, nil)
	if err != nil {
		return azkeys.UnwrapKeyResponse{}, fmt.Errorf("unwrap failed: %w", err)
	}

	return azkeys.UnwrapKeyResponse{
		Result: pt,
		KID:    new(azkeys.ID("https://fake.vault.azure.net/keys/" + keyName + "/" + version)),
	}, nil
}

// Wraps the JWK directly with RSA-OAEP (v0.5.0 format)
func (f *fakeKeyVault) legacyWrap(t *testing.T, key jwk.Key, keyVersion string) []byte {
	t.Helper()

	data, err := json.Marshal(key)
	require.NoError(t, err)
	res, err := f.WrapKey(t.Context(), testAKVKeyName, keyVersion, azkeys.KeyOperationParameters{
		Algorithm: new(azkeys.EncryptionAlgorithmRSAOAEP256),
		Value:     data,
	}, nil)
	require.NoError(t, err)

	f.wrapVersions = nil
	return res.Result
}

func newTestAKVStorage(t *testing.T, kv *fakeKeyVault, keyVersion string) *AzureKeyVaultKeyStorage {
	t.Helper()

	keyPath := filepath.Join(t.TempDir(), "wrapped-key.json")
	storage, err := NewAzureKeyVaultKeyStorageWithClient(kv, testAKVKeyName, keyVersion, keyPath)
	require.NoError(t, err)
	return storage
}

func readEnvelope(t *testing.T, path string) wrappedKeyEnvelope {
	t.Helper()

	data, err := os.ReadFile(path) //nolint:gosec
	require.NoError(t, err)

	var env wrappedKeyEnvelope
	err = json.Unmarshal(data, &env)
	require.NoError(t, err, "Wrapped key file should be a JSON envelope")
	return env
}

func privateKeyParam(t *testing.T, key jwk.Key) string {
	t.Helper()

	data, err := json.Marshal(key)
	require.NoError(t, err)
	var fields map[string]any
	err = json.Unmarshal(data, &fields)
	require.NoError(t, err)
	d, ok := fields["d"].(string)
	require.True(t, ok, "Key should have a private part")
	require.NotEmpty(t, d)
	return d
}

func requireSameKey(t *testing.T, expected jwk.Key, actual jwk.Key) {
	t.Helper()

	require.NotNil(t, actual)
	expectedJSON, err := json.Marshal(expected)
	require.NoError(t, err)
	actualJSON, err := json.Marshal(actual)
	require.NoError(t, err)
	assert.JSONEq(t, string(expectedJSON), string(actualJSON))
}

func TestNewAzureKeyVaultKeyStorageWithClient(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "wrapped-key.json")
	kv := &fakeKeyVault{}

	t.Run("valid parameters", func(t *testing.T) {
		storage, err := NewAzureKeyVaultKeyStorageWithClient(kv, testAKVKeyName, "abc123", keyPath)
		require.NoError(t, err)
		require.NotNil(t, storage)
		assert.Equal(t, testAKVKeyName, storage.keyName)
		assert.Equal(t, "abc123", storage.keyVersion)
		assert.Equal(t, keyPath, storage.storagePath)
	})

	t.Run("latest is the same as empty", func(t *testing.T) {
		storage, err := NewAzureKeyVaultKeyStorageWithClient(kv, testAKVKeyName, "Latest", keyPath)
		require.NoError(t, err)
		assert.Empty(t, storage.keyVersion)
	})

	t.Run("nil client", func(t *testing.T) {
		_, err := NewAzureKeyVaultKeyStorageWithClient(nil, testAKVKeyName, "", keyPath)
		require.ErrorContains(t, err, "client cannot be nil")
	})

	t.Run("empty key name", func(t *testing.T) {
		_, err := NewAzureKeyVaultKeyStorageWithClient(kv, "", "", keyPath)
		require.ErrorContains(t, err, "keyName cannot be empty")
	})

	t.Run("empty storage path", func(t *testing.T) {
		_, err := NewAzureKeyVaultKeyStorageWithClient(kv, testAKVKeyName, "", "")
		require.ErrorContains(t, err, "storagePath cannot be empty")
	})
}

func TestAzureKeyVaultKeyStorage_LoadNonExistent(t *testing.T) {
	kv := newFakeKeyVault(t)
	storage := newTestAKVStorage(t, kv, "")

	key, err := storage.Load(t.Context())
	require.ErrorIs(t, err, errKeyNoExist)
	require.Nil(t, key)

	logs := captureLogs(t)
	err = os.WriteFile(storage.storagePath, nil, 0600)
	require.NoError(t, err)
	key, err = storage.Load(t.Context())
	require.ErrorIs(t, err, errKeyNoExist)
	require.Nil(t, key)
	assert.Contains(t, logs.String(), "level=WARN")
	assert.Contains(t, logs.String(), "Wrapped signing key file is empty")

	assert.Empty(t, kv.unwrapVersions, "Key Vault should not be called")
}

func TestAzureKeyVaultKeyStorage_RoundTrip(t *testing.T) {
	kv := newFakeKeyVault(t)

	algs := []struct {
		alg   string
		curve string
	}{
		{alg: "RS256"},
		{alg: "ES256"},
		{alg: "ES384"},
		{alg: "ES512"},
		{alg: "EdDSA", curve: "Ed25519"},
	}
	for _, tc := range algs {
		t.Run(tc.alg, func(t *testing.T) {
			storage := newTestAKVStorage(t, kv, "")

			signingKey, err := jwks.NewSigningKey(tc.alg, tc.curve)
			require.NoError(t, err)

			err = storage.Store(t.Context(), signingKey)
			require.NoError(t, err)

			env := readEnvelope(t, storage.storagePath)
			assert.Equal(t, wrappedKeyEnvelopeVersion, env.Version)
			assert.Equal(t, kv.latest, env.KeyVersion)
			assert.NotEmpty(t, env.WrappedKey)
			assert.NotEmpty(t, env.Ciphertext)

			before, err := os.ReadFile(storage.storagePath)
			require.NoError(t, err)
			assert.NotContains(t, string(before), privateKeyParam(t, signingKey))

			loadedKey, err := storage.Load(t.Context())
			require.NoError(t, err)
			requireSameKey(t, signingKey, loadedKey)

			after, err := os.ReadFile(storage.storagePath)
			require.NoError(t, err)
			assert.Equal(t, before, after)
		})
	}
}

func TestAzureKeyVaultKeyStorage_LoadAfterRotation(t *testing.T) {
	kv := newFakeKeyVault(t)
	storage := newTestAKVStorage(t, kv, "")
	originalVersion := kv.latest

	signingKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err)
	err = storage.Store(t.Context(), signingKey)
	require.NoError(t, err)

	kv.rotate(t)

	loadedKey, err := storage.Load(t.Context())
	require.NoError(t, err)
	requireSameKey(t, signingKey, loadedKey)
	assert.Equal(t, []string{originalVersion}, kv.unwrapVersions, "Unwrap should use the version recorded in the file")
}

func TestAzureKeyVaultKeyStorage_StorePinnedKeyVersion(t *testing.T) {
	kv := newFakeKeyVault(t)
	pinnedVersion := kv.latest
	kv.rotate(t)

	storage := newTestAKVStorage(t, kv, pinnedVersion)

	signingKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err)
	err = storage.Store(t.Context(), signingKey)
	require.NoError(t, err)

	assert.Equal(t, []string{pinnedVersion}, kv.wrapVersions)
	env := readEnvelope(t, storage.storagePath)
	assert.Equal(t, pinnedVersion, env.KeyVersion)
}

func TestAzureKeyVaultKeyStorage_StoreExisting(t *testing.T) {
	kv := newFakeKeyVault(t)
	storage := newTestAKVStorage(t, kv, "")

	firstKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err)
	err = storage.Store(t.Context(), firstKey)
	require.NoError(t, err)

	secondKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err)
	err = storage.Store(t.Context(), secondKey)
	require.Error(t, err)
	assert.True(t, IsKeyExistError(err))

	loadedKey, err := storage.Load(t.Context())
	require.NoError(t, err)
	requireSameKey(t, firstKey, loadedKey)
}

func TestAzureKeyVaultKeyStorage_LoadLegacy(t *testing.T) {
	t.Run("rewrites file pinned to the latest version", func(t *testing.T) {
		kv := newFakeKeyVault(t)
		storage := newTestAKVStorage(t, kv, "")

		signingKey, err := jwks.NewSigningKey("EdDSA", "Ed25519")
		require.NoError(t, err)
		err = os.WriteFile(storage.storagePath, kv.legacyWrap(t, signingKey, ""), 0600)
		require.NoError(t, err)

		loadedKey, err := storage.Load(t.Context())
		require.NoError(t, err)
		requireSameKey(t, signingKey, loadedKey)

		env := readEnvelope(t, storage.storagePath)
		assert.Equal(t, kv.latest, env.KeyVersion)

		originalVersion := kv.latest
		kv.rotate(t)
		kv.unwrapVersions = nil
		loadedKey, err = storage.Load(t.Context())
		require.NoError(t, err)
		requireSameKey(t, signingKey, loadedKey)
		assert.Equal(t, []string{originalVersion}, kv.unwrapVersions)
	})

	t.Run("configured version unwraps a legacy file after rotation", func(t *testing.T) {
		kv := newFakeKeyVault(t)
		originalVersion := kv.latest

		signingKey, err := jwks.NewSigningKey("EdDSA", "Ed25519")
		require.NoError(t, err)
		legacy := kv.legacyWrap(t, signingKey, "")

		kv.rotate(t)
		storage := newTestAKVStorage(t, kv, originalVersion)
		err = os.WriteFile(storage.storagePath, legacy, 0600)
		require.NoError(t, err)

		loadedKey, err := storage.Load(t.Context())
		require.NoError(t, err)
		requireSameKey(t, signingKey, loadedKey)

		env := readEnvelope(t, storage.storagePath)
		assert.Equal(t, originalVersion, env.KeyVersion)
	})

	t.Run("failed rewrite still returns the key", func(t *testing.T) {
		kv := newFakeKeyVault(t)
		storage := newTestAKVStorage(t, kv, "")

		signingKey, err := jwks.NewSigningKey("EdDSA", "Ed25519")
		require.NoError(t, err)
		legacy := kv.legacyWrap(t, signingKey, "")
		err = os.WriteFile(storage.storagePath, legacy, 0600)
		require.NoError(t, err)

		kv.wrapErr = errors.New("mock wrap error")
		loadedKey, err := storage.Load(t.Context())
		require.NoError(t, err)
		requireSameKey(t, signingKey, loadedKey)

		data, err := os.ReadFile(storage.storagePath)
		require.NoError(t, err)
		assert.Equal(t, legacy, data)
	})
}

func TestAzureKeyVaultKeyStorage_LoadUnpinnedEnvelope(t *testing.T) {
	kv := newFakeKeyVault(t)
	storage := newTestAKVStorage(t, kv, "")

	signingKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err)
	err = storage.Store(t.Context(), signingKey)
	require.NoError(t, err)

	env := readEnvelope(t, storage.storagePath)
	env.KeyVersion = ""
	data, err := json.Marshal(env)
	require.NoError(t, err)
	err = os.WriteFile(storage.storagePath, data, 0600)
	require.NoError(t, err)

	loadedKey, err := storage.Load(t.Context())
	require.NoError(t, err)
	requireSameKey(t, signingKey, loadedKey)

	env = readEnvelope(t, storage.storagePath)
	assert.Equal(t, kv.latest, env.KeyVersion)
}

func TestAzureKeyVaultKeyStorage_LoadErrors(t *testing.T) {
	storeKey := func(t *testing.T) (*fakeKeyVault, *AzureKeyVaultKeyStorage) {
		t.Helper()

		kv := newFakeKeyVault(t)
		storage := newTestAKVStorage(t, kv, "")
		signingKey, err := jwks.NewSigningKey("ES256", "")
		require.NoError(t, err)
		err = storage.Store(t.Context(), signingKey)
		require.NoError(t, err)
		return kv, storage
	}

	t.Run("unwrap error", func(t *testing.T) {
		kv, storage := storeKey(t)
		kv.unwrapErr = errors.New("mock unwrap error")

		_, err := storage.Load(t.Context())
		require.ErrorContains(t, err, "failed to unwrap key with Azure Key Vault")
	})

	t.Run("unsupported format version", func(t *testing.T) {
		_, storage := storeKey(t)
		env := readEnvelope(t, storage.storagePath)
		env.Version = 99
		data, err := json.Marshal(env)
		require.NoError(t, err)
		err = os.WriteFile(storage.storagePath, data, 0600)
		require.NoError(t, err)

		_, err = storage.Load(t.Context())
		require.ErrorContains(t, err, "unsupported wrapped key file format version")
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		_, storage := storeKey(t)
		env := readEnvelope(t, storage.storagePath)
		env.Ciphertext[len(env.Ciphertext)-1] ^= 0xff
		data, err := json.Marshal(env)
		require.NoError(t, err)
		err = os.WriteFile(storage.storagePath, data, 0600)
		require.NoError(t, err)

		_, err = storage.Load(t.Context())
		require.ErrorContains(t, err, "failed to decrypt signing key")
	})
}

func TestAzureKeyVaultKeyStorage_StoreErrors(t *testing.T) {
	signingKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err)

	t.Run("wrap error", func(t *testing.T) {
		kv := newFakeKeyVault(t)
		kv.wrapErr = errors.New("mock wrap error")
		storage := newTestAKVStorage(t, kv, "")

		err := storage.Store(t.Context(), signingKey)
		require.ErrorContains(t, err, "failed to wrap key with Azure Key Vault")
		assert.NoFileExists(t, storage.storagePath)
	})

	t.Run("missing key version in response", func(t *testing.T) {
		kv := newFakeKeyVault(t)
		kv.omitKID = true
		storage := newTestAKVStorage(t, kv, "")

		err := storage.Store(t.Context(), signingKey)
		require.ErrorContains(t, err, "does not include the version of the key")
		assert.NoFileExists(t, storage.storagePath)
	})
}

func TestAzureKeyVaultKeyStorage_InvalidPath(t *testing.T) {
	_, err := NewAzureKeyVaultKeyStorageWithClient(&fakeKeyVault{}, testAKVKeyName, "", "/invalid/nonexistent/deeply/nested/path/key.bin")
	require.Error(t, err, "Expected error for invalid path")
}
