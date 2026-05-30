package jwks

import (
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSigningKey(t *testing.T) {
	t.Run("RS256", func(t *testing.T) {
		key, err := NewSigningKey("RS256", "")
		require.NoError(t, err)
		require.NotNil(t, key)

		assert.Equal(t, jwa.RSA(), key.KeyType())
		assertAlgorithm(t, key, jwa.RS256())

		rawKey, err := jwk.Export[*rsa.PrivateKey](key)
		require.NoError(t, err)
		assert.Equal(t, rsaKeySize, rawKey.N.BitLen(), "RSA modulus should be %d bits", rsaKeySize)
	})

	t.Run("ES256", func(t *testing.T) {
		key, err := NewSigningKey("ES256", "")
		require.NoError(t, err)

		assert.Equal(t, jwa.EC(), key.KeyType())
		assertAlgorithm(t, key, jwa.ES256())
		assertCurve(t, key, jwa.P256())
	})

	t.Run("ES384", func(t *testing.T) {
		key, err := NewSigningKey("ES384", "")
		require.NoError(t, err)

		assert.Equal(t, jwa.EC(), key.KeyType())
		assertAlgorithm(t, key, jwa.ES384())
		assertCurve(t, key, jwa.P384())
	})

	t.Run("ES512", func(t *testing.T) {
		key, err := NewSigningKey("ES512", "")
		require.NoError(t, err)

		assert.Equal(t, jwa.EC(), key.KeyType())
		assertAlgorithm(t, key, jwa.ES512())
		assertCurve(t, key, jwa.P521())
	})

	t.Run("EdDSA with empty curve defaults to Ed25519", func(t *testing.T) {
		key, err := NewSigningKey("EdDSA", "")
		require.NoError(t, err)

		assert.Equal(t, jwa.OKP(), key.KeyType())
		assertAlgorithm(t, key, jwa.EdDSA())

		rawKey, err := jwk.Export[ed25519.PrivateKey](key)
		require.NoError(t, err)
		assert.Len(t, rawKey, ed25519.PrivateKeySize)
	})

	t.Run("EdDSA with explicit Ed25519 curve", func(t *testing.T) {
		key, err := NewSigningKey("EdDSA", "Ed25519")
		require.NoError(t, err)
		assert.Equal(t, jwa.OKP(), key.KeyType())
		assertAlgorithm(t, key, jwa.EdDSA())
	})

	t.Run("EdDSA with unsupported curve fails", func(t *testing.T) {
		key, err := NewSigningKey("EdDSA", "Ed448")
		require.Error(t, err)
		require.ErrorContains(t, err, "unsupported EdDSA curve")
		assert.Nil(t, key)
	})

	t.Run("unsupported algorithm fails", func(t *testing.T) {
		key, err := NewSigningKey("HS256", "")
		require.Error(t, err)
		require.ErrorContains(t, err, "unsupported algorithm")
		assert.Nil(t, key)
	})

	t.Run("generated key is private", func(t *testing.T) {
		// Every supported algorithm must produce a private key (carries the `d` parameter),
		// otherwise the service could not sign tokens
		for _, alg := range []string{"RS256", "ES256", "ES384", "ES512", "EdDSA"} {
			t.Run(alg, func(t *testing.T) {
				key, err := NewSigningKey(alg, "")
				require.NoError(t, err)
				assert.True(t, key.Has("d"), "key should carry the private `d` parameter")
			})
		}
	})
}

func TestNewSigningKey_KeyID(t *testing.T) {
	t.Run("kid is set and decodes to 16 bytes", func(t *testing.T) {
		key, err := NewSigningKey("ES256", "")
		require.NoError(t, err)

		kid, ok := key.KeyID()
		require.True(t, ok, "key should have a kid")
		require.NotEmpty(t, kid)

		decoded, err := base64.RawURLEncoding.DecodeString(kid)
		require.NoError(t, err, "kid should be valid base64url without padding")
		assert.Len(t, decoded, 16, "kid should decode to 16 random bytes")
	})

	t.Run("kid is ASCII-safe", func(t *testing.T) {
		key, err := NewSigningKey("ES256", "")
		require.NoError(t, err)

		kid, ok := key.KeyID()
		require.True(t, ok)
		for _, c := range kid {
			assert.True(t,
				(c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_',
				"kid should contain only base64url characters (A-Za-z0-9-_)")
		}
	})

	t.Run("kid is unique across keys", func(t *testing.T) {
		kids := make(map[string]bool)
		for range 100 {
			key, err := NewSigningKey("ES256", "")
			require.NoError(t, err)

			kid, ok := key.KeyID()
			require.True(t, ok)
			assert.False(t, kids[kid], "kid should be unique across generated keys")
			kids[kid] = true
		}
		assert.Len(t, kids, 100)
	})
}

func assertAlgorithm(t *testing.T, key jwk.Key, want jwa.SignatureAlgorithm) {
	t.Helper()
	alg, ok := key.Algorithm()
	require.True(t, ok, "key should have an algorithm")
	assert.Equal(t, want, alg)
}

func assertCurve(t *testing.T, key jwk.Key, want jwa.EllipticCurveAlgorithm) {
	t.Helper()
	crv, err := jwk.Get[jwa.EllipticCurveAlgorithm](key, jwk.ECDSACrvKey)
	require.NoError(t, err)
	assert.Equal(t, want, crv)
}
