package jwks

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPublicJWKSAsJSON(t *testing.T) {
	algs := []string{"RS256", "ES256", "ES384", "ES512", "EdDSA"}

	t.Run("output is a valid single-key JWKS", func(t *testing.T) {
		for _, alg := range algs {
			t.Run(alg, func(t *testing.T) {
				key, err := NewSigningKey(alg, "")
				require.NoError(t, err)

				data, err := GetPublicJWKSAsJSON(key)
				require.NoError(t, err)
				require.NotEmpty(t, data)

				set, err := jwk.Parse(data)
				require.NoError(t, err)
				require.Equal(t, 1, set.Len(), "JWKS should contain exactly one key")

				pub, ok := set.Key(0)
				require.True(t, ok)

				// kid and alg are preserved from the source key
				wantKid, _ := key.KeyID()
				gotKid, ok := pub.KeyID()
				require.True(t, ok)
				assert.Equal(t, wantKid, gotKid)

				wantAlg, _ := key.Algorithm()
				gotAlg, ok := pub.Algorithm()
				require.True(t, ok)
				assert.Equal(t, wantAlg, gotAlg)
			})
		}
	})

	t.Run("private material is stripped", func(t *testing.T) {
		for _, alg := range algs {
			t.Run(alg, func(t *testing.T) {
				key, err := NewSigningKey(alg, "")
				require.NoError(t, err)
				require.True(t, key.Has("d"), "source key should be private")

				data, err := GetPublicJWKSAsJSON(key)
				require.NoError(t, err)

				// The serialized JWKS must never carry the private `d` parameter
				var raw map[string]any
				require.NoError(t, json.Unmarshal(data, &raw))
				keys, ok := raw["keys"].([]any)
				require.True(t, ok)
				require.Len(t, keys, 1)

				entry, ok := keys[0].(map[string]any)
				require.True(t, ok)
				_, hasPrivate := entry["d"]
				assert.False(t, hasPrivate, "public JWKS must not contain the private `d` parameter")

				parsed, err := jwk.Parse(data)
				require.NoError(t, err)
				pub, ok := parsed.Key(0)
				require.True(t, ok)
				assert.False(t, pub.Has("d"), "parsed public key must not carry `d`")
			})
		}
	})

	t.Run("accepts an already-public key", func(t *testing.T) {
		key, err := NewSigningKey("ES256", "")
		require.NoError(t, err)
		pubKey, err := key.PublicKey()
		require.NoError(t, err)

		data, err := GetPublicJWKSAsJSON(pubKey)
		require.NoError(t, err)

		parsed, err := jwk.Parse(data)
		require.NoError(t, err)
		assert.Equal(t, 1, parsed.Len())
	})
}
