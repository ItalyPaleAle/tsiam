package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/tsiam/pkg/types"
)

func TestNewToken(t *testing.T) {
	// Generate a test signing key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	err = key.Set(jwk.AlgorithmKey, "ES256")
	require.NoError(t, err)

	testWhois := types.TailscaleWhoIs{
		NodeID:        "test-node-id",
		Name:          "test-node.example.com",
		UserLoginName: "user@example.com",
	}

	t.Run("Token contains jti claim", func(t *testing.T) {
		resp, err := NewToken(key, TokenRequest{
			Issuer:   "https://test-issuer.example.com",
			Audience: "https://test-audience.example.com",
			Lifetime: 5 * time.Minute,
			Subject:  testWhois,
		})
		require.NoError(t, err)

		// Verify JTI is present in response
		assert.NotEmpty(t, resp.JTI, "JTI should not be empty")

		// Parse the token to verify jti claim
		parsedToken, err := jwt.Parse([]byte(resp.Token), jwt.WithVerify(false))
		require.NoError(t, err)

		jti, ok := parsedToken.JwtID()
		require.True(t, ok, "jti claim should be present in token")
		assert.Equal(t, resp.JTI, jti, "JTI in response should match jti claim in token")
		assert.NotEmpty(t, jti, "jti claim should not be empty")
	})

	t.Run("JTI is base64 URL encoded 24 bytes", func(t *testing.T) {
		resp, err := NewToken(key, TokenRequest{
			Issuer:   "https://test-issuer.example.com",
			Audience: "https://test-audience.example.com",
			Lifetime: 5 * time.Minute,
			Subject:  testWhois,
		})
		require.NoError(t, err)

		// Decode the JTI
		decoded, err := base64.RawURLEncoding.DecodeString(resp.JTI)
		require.NoError(t, err, "JTI should be valid base64 URL encoding without padding")
		assert.Len(t, decoded, 24, "Decoded JTI should be exactly 24 bytes")
	})

	t.Run("Two successive tokens have different JTIs", func(t *testing.T) {
		resp1, err := NewToken(key, TokenRequest{
			Issuer:   "https://test-issuer.example.com",
			Audience: "https://test-audience.example.com",
			Lifetime: 5 * time.Minute,
			Subject:  testWhois,
		})
		require.NoError(t, err)

		resp2, err := NewToken(key, TokenRequest{
			Issuer:   "https://test-issuer.example.com",
			Audience: "https://test-audience.example.com",
			Lifetime: 5 * time.Minute,
			Subject:  testWhois,
		})
		require.NoError(t, err)

		assert.NotEqual(t, resp1.JTI, resp2.JTI, "Successive tokens should have different JTIs")
	})

	t.Run("JTI is unpredictable", func(t *testing.T) {
		// Generate multiple tokens and verify JTIs are unique
		jtis := make(map[string]bool)
		for range 100 {
			resp, err := NewToken(key, TokenRequest{
				Issuer:   "https://test-issuer.example.com",
				Audience: "https://test-audience.example.com",
				Lifetime: 5 * time.Minute,
				Subject:  testWhois,
			})
			require.NoError(t, err)

			// Check that this JTI hasn't been seen before
			assert.False(t, jtis[resp.JTI], "JTI should be unique across multiple tokens")
			jtis[resp.JTI] = true
		}
		assert.Len(t, jtis, 100, "All 100 tokens should have unique JTIs")
	})

	t.Run("JTI is ASCII-safe", func(t *testing.T) {
		resp, err := NewToken(key, TokenRequest{
			Issuer:   "https://test-issuer.example.com",
			Audience: "https://test-audience.example.com",
			Lifetime: 5 * time.Minute,
			Subject:  testWhois,
		})
		require.NoError(t, err)

		// Base64 URL encoding produces only ASCII characters: A-Z, a-z, 0-9, -, _
		for _, c := range resp.JTI {
			assert.True(t,
				(c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_',
				"JTI should contain only ASCII-safe characters (A-Za-z0-9-_)")
		}
	})

	t.Run("Token with all claims including jti", func(t *testing.T) {
		resp, err := NewToken(key, TokenRequest{
			Issuer:   "https://test-issuer.example.com",
			Audience: "https://test-audience.example.com",
			Lifetime: 5 * time.Minute,
			Subject:  testWhois,
		})
		require.NoError(t, err)

		// Parse the token to verify all claims
		parsedToken, err := jwt.Parse([]byte(resp.Token), jwt.WithVerify(false))
		require.NoError(t, err)

		// Verify jti
		jti, ok := parsedToken.JwtID()
		require.True(t, ok)
		assert.Equal(t, resp.JTI, jti)

		// Verify other claims are still present
		sub, ok := parsedToken.Subject()
		require.True(t, ok)
		assert.Equal(t, "test-node.example.com", sub)

		iss, ok := parsedToken.Issuer()
		require.True(t, ok)
		assert.Equal(t, "https://test-issuer.example.com", iss)

		audiences, ok := parsedToken.Audience()
		require.True(t, ok)
		require.Len(t, audiences, 1)
		assert.Equal(t, "https://test-audience.example.com", audiences[0])

		iat, ok := parsedToken.IssuedAt()
		require.True(t, ok)
		assert.NotZero(t, iat)

		exp, ok := parsedToken.Expiration()
		require.True(t, ok)
		assert.NotZero(t, exp)

		nbf, ok := parsedToken.NotBefore()
		require.True(t, ok)
		assert.NotZero(t, nbf)
	})
}
