package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/italypaleale/go-kit/tsnetserver"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewToken(t *testing.T) {
	// Generate a test signing key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	err = key.Set(jwk.AlgorithmKey, "ES256")
	require.NoError(t, err)

	testWhois := tsnetserver.TailscaleWhoIs{
		NodeID:        "test-node-id",
		Name:          "test-node.example.com",
		Hostname:      "test-node",
		IP4:           "100.64.0.1",
		IP6:           "fd7a:115c:a1e0::1",
		UserLoginName: "user@example.com",
		Tags:          []string{"tag:webserver", "tag:production"},
	}

	t.Run("Basic token generation", func(t *testing.T) {
		resp, err := NewToken(key, TokenRequest{
			Issuer:   "https://test-issuer.example.com",
			Audience: "https://test-audience.example.com",
			Lifetime: 5 * time.Minute,
			Subject:  testWhois,
		})
		require.NoError(t, err)

		// Verify response fields
		assert.NotEmpty(t, resp.Token, "Token should not be empty")
		assert.NotEmpty(t, resp.JTI, "JTI should not be empty")
		assert.Equal(t, int64(300), resp.ExpiresIn, "ExpiresIn should be 300 seconds (5 minutes)")
		assert.Greater(t, resp.ExpiresOn, time.Now().Unix(), "ExpiresOn should be in the future")
		assert.LessOrEqual(t, resp.NotBefore, time.Now().Unix(), "NotBefore should be now or in the past")
	})

	t.Run("Subject claim matches node name", func(t *testing.T) {
		resp, err := NewToken(key, TokenRequest{
			Issuer:   "https://test-issuer.example.com",
			Audience: "https://test-audience.example.com",
			Lifetime: 5 * time.Minute,
			Subject:  testWhois,
		})
		require.NoError(t, err)

		parsedToken, err := jwt.Parse([]byte(resp.Token), jwt.WithVerify(false))
		require.NoError(t, err)

		sub, ok := parsedToken.Subject()
		require.True(t, ok, "Subject claim should be present")
		assert.Equal(t, "test-node.example.com", sub, "Subject should match node name")
	})

	t.Run("Issuer claim is set correctly", func(t *testing.T) {
		resp, err := NewToken(key, TokenRequest{
			Issuer:   "https://my-issuer.example.com",
			Audience: "https://test-audience.example.com",
			Lifetime: 5 * time.Minute,
			Subject:  testWhois,
		})
		require.NoError(t, err)

		parsedToken, err := jwt.Parse([]byte(resp.Token), jwt.WithVerify(false))
		require.NoError(t, err)

		iss, ok := parsedToken.Issuer()
		require.True(t, ok, "Issuer claim should be present")
		assert.Equal(t, "https://my-issuer.example.com", iss)
	})

	t.Run("Issuer can be empty", func(t *testing.T) {
		resp, err := NewToken(key, TokenRequest{
			Issuer:   "",
			Audience: "https://test-audience.example.com",
			Lifetime: 5 * time.Minute,
			Subject:  testWhois,
		})
		require.NoError(t, err)

		parsedToken, err := jwt.Parse([]byte(resp.Token), jwt.WithVerify(false))
		require.NoError(t, err)

		_, ok := parsedToken.Issuer()
		assert.False(t, ok, "Issuer claim should not be present when empty")
	})

	t.Run("Audience claim is set correctly", func(t *testing.T) {
		resp, err := NewToken(key, TokenRequest{
			Issuer:   "https://test-issuer.example.com",
			Audience: "https://my-api.example.com",
			Lifetime: 5 * time.Minute,
			Subject:  testWhois,
		})
		require.NoError(t, err)

		parsedToken, err := jwt.Parse([]byte(resp.Token), jwt.WithVerify(false))
		require.NoError(t, err)

		audiences, ok := parsedToken.Audience()
		require.True(t, ok, "Audience claim should be present")
		require.Len(t, audiences, 1, "Should have exactly one audience")
		assert.Equal(t, "https://my-api.example.com", audiences[0])
	})

	t.Run("Audience can be empty", func(t *testing.T) {
		resp, err := NewToken(key, TokenRequest{
			Issuer:   "https://test-issuer.example.com",
			Audience: "",
			Lifetime: 5 * time.Minute,
			Subject:  testWhois,
		})
		require.NoError(t, err)

		parsedToken, err := jwt.Parse([]byte(resp.Token), jwt.WithVerify(false))
		require.NoError(t, err)

		_, ok := parsedToken.Audience()
		assert.False(t, ok, "Audience claim should not be present when empty")
	})

	t.Run("Token lifetime is respected", func(t *testing.T) {
		testCases := []struct {
			name     string
			lifetime time.Duration
		}{
			{"1 minute", 1 * time.Minute},
			{"5 minutes", 5 * time.Minute},
			{"30 minutes", 30 * time.Minute},
			{"1 hour", 1 * time.Hour},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				before := time.Now()
				resp, err := NewToken(key, TokenRequest{
					Issuer:   "https://test-issuer.example.com",
					Audience: "https://test-audience.example.com",
					Lifetime: tc.lifetime,
					Subject:  testWhois,
				})
				require.NoError(t, err)
				after := time.Now()

				// Check ExpiresIn matches lifetime
				assert.Equal(t, int64(tc.lifetime.Seconds()), resp.ExpiresIn)

				// Check ExpiresOn is approximately now + lifetime
				expectedExpiry := before.Add(tc.lifetime).Unix()
				assert.GreaterOrEqual(t, resp.ExpiresOn, expectedExpiry)
				assert.LessOrEqual(t, resp.ExpiresOn, after.Add(tc.lifetime).Unix())

				// Verify in the parsed token
				parsedToken, err := jwt.Parse([]byte(resp.Token), jwt.WithVerify(false))
				require.NoError(t, err)

				exp, ok := parsedToken.Expiration()
				require.True(t, ok)
				assert.Equal(t, resp.ExpiresOn, exp.Unix())
			})
		}
	})

	t.Run("Timestamps are consistent", func(t *testing.T) {
		before := time.Now()
		resp, err := NewToken(key, TokenRequest{
			Issuer:   "https://test-issuer.example.com",
			Audience: "https://test-audience.example.com",
			Lifetime: 10 * time.Minute,
			Subject:  testWhois,
		})
		require.NoError(t, err)
		after := time.Now()

		parsedToken, err := jwt.Parse([]byte(resp.Token), jwt.WithVerify(false))
		require.NoError(t, err)

		iat, ok := parsedToken.IssuedAt()
		require.True(t, ok)
		nbf, ok := parsedToken.NotBefore()
		require.True(t, ok)
		exp, ok := parsedToken.Expiration()
		require.True(t, ok)

		// iat and nbf should be the same
		assert.Equal(t, iat.Unix(), nbf.Unix(), "IssuedAt and NotBefore should be identical")

		// iat should be between before and after
		assert.GreaterOrEqual(t, iat.Unix(), before.Unix())
		assert.LessOrEqual(t, iat.Unix(), after.Unix())

		// exp should be iat + lifetime
		expectedExp := iat.Add(10 * time.Minute).Unix()
		assert.Equal(t, expectedExp, exp.Unix())
	})

	t.Run("Custom tsiam claim contains all fields", func(t *testing.T) {
		resp, err := NewToken(key, TokenRequest{
			Issuer:   "https://test-issuer.example.com",
			Audience: "https://test-audience.example.com",
			Lifetime: 5 * time.Minute,
			Subject:  testWhois,
		})
		require.NoError(t, err)

		parsedToken, err := jwt.Parse([]byte(resp.Token), jwt.WithVerify(false))
		require.NoError(t, err)

		// Extract the tsiam claim
		var tsiamMap map[string]interface{}
		err = parsedToken.Get("italypaleale.me/tsiam", &tsiamMap)
		require.NoError(t, err, "tsiam claim should be present")

		assert.Equal(t, "test-node-id", tsiamMap["nodeId"])
		assert.Equal(t, "test-node.example.com", tsiamMap["name"])
		assert.Equal(t, "test-node", tsiamMap["hostname"])
		assert.Equal(t, "100.64.0.1", tsiamMap["ip4"])
		assert.Equal(t, "fd7a:115c:a1e0::1", tsiamMap["ip6"])
		assert.Equal(t, "user@example.com", tsiamMap["userLoginName"])

		tags, ok := tsiamMap["tags"].([]interface{})
		require.True(t, ok, "tags should be an array")
		assert.Len(t, tags, 2)
		assert.Equal(t, "tag:webserver", tags[0])
		assert.Equal(t, "tag:production", tags[1])
	})

	t.Run("Token signature is valid", func(t *testing.T) {
		resp, err := NewToken(key, TokenRequest{
			Issuer:   "https://test-issuer.example.com",
			Audience: "https://test-audience.example.com",
			Lifetime: 5 * time.Minute,
			Subject:  testWhois,
		})
		require.NoError(t, err)

		// Parse and verify the token signature
		alg, ok := key.Algorithm()
		require.True(t, ok)
		parsedToken, err := jwt.Parse([]byte(resp.Token),
			jwt.WithKey(alg, key),
		)
		require.NoError(t, err, "Token signature should be valid")
		assert.NotNil(t, parsedToken)
	})

	t.Run("Key without algorithm fails", func(t *testing.T) {
		// Create a key without algorithm
		badKey, err := jwk.Import(privateKey)
		require.NoError(t, err)

		_, err = NewToken(badKey, TokenRequest{
			Issuer:   "https://test-issuer.example.com",
			Audience: "https://test-audience.example.com",
			Lifetime: 5 * time.Minute,
			Subject:  testWhois,
		})
		require.Error(t, err)
		require.ErrorContains(t, err, "algorithm")
	})

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
