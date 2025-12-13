package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Initialize test keys
	err := generateSigningKey("RS256", "")
	if err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

func TestHandleJWKS(t *testing.T) {
	// Create a request to the JWKS endpoint
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	// Call the handler
	handleJWKS(w, req)

	// Check the response
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the response as JWK Set
	set, err := jwk.Parse(w.Body.Bytes())
	require.NoError(t, err, "Failed to parse JWKS")

	// Verify the response has keys
	assert.NotZero(t, set.Len(), "Expected at least one key in JWKS response")

	// Get the first key
	key, ok := set.Key(0)
	require.True(t, ok, "Failed to get key from set")

	// Verify key properties
	assert.Equal(t, jwa.EC(), key.KeyType())
	alg, ok := key.Algorithm()
	assert.True(t, ok, "Expected algorithm to be set")
	assert.Equal(t, jwa.ES256(), alg)
	kid, ok := key.KeyID()
	assert.True(t, ok, "Expected kid to be set")
	assert.NotEmpty(t, kid, "Expected kid to be non-empty")
}

func TestHandleRoot(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handleRoot(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()
	assert.NotEmpty(t, body, "Expected non-empty response body")
}

func TestHandleToken(t *testing.T) {
	// Set issuer URL for test
	issuerURL = "https://test-tsiam"

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()

	handleToken(w, req)

	// Should succeed even without proper Tailscale headers in test
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the response
	var response map[string]any
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err, "Failed to decode response")

	// Check for required fields
	assert.NotEmpty(t, response["access_token"], "Expected access_token in response")
	assert.Equal(t, "Bearer", response["token_type"])

	// JSON numbers are unmarshaled as float64
	expiresIn, ok := response["expires_in"].(float64)
	require.True(t, ok, "Expected expires_in to be a number")
	assert.Equal(t, defaultTokenLifetime, int(expiresIn))

	// Try to parse the JWT (should be valid format)
	tokenString := response["access_token"].(string)
	token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	require.NoError(t, err, "Failed to parse JWT")

	// Verify claims exist
	issuer, ok := token.Issuer()
	assert.True(t, ok, "Expected issuer to be set")
	assert.NotEmpty(t, issuer, "Expected issuer to be non-empty")
	subject, ok := token.Subject()
	assert.True(t, ok, "Expected subject to be set")
	assert.NotEmpty(t, subject, "Expected subject to be non-empty")

	// Check custom claims
	var nodeID string
	err = token.Get("node_id", &nodeID)
	assert.NoError(t, err, "Expected node_id claim")
}

func TestHandleRoot_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	w := httptest.NewRecorder()

	handleRoot(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGenerateSigningKey_ES256(t *testing.T) {
	err := generateSigningKey("ES256", "")
	require.NoError(t, err, "Failed to generate ES256 key")
	assert.Equal(t, jwa.ES256(), algorithm)
}

func TestGenerateSigningKey_ES384(t *testing.T) {
	err := generateSigningKey("ES384", "")
	require.NoError(t, err, "Failed to generate ES384 key")
	assert.Equal(t, jwa.ES384(), algorithm)
}

func TestGenerateSigningKey_ES512(t *testing.T) {
	err := generateSigningKey("ES512", "")
	require.NoError(t, err, "Failed to generate ES512 key")
	assert.Equal(t, jwa.ES512(), algorithm)
}

func TestGenerateSigningKey_EdDSA(t *testing.T) {
	err := generateSigningKey("EdDSA", "ed25519")
	require.NoError(t, err, "Failed to generate EdDSA key")
	assert.Equal(t, jwa.EdDSA(), algorithm)
}

func TestGenerateSigningKey_UnsupportedAlgorithm(t *testing.T) {
	err := generateSigningKey("HS256", "")
	assert.Error(t, err, "Expected error for unsupported algorithm")
}

func TestGenerateSigningKey_EdDSA_InvalidCurve(t *testing.T) {
	err := generateSigningKey("EdDSA", "ed448")
	assert.Error(t, err, "Expected error for unsupported EdDSA curve")
}
