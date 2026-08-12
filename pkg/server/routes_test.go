package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/italypaleale/go-kit/httpserver"
	"github.com/italypaleale/go-kit/tsnetserver"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/tsiam/pkg/jwks"
)

func TestExtractAudience(t *testing.T) {
	tests := []struct {
		name        string
		resource    string
		audience    string
		expected    string
		expectError bool
		errorType   string
	}{
		{
			name:        "Valid resource parameter",
			resource:    "https://api.example.com",
			audience:    "",
			expected:    "https://api.example.com",
			expectError: false,
		},
		{
			name:        "Valid audience parameter",
			resource:    "",
			audience:    "https://api.example.com",
			expected:    "https://api.example.com",
			expectError: false,
		},
		{
			name:        "Both parameters with same value",
			resource:    "https://api.example.com",
			audience:    "https://api.example.com",
			expected:    "https://api.example.com",
			expectError: false,
		},
		{
			name:        "Both parameters with different values",
			resource:    "https://api1.example.com",
			audience:    "https://api2.example.com",
			expected:    "",
			expectError: true,
			errorType:   "audience_conflict",
		},
		{
			name:        "Neither parameter provided",
			resource:    "",
			audience:    "",
			expected:    "",
			expectError: true,
			errorType:   "missing_audience",
		},
		{
			name:        "Resource with whitespace trimmed",
			resource:    "  https://api.example.com  ",
			audience:    "",
			expected:    "https://api.example.com",
			expectError: false,
		},
		{
			name:        "Audience with whitespace trimmed",
			resource:    "",
			audience:    "  https://api.example.com  ",
			expected:    "https://api.example.com",
			expectError: false,
		},
		{
			name:        "Empty after trimming",
			resource:    "   ",
			audience:    "",
			expected:    "",
			expectError: true,
			errorType:   "missing_audience",
		},
		{
			name:        "Audience too long",
			resource:    "",
			audience:    strings.Repeat("a", 513),
			expected:    "",
			expectError: true,
			errorType:   "audience_too_long",
		},
		{
			name:        "Audience at max length (512 chars)",
			resource:    "",
			audience:    strings.Repeat("a", 512),
			expected:    strings.Repeat("a", 512),
			expectError: false,
		},
		{
			name:        "Audience containing CR is rejected",
			resource:    "https://api.example.com\r\nLog-Injection: pwned",
			audience:    "",
			expected:    "",
			expectError: true,
			errorType:   "audience_invalid_chars",
		},
		{
			name:        "Audience containing NUL is rejected",
			resource:    "https://api.example.com\x00admin",
			audience:    "",
			expected:    "",
			expectError: true,
			errorType:   "audience_invalid_chars",
		},
		{
			name:        "Audience containing DEL is rejected",
			resource:    "https://api.example.com\x7f",
			audience:    "",
			expected:    "",
			expectError: true,
			errorType:   "audience_invalid_chars",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request with query parameters
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", nil)
			q := req.URL.Query()
			if tt.resource != "" {
				q.Add("resource", tt.resource)
			}
			if tt.audience != "" {
				q.Add("audience", tt.audience)
			}
			req.URL.RawQuery = q.Encode()

			// Extract audience
			result, err := extractAudience(req)

			if tt.expectError {
				require.NotNil(t, err, "Expected an error but got nil")
				if tt.errorType != "" {
					// Check that the error code matches
					assert.Contains(t, err.Error(), tt.errorType)
				}
			} else {
				require.Nil(t, err, "Expected no error but got: %v", err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestSanitizeWhois(t *testing.T) {
	tests := []struct {
		name           string
		input          tsnetserver.TailscaleWhoIs
		expectUserName string
	}{
		{
			name: "Untagged node retains UserLoginName",
			input: tsnetserver.TailscaleWhoIs{
				NodeID:        "node1",
				Name:          "alice-laptop.tailnet.ts.net",
				UserLoginName: "alice@example.com",
				Tags:          nil,
			},
			expectUserName: "alice@example.com",
		},
		{
			name: "Tagged node clears UserLoginName",
			input: tsnetserver.TailscaleWhoIs{
				NodeID:        "node2",
				Name:          "db-backup-1.tailnet.ts.net",
				UserLoginName: "admin@example.com",
				Tags:          []string{"tag:db-backup"},
			},
			expectUserName: "",
		},
		{
			name: "Node with multiple tags clears UserLoginName",
			input: tsnetserver.TailscaleWhoIs{
				NodeID:        "node3",
				Name:          "worker-1.tailnet.ts.net",
				UserLoginName: "admin@example.com",
				Tags:          []string{"tag:worker", "tag:prod"},
			},
			expectUserName: "",
		},
		{
			name: "Empty tags slice preserves UserLoginName",
			input: tsnetserver.TailscaleWhoIs{
				NodeID:        "node4",
				UserLoginName: "bob@example.com",
				Tags:          []string{},
			},
			expectUserName: "bob@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeWhois(tt.input)
			assert.Equal(t, tt.expectUserName, result.UserLoginName)
			// Other identifying fields should pass through untouched
			assert.Equal(t, tt.input.NodeID, result.NodeID)
			assert.Equal(t, tt.input.Name, result.Name)
			assert.Equal(t, tt.input.Tags, result.Tags)
		})
	}
}

const discoveryTestHostname = "tsiam.test-tailnet.ts.net"

//nolint:tagliatelle
type oidcConfigurationDocument struct {
	Issuer                           string   `json:"issuer"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	ClaimsSupported                  []string `json:"claims_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

// Builds a Server with a fresh signing key and a pre-computed JWKS for discovery tests
// Hostname is fixed so the OIDC URLs are predictable; whoIs is unused by these handlers
func newDiscoveryServer(t *testing.T, algorithm string) *Server {
	t.Helper()
	signingKey, err := jwks.NewSigningKey(algorithm, "")
	require.NoError(t, err)
	publicJwks, err := jwks.GetPublicJWKSAsJSON(signingKey)
	require.NoError(t, err)
	return &Server{
		signingKey: signingKey,
		publicJwks: publicJwks,
		hostname:   func() string { return discoveryTestHostname },
	}
}

func TestHandleGetJWKS(t *testing.T) {
	s := newDiscoveryServer(t, "ES256")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	s.handleGetJWKS(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Header().Get(httpserver.HeaderContentType), "application/json")

	// Body must be byte-identical to the precomputed JWKS; any drift between the cached bytes and what's served would break relying-party verification
	assert.Equal(t, string(s.publicJwks), rr.Body.String())

	// The body must round-trip through jwk.ParseString and contain a key whose kid matches the live signing key
	set, err := jwk.ParseString(rr.Body.String())
	require.NoError(t, err)
	require.Equal(t, 1, set.Len(), "JWKS should contain exactly one key for the live signing key")

	pubKey, ok := set.Key(0)
	require.True(t, ok)
	kid, ok := pubKey.KeyID()
	require.True(t, ok)
	expectedKid, ok := s.signingKey.KeyID()
	require.True(t, ok)
	assert.Equal(t, expectedKid, kid)
}

func TestHandleGetOpenIDConfiguration(t *testing.T) {
	algorithms := []string{"RS256", "ES256", "ES384", "ES512", "EdDSA"}
	for _, algorithm := range algorithms {
		t.Run(algorithm, func(t *testing.T) {
			s := newDiscoveryServer(t, algorithm)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/openid-configuration", nil)
			rr := httptest.NewRecorder()
			s.handleGetOpenIDConfiguration(rr, req)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Contains(t, rr.Header().Get(httpserver.HeaderContentType), "application/json")

			var doc oidcConfigurationDocument
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &doc))

			expectedBase := "https://" + discoveryTestHostname
			assert.Equal(t, expectedBase, doc.Issuer)
			assert.Equal(t, expectedBase+"/token", doc.TokenEndpoint)
			assert.Equal(t, expectedBase+"/.well-known/jwks.json", doc.JWKSURI)
			assert.Equal(t, []string{"aud", "exp", "iat", "iss", "jti", "nbf", "sub"}, doc.ClaimsSupported)
			assert.Equal(t, []string{"id_token"}, doc.ResponseTypesSupported)
			assert.Equal(t, []string{"public"}, doc.SubjectTypesSupported)
			assert.Equal(t, []string{algorithm}, doc.IDTokenSigningAlgValuesSupported)
		})
	}
}

func TestOIDCDiscoveryMatchesIssuedToken(t *testing.T) {
	s, restore := newTestServer(t, nil, func(*http.Request) (tsnetserver.TailscaleWhoIs, error) {
		return defaultWhois(), nil
	})
	defer restore()

	tokenRecorder := postToken(t, s, "?resource="+testAudience)
	require.Equal(t, http.StatusOK, tokenRecorder.Code, "body: %s", tokenRecorder.Body.String())

	//nolint:tagliatelle
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	err := json.Unmarshal(tokenRecorder.Body.Bytes(), &tokenResponse)
	require.NoError(t, err)

	discoveryRequest := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/openid-configuration", nil)
	discoveryRecorder := httptest.NewRecorder()
	s.handleGetOpenIDConfiguration(discoveryRecorder, discoveryRequest)
	require.Equal(t, http.StatusOK, discoveryRecorder.Code)

	var discoveryDocument oidcConfigurationDocument
	err = json.Unmarshal(discoveryRecorder.Body.Bytes(), &discoveryDocument)
	require.NoError(t, err)

	jwksRequest := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/jwks.json", nil)
	jwksRecorder := httptest.NewRecorder()
	s.handleGetJWKS(jwksRecorder, jwksRequest)
	require.Equal(t, http.StatusOK, jwksRecorder.Code)

	keySet, err := jwk.Parse(jwksRecorder.Body.Bytes())
	require.NoError(t, err)
	parsedToken, err := jwt.Parse([]byte(tokenResponse.AccessToken), jwt.WithKeySet(keySet))
	require.NoError(t, err)

	tokenIssuer, ok := parsedToken.Issuer()
	require.True(t, ok)
	assert.Equal(t, discoveryDocument.Issuer, tokenIssuer)
	for _, claim := range discoveryDocument.ClaimsSupported {
		assert.True(t, parsedToken.Has(claim), "issued token should contain advertised claim %q", claim)
	}

	signedMessage, err := jws.Parse([]byte(tokenResponse.AccessToken))
	require.NoError(t, err)
	require.Len(t, signedMessage.Signatures(), 1)
	tokenAlgorithm, ok := signedMessage.Signatures()[0].ProtectedHeaders().Algorithm()
	require.True(t, ok)
	assert.Equal(t, []string{tokenAlgorithm.String()}, discoveryDocument.IDTokenSigningAlgValuesSupported)
}

func TestHandleGetOpenIDConfigurationWithoutSigningAlgorithm(t *testing.T) {
	s := newDiscoveryServer(t, "ES256")
	err := s.signingKey.Remove(jwk.AlgorithmKey)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	s.handleGetOpenIDConfiguration(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestNewServerRejectsSigningKeyWithoutAlgorithm(t *testing.T) {
	signingKey, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err)
	err = signingKey.Remove(jwk.AlgorithmKey)
	require.NoError(t, err)

	s, err := NewServer(NewServerOpts{SigningKey: signingKey})
	require.EqualError(t, err, "signing key does not contain an algorithm")
	assert.Nil(t, s)
}

func TestNewServerRejectsInvalidSigningKeys(t *testing.T) {
	symmetricKey, err := jwk.Import[jwk.Key]([]byte("01234567890123456789012345678901"))
	require.NoError(t, err)
	err = symmetricKey.Set(jwk.AlgorithmKey, jwa.HS256())
	require.NoError(t, err)

	publicSource, err := jwks.NewSigningKey("ES256", "")
	require.NoError(t, err)
	publicKey, err := publicSource.PublicKey()
	require.NoError(t, err)

	encryptionKey, err := jwks.NewSigningKey("RS256", "")
	require.NoError(t, err)
	err = encryptionKey.Set(jwk.AlgorithmKey, jwa.RSA_OAEP())
	require.NoError(t, err)

	tests := []struct {
		name          string
		key           jwk.Key
		expectedError string
	}{
		{
			name:          "symmetric key",
			key:           symmetricKey,
			expectedError: "symmetric signing keys are not supported",
		},
		{
			name:          "public key",
			key:           publicKey,
			expectedError: "signing key must be private",
		},
		{
			name:          "non-signature algorithm",
			key:           encryptionKey,
			expectedError: "signing key algorithm is not a signature algorithm",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := NewServer(NewServerOpts{SigningKey: test.key})
			require.EqualError(t, err, test.expectedError)
			assert.Nil(t, s)
		})
	}
}
