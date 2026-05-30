package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/italypaleale/go-kit/httpserver"
	"github.com/italypaleale/go-kit/tsnetserver"
	"github.com/lestrrat-go/jwx/v4/jwk"
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

// Builds a Server with a fresh signing key and a pre-computed JWKS for discovery tests
// Hostname is fixed so the OIDC URLs are predictable; whoIs is unused by these handlers
func newDiscoveryServer(t *testing.T) *Server {
	t.Helper()
	signingKey, err := jwks.NewSigningKey("ES256", "")
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
	s := newDiscoveryServer(t)

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
	s := newDiscoveryServer(t)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	s.handleGetOpenIDConfiguration(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Header().Get(httpserver.HeaderContentType), "application/json")

	//nolint:tagliatelle
	var doc struct {
		Issuer        string `json:"issuer"`
		TokenEndpoint string `json:"token_endpoint"`
		JWKSURI       string `json:"jwks_uri"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &doc))

	expectedBase := "https://" + discoveryTestHostname
	assert.Equal(t, expectedBase, doc.Issuer)
	assert.Equal(t, expectedBase+"/token", doc.TokenEndpoint)
	assert.Equal(t, expectedBase+"/.well-known/jwks.json", doc.JWKSURI)
}
