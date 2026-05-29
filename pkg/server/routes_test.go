package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/italypaleale/go-kit/tsnetserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
