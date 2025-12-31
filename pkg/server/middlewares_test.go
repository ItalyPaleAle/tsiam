package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequireNoBrowser(t *testing.T) {
	tests := []struct {
		name           string
		headers        map[string]string
		expectedStatus int
		expectError    bool
	}{
		{
			name: "Valid request with X-Tsiam header set to 1",
			headers: map[string]string{
				"X-Tsiam": "1",
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "Valid request with X-Tsiam header set to non-standard value",
			headers: map[string]string{
				"X-Tsiam": "true",
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "Valid request with X-Tsiam header set to random string",
			headers: map[string]string{
				"X-Tsiam": "my-custom-value",
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "Missing X-Tsiam header",
			headers:        map[string]string{},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Empty X-Tsiam header",
			headers: map[string]string{
				"X-Tsiam": "",
			},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Request with Origin header (browser)",
			headers: map[string]string{
				"X-Tsiam": "1",
				"Origin":  "https://example.com",
			},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Request with Sec-Fetch-Site header (browser)",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-Site": "cross-site",
			},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Request with Sec-Fetch-Mode header (browser)",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-Mode": "navigate",
			},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Request with Sec-Fetch-Dest header (browser)",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-Dest": "document",
			},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Request with Sec-Fetch-User header (browser)",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-User": "?1",
			},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Request with multiple browser headers",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Origin":         "https://example.com",
				"Sec-Fetch-Site": "same-origin",
				"Sec-Fetch-Mode": "cors",
			},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Request with non-browser headers is allowed",
			headers: map[string]string{
				"X-Tsiam":      "1",
				"User-Agent":   "curl/7.68.0",
				"Content-Type": "application/json",
				"Accept":       "*/*",
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler that should be called only if validation passes
			handlerCalled := false
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with middleware
			handler := requireNoBrowser(testHandler)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)

			// Set headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Execute request
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			// Verify status code
			assert.Equal(t, tt.expectedStatus, rr.Code)

			// Verify handler was called only when no error expected
			if tt.expectError {
				assert.False(t, handlerCalled, "Handler should not be called when validation fails")
			} else {
				assert.True(t, handlerCalled, "Handler should be called when validation passes")
			}
		})
	}
}

func TestValidateNoBrowser(t *testing.T) {
	tests := []struct {
		name        string
		headers     map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid request",
			headers: map[string]string{
				"X-Tsiam": "1",
			},
			expectError: false,
		},
		{
			name:        "Missing X-Tsiam header",
			headers:     map[string]string{},
			expectError: true,
			errorMsg:    "missing header X-Tsiam",
		},
		{
			name: "Empty X-Tsiam header",
			headers: map[string]string{
				"X-Tsiam": "",
			},
			expectError: true,
			errorMsg:    "missing header X-Tsiam",
		},
		{
			name: "Origin header present",
			headers: map[string]string{
				"X-Tsiam": "1",
				"Origin":  "https://example.com",
			},
			expectError: true,
			errorMsg:    "found browser header 'Origin'",
		},
		{
			name: "Sec-Fetch-Site header present",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-Site": "same-origin",
			},
			expectError: true,
			errorMsg:    "found browser header 'Sec-Fetch-Site'",
		},
		{
			name: "Sec-Fetch-Mode header present",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-Mode": "navigate",
			},
			expectError: true,
			errorMsg:    "found browser header 'Sec-Fetch-Mode'",
		},
		{
			name: "Sec-Fetch-Dest header present",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-Dest": "document",
			},
			expectError: true,
			errorMsg:    "found browser header 'Sec-Fetch-Dest'",
		},
		{
			name: "Sec-Fetch-User header present",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-User": "?1",
			},
			expectError: true,
			errorMsg:    "found browser header 'Sec-Fetch-User'",
		},
		{
			name: "Case sensitivity - X-Tsiam with different casing",
			headers: map[string]string{
				"x-tsiam": "1",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)

			// Set headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Validate
			err := validateNoBrowser(req)

			// Check error
			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBrowserHeadersConstant(t *testing.T) {
	// Verify all expected browser headers are in the list
	expectedHeaders := []string{
		"Origin",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"Sec-Fetch-Dest",
		"Sec-Fetch-User",
	}

	assert.Equal(t, expectedHeaders, browserHeaders, "Browser headers list should contain all expected headers")
}
