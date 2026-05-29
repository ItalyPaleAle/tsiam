package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequireEmptyBody(t *testing.T) {
	called := false
	handler := requireEmptyBody(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	t.Run("No body passes through", func(t *testing.T) {
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", nil)
		rr := httptest.NewRecorder()
		handler(rr, req)
		assert.True(t, called)
		assert.Equal(t, http.StatusNoContent, rr.Code)
	})

	t.Run("Body with Content-Length rejected upfront", func(t *testing.T) {
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", bytes.NewReader([]byte("hi")))
		req.ContentLength = 2
		rr := httptest.NewRecorder()
		handler(rr, req)
		assert.False(t, called, "handler must not run when body is present")
		assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
	})

	t.Run("Chunked body (ContentLength = -1) detected and rejected", func(t *testing.T) {
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", bytes.NewReader([]byte("chunked-data")))
		req.ContentLength = -1 // Simulates chunked transfer encoding
		rr := httptest.NewRecorder()
		handler(rr, req)
		assert.False(t, called, "handler must not run when chunked body has data")
		assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
	})

	t.Run("Empty chunked body (ContentLength = -1, no data) passes through", func(t *testing.T) {
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", bytes.NewReader(nil))
		req.ContentLength = -1
		rr := httptest.NewRecorder()
		handler(rr, req)
		assert.True(t, called, "empty chunked body should be allowed")
		assert.Equal(t, http.StatusNoContent, rr.Code)
	})
}

func TestRejectOversizedRequest(t *testing.T) {
	mw := rejectOversizedRequest(maxBodySize)
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	t.Run("Under cap passes through", func(t *testing.T) {
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader([]byte("hi")))
		req.ContentLength = 2
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.True(t, called)
		assert.Equal(t, http.StatusNoContent, rr.Code)
	})

	t.Run("At cap passes through", func(t *testing.T) {
		called = false
		payload := bytes.Repeat([]byte("a"), maxBodySize)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(payload))
		req.ContentLength = int64(len(payload))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.True(t, called)
		assert.Equal(t, http.StatusNoContent, rr.Code)
	})

	t.Run("Over cap returns 413 and skips handler", func(t *testing.T) {
		called = false
		payload := bytes.Repeat([]byte("a"), maxBodySize*2)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(payload))
		req.ContentLength = int64(len(payload))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.False(t, called, "handler must not be called when the body is oversized")
		assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
		assert.Equal(t, "close", rr.Header().Get("Connection"))
	})

	t.Run("Unknown Content-Length passes through to handler / MaxBytesReader backstop", func(t *testing.T) {
		// Chunked transfer encoding sends ContentLength = -1; the upfront check must let it through (the backstop middleware will still cap any actual body read)
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader([]byte("ignored")))
		req.ContentLength = -1
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.True(t, called)
		assert.Equal(t, http.StatusNoContent, rr.Code)
	})
}

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
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", nil)

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

func TestRequireNotFunneledRequest(t *testing.T) {
	// Helper that swaps the package-level seam for the duration of the subtest
	withFunneled := func(t *testing.T, funneled bool) {
		t.Helper()
		prev := isFunneledRequest
		isFunneledRequest = func(*http.Request) bool { return funneled }
		t.Cleanup(func() { isFunneledRequest = prev })
	}

	t.Run("Non-funneled request passes through", func(t *testing.T) {
		withFunneled(t, false)

		handlerCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusNoContent)
		})

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/whatever", nil)
		rr := httptest.NewRecorder()
		requireNotFunneledRequest(next)(rr, req)

		assert.True(t, handlerCalled, "non-funneled request should reach the wrapped handler")
		assert.Equal(t, http.StatusNoContent, rr.Code)
	})

	t.Run("Funneled request returns 404 and skips handler", func(t *testing.T) {
		withFunneled(t, true)

		handlerCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/whatever", nil)
		rr := httptest.NewRecorder()
		requireNotFunneledRequest(next)(rr, req)

		assert.False(t, handlerCalled, "funneled request must not reach the wrapped handler")
		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
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
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", nil)

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
