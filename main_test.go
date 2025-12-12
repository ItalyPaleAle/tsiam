package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestHandleJWKS(t *testing.T) {
	// Create a request to the JWKS endpoint
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	// Call the handler
	handleJWKS(w, req)

	// Check the response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse the response
	var response JWKSResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify the response has keys
	if len(response.Keys) == 0 {
		t.Error("Expected at least one key in JWKS response")
	}

	// Verify key properties
	key := response.Keys[0]
	if key.Kty != "RSA" {
		t.Errorf("Expected key type RSA, got %s", key.Kty)
	}
	if key.Alg != "RS256" {
		t.Errorf("Expected algorithm RS256, got %s", key.Alg)
	}
	if key.Use != "sig" {
		t.Errorf("Expected key use 'sig', got %s", key.Use)
	}
	if key.Kid == "" {
		t.Error("Expected kid to be set")
	}
	if key.N == "" {
		t.Error("Expected N (modulus) to be set")
	}
	if key.E == "" {
		t.Error("Expected E (exponent) to be set")
	}
}

func TestHandleJWKS_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	handleJWKS(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestHandleRoot(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handleRoot(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if body == "" {
		t.Error("Expected non-empty response body")
	}
}

func TestHandleToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()

	handleToken(w, req)

	// Should succeed even without proper Tailscale headers in test
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse the response
	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Check for required fields
	if response["access_token"] == "" {
		t.Error("Expected access_token in response")
	}
	if response["token_type"] != "Bearer" {
		t.Errorf("Expected token_type 'Bearer', got %s", response["token_type"])
	}
	if response["expires_in"] != "3600" {
		t.Errorf("Expected expires_in '3600', got %s", response["expires_in"])
	}

	// Try to parse the JWT (should be valid format)
	tokenString := response["access_token"]
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, &TokenClaims{})
	if err != nil {
		t.Fatalf("Failed to parse JWT: %v", err)
	}

	// Verify claims exist
	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		t.Fatal("Failed to cast claims")
	}

	// Basic validation
	if claims.Issuer == "" {
		t.Error("Expected issuer to be set")
	}
}

func TestHandleToken_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/token", nil)
	w := httptest.NewRecorder()

	handleToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestHandleRoot_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	w := httptest.NewRecorder()

	handleRoot(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}
