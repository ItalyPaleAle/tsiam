package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func init() {
	// Initialize test keys
	if err := generateSigningKey("RS256"); err != nil {
		panic(err)
	}
}

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

	// Parse the response as JWK Set
	set, err := jwk.Parse(w.Body.Bytes())
	if err != nil {
		t.Fatalf("Failed to parse JWKS: %v", err)
	}

	// Verify the response has keys
	if set.Len() == 0 {
		t.Error("Expected at least one key in JWKS response")
	}

	// Get the first key
	key, ok := set.Key(0)
	if !ok {
		t.Fatal("Failed to get key from set")
	}

	// Verify key properties
	if key.KeyType() != jwa.RSA() {
		t.Errorf("Expected key type RSA, got %s", key.KeyType())
	}
	alg, ok := key.Algorithm()
	if !ok {
		t.Error("Expected algorithm to be set")
	} else if alg != jwa.RS256() {
		t.Errorf("Expected algorithm RS256, got %s", alg)
	}
	kid, ok := key.KeyID()
	if !ok || kid == "" {
		t.Error("Expected kid to be set")
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
	// Set issuer URL for test
	issuerURL = "https://test-tsiam"
	
	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()

	handleToken(w, req)

	// Should succeed even without proper Tailscale headers in test
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Parse the response
	var response map[string]interface{}
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
	
	// JSON numbers are unmarshaled as float64
	expiresIn, ok := response["expires_in"].(float64)
	if !ok || int(expiresIn) != defaultTokenLifetime {
		t.Errorf("Expected expires_in '%d', got %v", defaultTokenLifetime, response["expires_in"])
	}

	// Try to parse the JWT (should be valid format)
	tokenString := response["access_token"].(string)
	token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		t.Fatalf("Failed to parse JWT: %v", err)
	}

	// Verify claims exist
	issuer, ok := token.Issuer()
	if !ok || issuer == "" {
		t.Error("Expected issuer to be set")
	}
	subject, ok := token.Subject()
	if !ok || subject == "" {
		t.Error("Expected subject to be set")
	}
	
	// Check custom claims
	var nodeID string
	if err := token.Get("node_id", &nodeID); err != nil {
		t.Error("Expected node_id claim")
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

func TestGenerateSigningKey_ES256(t *testing.T) {
	err := generateSigningKey("ES256")
	if err != nil {
		t.Fatalf("Failed to generate ES256 key: %v", err)
	}
	if algorithm != jwa.ES256() {
		t.Errorf("Expected algorithm ES256, got %s", algorithm)
	}
}

func TestGenerateSigningKey_ES384(t *testing.T) {
	err := generateSigningKey("ES384")
	if err != nil {
		t.Fatalf("Failed to generate ES384 key: %v", err)
	}
	if algorithm != jwa.ES384() {
		t.Errorf("Expected algorithm ES384, got %s", algorithm)
	}
}

func TestGenerateSigningKey_ES512(t *testing.T) {
	err := generateSigningKey("ES512")
	if err != nil {
		t.Fatalf("Failed to generate ES512 key: %v", err)
	}
	if algorithm != jwa.ES512() {
		t.Errorf("Expected algorithm ES512, got %s", algorithm)
	}
}

func TestGenerateSigningKey_EdDSA(t *testing.T) {
	err := generateSigningKey("EdDSA")
	if err != nil {
		t.Fatalf("Failed to generate EdDSA key: %v", err)
	}
	if algorithm != jwa.EdDSA() {
		t.Errorf("Expected algorithm EdDSA, got %s", algorithm)
	}
}

func TestGenerateSigningKey_UnsupportedAlgorithm(t *testing.T) {
	err := generateSigningKey("HS256")
	if err == nil {
		t.Error("Expected error for unsupported algorithm")
	}
}
