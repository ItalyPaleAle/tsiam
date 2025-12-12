package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"tailscale.com/tsnet"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
)

// JWKSResponse represents the JWKS response structure
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// TokenClaims represents the JWT claims
type TokenClaims struct {
	jwt.RegisteredClaims
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	UserID   string `json:"user_id,omitempty"`
}

func init() {
	// Generate RSA keypair for signing JWTs
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}
	publicKey = &privateKey.PublicKey

	// Generate a key ID
	keyID = fmt.Sprintf("key-%d", time.Now().Unix())
}

func main() {
	// Initialize tsnet server
	hostname := os.Getenv("TSIAM_HOSTNAME")
	if hostname == "" {
		hostname = "tsiam"
	}

	srv := &tsnet.Server{
		Hostname: hostname,
		Logf:     log.Printf,
	}
	defer srv.Close()

	// Start listening
	ln, err := srv.ListenTLS("tcp", ":443")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	log.Printf("Starting tsiam server on %s...", hostname)

	// Setup HTTP handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/token", handleToken)
	mux.HandleFunc("/.well-known/jwks.json", handleJWKS)
	mux.HandleFunc("/", handleRoot)

	// Start HTTP server
	if err := http.Serve(ln, mux); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Tailscale Workload Identity Service\n")
	fmt.Fprintf(w, "\nEndpoints:\n")
	fmt.Fprintf(w, "  GET /token - Get a JWT token for this workload\n")
	fmt.Fprintf(w, "  GET /.well-known/jwks.json - Get the JWKS public keys\n")
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get Tailscale connection info from tsnet
	// The tsnet.Server provides the underlying connection which includes peer info
	who, err := getTailscaleWhoIs(r)
	if err != nil {
		log.Printf("Failed to get Tailscale identity: %v", err)
		http.Error(w, "Failed to identify caller", http.StatusInternalServerError)
		return
	}

	// Create JWT claims
	now := time.Now()
	claims := TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://tsiam.tailnet.ts.net",
			Subject:   who.NodeID,
			Audience:  jwt.ClaimStrings{"tsiam"},
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		NodeID:   who.NodeID,
		NodeName: who.NodeName,
		UserID:   who.UserID,
	}

	// Create and sign the token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		log.Printf("Failed to sign token: %v", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Return the token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token": tokenString,
		"token_type":   "Bearer",
		"expires_in":   "3600",
	})
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Convert public key to JWK format
	n := publicKey.N.Bytes()
	e := big.NewInt(int64(publicKey.E)).Bytes()

	jwk := JWK{
		Kid: keyID,
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(n),
		E:   base64.RawURLEncoding.EncodeToString(e),
	}

	response := JWKSResponse{
		Keys: []JWK{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// WhoIsInfo contains information about the Tailscale node making the request
type WhoIsInfo struct {
	NodeID   string
	NodeName string
	UserID   string
}

func getTailscaleWhoIs(r *http.Request) (*WhoIsInfo, error) {
	// In a real tsnet application, we would use the tsnet.Server's LocalClient
	// to query the WhoIs API. For now, we'll extract from headers/connection info.
	
	// tsnet automatically sets the remote address to the Tailscale node info
	// We can also use r.TLS.PeerCertificates if mTLS is enabled
	
	// For demonstration, we'll use the remote address and X-Forwarded-For header
	// In production, tsnet provides proper APIs to get node identity
	
	nodeID := r.Header.Get("X-Tailscale-Node-Id")
	if nodeID == "" {
		// Fallback to remote address
		nodeID = r.RemoteAddr
	}
	
	nodeName := r.Header.Get("X-Tailscale-Node-Name")
	if nodeName == "" {
		nodeName = "unknown"
	}
	
	userID := r.Header.Get("X-Tailscale-User-Id")
	
	return &WhoIsInfo{
		NodeID:   nodeID,
		NodeName: nodeName,
		UserID:   userID,
	}, nil
}
