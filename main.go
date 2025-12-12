package main

import (
	"context"
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
	tsServer   *tsnet.Server
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

	tsServer = &tsnet.Server{
		Hostname: hostname,
		Logf:     log.Printf,
	}
	defer tsServer.Close()

	// Start listening
	ln, err := tsServer.ListenTLS("tcp", ":443")
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
	// Check if tsServer is initialized (may be nil in tests)
	if tsServer == nil {
		// In test mode, use remote address as fallback
		return &WhoIsInfo{
			NodeID:   r.RemoteAddr,
			NodeName: "test-node",
			UserID:   "test-user",
		}, nil
	}

	// Get the LocalClient to query the WhoIs API
	lc, err := tsServer.LocalClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get local client: %w", err)
	}

	// Get the remote address from the request
	remoteAddr := r.RemoteAddr
	if remoteAddr == "" {
		return nil, fmt.Errorf("no remote address in request")
	}

	// Query the WhoIs API to get secure node identity
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	whois, err := lc.WhoIs(ctx, remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to query WhoIs: %w", err)
	}

	// Extract node and user information
	nodeID := ""
	nodeName := ""
	userID := ""

	if whois.Node != nil {
		nodeID = fmt.Sprintf("%d", whois.Node.ID)
		nodeName = whois.Node.Name
	}

	if whois.UserProfile != nil {
		userID = fmt.Sprintf("%d", whois.UserProfile.ID)
	}

	return &WhoIsInfo{
		NodeID:   nodeID,
		NodeName: nodeName,
		UserID:   userID,
	}, nil
}
