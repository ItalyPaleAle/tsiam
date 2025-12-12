package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"tailscale.com/tsnet"
)

const (
	// Default token lifetime in seconds
	defaultTokenLifetime = 3600
	// Timeout for WhoIs API calls
	whoIsTimeout = 5 * time.Second
	// RSA key size in bits
	rsaKeySize = 2048
)

var (
	// CLI flags
	signingAlgorithm = flag.String("algorithm", "RS256", "Signing algorithm: RS256, ES256, ES384, ES512, EdDSA")
	
	// Keys and config
	signingKey jwk.Key
	publicKey  jwk.Key
	keyID      string
	tsServer   *tsnet.Server
	issuerURL  string
	algorithm  jwa.SignatureAlgorithm
)

// WhoIsInfo contains information about the Tailscale node making the request
type WhoIsInfo struct {
	NodeID   string
	NodeName string
	UserID   string
}

func generateSigningKey(alg string) error {
	// Generate a key ID
	keyID = fmt.Sprintf("key-%d", time.Now().Unix())

	var err error
	var rawKey interface{}

	switch alg {
	case "RS256":
		algorithm = jwa.RS256()
		rsaKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
		if err != nil {
			return fmt.Errorf("failed to generate RSA key: %w", err)
		}
		rawKey = rsaKey

	case "ES256":
		algorithm = jwa.ES256()
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		rawKey = ecKey

	case "ES384":
		algorithm = jwa.ES384()
		ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		rawKey = ecKey

	case "ES512":
		algorithm = jwa.ES512()
		ecKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		rawKey = ecKey

	case "EdDSA":
		algorithm = jwa.EdDSA()
		_, edKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate EdDSA key: %w", err)
		}
		rawKey = edKey

	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}

	// Create JWK from the raw key
	signingKey, err = jwk.Import(rawKey)
	if err != nil {
		return fmt.Errorf("failed to import signing key: %w", err)
	}

	// Set key ID
	if err := signingKey.Set(jwk.KeyIDKey, keyID); err != nil {
		return fmt.Errorf("failed to set key ID: %w", err)
	}

	// Set algorithm
	if err := signingKey.Set(jwk.AlgorithmKey, algorithm); err != nil {
		return fmt.Errorf("failed to set algorithm: %w", err)
	}

	// Create public key
	publicKey, err = signingKey.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	return nil
}

func main() {
	// Parse CLI flags
	flag.Parse()

	// Generate signing key based on algorithm
	if err := generateSigningKey(*signingAlgorithm); err != nil {
		log.Fatalf("Failed to generate signing key: %v", err)
	}
	log.Printf("Using signing algorithm: %s", algorithm)

	// Initialize tsnet server
	hostname := os.Getenv("TSIAM_HOSTNAME")
	if hostname == "" {
		hostname = "tsiam"
	}

	// Set the issuer URL based on hostname
	issuerURL = fmt.Sprintf("https://%s", hostname)

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
	who, err := getTailscaleWhoIs(r)
	if err != nil {
		log.Printf("Failed to get Tailscale identity: %v", err)
		http.Error(w, "Failed to identify caller", http.StatusInternalServerError)
		return
	}

	// Create JWT token
	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer(issuerURL).
		Subject(who.NodeID).
		Audience([]string{"tsiam"}).
		IssuedAt(now).
		NotBefore(now).
		Expiration(now.Add(time.Duration(defaultTokenLifetime) * time.Second)).
		Claim("node_id", who.NodeID).
		Claim("node_name", who.NodeName).
		Claim("user_id", who.UserID).
		Build()
	if err != nil {
		log.Printf("Failed to build token: %v", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Sign the token
	signed, err := jwt.Sign(token, jwt.WithKey(algorithm, signingKey))
	if err != nil {
		log.Printf("Failed to sign token: %v", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Return the token
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"access_token": string(signed),
		"token_type":   "Bearer",
		"expires_in":   defaultTokenLifetime,
	}
	if err := writeJSON(w, response); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Create JWKS with the public key
	set := jwk.NewSet()
	if err := set.AddKey(publicKey); err != nil {
		log.Printf("Failed to add key to set: %v", err)
		http.Error(w, "Failed to generate JWKS", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := writeJSON(w, set); err != nil {
		log.Printf("Failed to write JWKS: %v", err)
	}
}

// writeJSON is a helper to write JSON responses
func writeJSON(w http.ResponseWriter, v interface{}) error {
	// Check if it's a jwk.Set - use standard json marshaling
	if set, ok := v.(jwk.Set); ok {
		data, err := json.Marshal(set)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	// For other types, use standard json encoding
	return json.NewEncoder(w).Encode(v)
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
	ctx, cancel := context.WithTimeout(context.Background(), whoIsTimeout)
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
