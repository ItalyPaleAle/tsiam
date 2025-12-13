package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"tailscale.com/tsnet"

	"github.com/italypaleale/tsiam/pkg/config"
	"github.com/italypaleale/tsiam/pkg/utils"
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
	// Keys and config
	signingKey jwk.Key
	publicKey  jwk.Key
	keyID      string
	tsServer   *tsnet.Server
	issuerURL  string
	algorithm  jwa.SignatureAlgorithm
	cachedJWKS []byte // Cached JSON-encoded JWKS
	keyStorage KeyStorage
	logger     *slog.Logger
)

// WhoIsInfo contains information about the Tailscale node making the request
type WhoIsInfo struct {
	NodeID   string
	NodeName string
	UserID   string
}

func genKid() (string, error) {
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random key ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func generateSigningKey(alg string, curve string) (err error) {
	// Generate a random key ID (base64url, no padding)
	keyID, err = genKid()
	if err != nil {
		return err
	}

	var rawKey any
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
		// Currently only Ed25519 is supported
		if curve != "" && curve != "Ed25519" {
			return fmt.Errorf("unsupported EdDSA curve: %s (only ed25519 is supported)", curve)
		}
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
	err = signingKey.Set(jwk.KeyIDKey, keyID)
	if err != nil {
		return fmt.Errorf("failed to set key ID: %w", err)
	}

	// Set algorithm
	err = signingKey.Set(jwk.AlgorithmKey, algorithm)
	if err != nil {
		return fmt.Errorf("failed to set algorithm: %w", err)
	}

	// Create public key
	publicKey, err = signingKey.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	// Cache the JWKS JSON
	err = cacheJWKS()
	if err != nil {
		return err
	}

	return nil
}

func cacheJWKS() error {
	set := jwk.NewSet()
	if err := set.AddKey(publicKey); err != nil {
		return fmt.Errorf("failed to add key to JWKS set: %w", err)
	}
	var err error
	cachedJWKS, err = json.Marshal(set)
	if err != nil {
		return fmt.Errorf("failed to marshal JWKS: %w", err)
	}
	return nil
}

func main() {
	var err error

	// Initialize logger
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Load configuration
	err = config.LoadConfig()
	if err != nil {
		utils.FatalError(logger, "Failed to load config", err)
	}
	cfg := config.Get()

	ctx := context.Background()

	// Initialize key storage if path is provided
	if cfg.SigningKey.StoragePath != "" {
		keyStorage, err = NewFileKeyStorage(cfg.SigningKey.StoragePath)
		if err != nil {
			utils.FatalError(logger, "Failed to initialize key storage", err)
		}

		// Try to load existing key
		loadedKey, err := keyStorage.Load(ctx)
		if err != nil {
			utils.FatalError(logger, "Failed to load key from storage", err)
		}

		if loadedKey != nil {
			// Use existing key
			signingKey = loadedKey
			logger.Info("Loaded existing signing key", "path", cfg.SigningKey.StoragePath)

			// Extract algorithm and key ID from loaded key
			loadedAlg, ok := signingKey.Algorithm()
			if ok {
				algorithm, ok = loadedAlg.(jwa.SignatureAlgorithm)
				if !ok {
					utils.FatalError(logger, "Loaded key has invalid algorithm type", errors.New("invalid algorithm type"))
				}
			}
			if kid, ok := signingKey.KeyID(); ok {
				keyID = kid
			}

			// Generate public key
			publicKey, err = signingKey.PublicKey()
			if err != nil {
				utils.FatalError(logger, "Failed to get public key", err)
			}

			// Cache JWKS
			err = cacheJWKS()
			if err != nil {
				utils.FatalError(logger, "Failed to cache JWKS", err)
			}
		} else {
			// Generate new key
			err = generateSigningKey(cfg.SigningKey.Algorithm, cfg.SigningKey.Curve)
			if err != nil {
				utils.FatalError(logger, "Failed to generate signing key", err)
			}

			// Persist the new key
			err = keyStorage.Store(ctx, signingKey)
			if err != nil {
				utils.FatalError(logger, "Failed to store key", err)
			}
			logger.Info("Generated and stored new signing key", "path", cfg.SigningKey.StoragePath)
		}
	} else {
		// Generate ephemeral key
		err = generateSigningKey(cfg.SigningKey.Algorithm, cfg.SigningKey.Curve)
		if err != nil {
			utils.FatalError(logger, "Failed to generate signing key", err)
		}
		logger.Info("Using ephemeral signing key (will not persist across restarts)")
	}

	logger.Warn("Using signing algorithm", "algorithm", algorithm, "keyID", keyID)

	// Set the issuer URL based on hostname
	issuerURL = fmt.Sprintf("https://%s", cfg.TSNet.Hostname)

	tsLogger := logger.With("scope", "tsnet")
	tsServer = &tsnet.Server{
		Hostname: cfg.TSNet.Hostname,
		Logf: func(format string, args ...any) {
			tsLogger.Info(fmt.Sprintf(format, args...))
		},
	}
	defer func() { _ = tsServer.Close() }()

	// Start listening
	ln, err := tsServer.ListenTLS("tcp", ":443")
	if err != nil {
		utils.FatalError(logger, "Failed to listen", err)
	}
	defer func() { _ = ln.Close() }()

	logger.Info("Starting tsiam server", "hostname", cfg.TSNet.Hostname)

	// Setup HTTP handlers
	mux := http.NewServeMux()
	mux.HandleFunc("GET /token", handleToken)
	mux.HandleFunc("POST /token", handleToken)
	mux.HandleFunc("GET /.well-known/jwks.json", handleJWKS)
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /", handleRoot)

	// Start HTTP server
	err = http.Serve(ln, mux)
	if err != nil {
		utils.FatalError(logger, "Failed to serve", err)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintf(w, "👋")
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	// Get Tailscale connection info from tsnet
	who, err := getTailscaleWhoIs(r)
	if err != nil {
		logger.Error("Failed to get Tailscale identity", "error", err)
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
		Expiration(now.Add(time.Duration(defaultTokenLifetime)*time.Second)).
		Claim("node_id", who.NodeID).
		Claim("node_name", who.NodeName).
		Claim("user_id", who.UserID).
		Build()
	if err != nil {
		logger.Error("Failed to build token", "error", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Sign the token
	signed, err := jwt.Sign(token, jwt.WithKey(algorithm, signingKey))
	if err != nil {
		logger.Error("Failed to sign token", "error", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Return the token
	w.Header().Set("Content-Type", "application/json")
	response := map[string]any{
		"access_token": string(signed),
		"token_type":   "Bearer",
		"expires_in":   defaultTokenLifetime,
	}
	err = writeJSON(w, response)
	if err != nil {
		logger.Error("Failed to write response", "error", err)
	}
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	// Return cached JWKS
	w.Header().Set("Content-Type", "application/json")
	_, err := w.Write(cachedJWKS)
	if err != nil {
		logger.Error("Failed to write JWKS", "error", err)
	}
}

// writeJSON is a helper to write JSON responses
func writeJSON(w http.ResponseWriter, v any) error {
	// Check if it's a jwk.Set - use standard json marshaling
	set, ok := v.(jwk.Set)
	if ok {
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
	ctx, cancel := context.WithTimeout(r.Context(), whoIsTimeout)
	defer cancel()

	whois, err := lc.WhoIs(ctx, remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to query WhoIs: %w", err)
	}

	// Extract node and user information
	var nodeID, nodeName, userID string

	if whois.Node != nil {
		nodeID = strconv.FormatInt(int64(whois.Node.ID), 10)
		nodeName = whois.Node.Name
	}

	if whois.UserProfile != nil {
		userID = strconv.FormatInt(int64(whois.UserProfile.ID), 10)
	}

	return &WhoIsInfo{
		NodeID:   nodeID,
		NodeName: nodeName,
		UserID:   userID,
	}, nil
}
