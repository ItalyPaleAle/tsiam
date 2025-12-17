package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	slogkit "github.com/italypaleale/go-kit/slog"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"tailscale.com/tsnet"

	"github.com/italypaleale/tsiam/pkg/config"
	"github.com/italypaleale/tsiam/pkg/jwks"
	"github.com/italypaleale/tsiam/pkg/keystorage"
)

const (
	// Default token lifetime in seconds
	defaultTokenLifetime = 3600
	// Timeout for WhoIs API calls
	whoIsTimeout = 5 * time.Second
)

var (
	// Keys and config
	signingKey jwk.Key
	keyID      string
	tsServer   *tsnet.Server
	issuerURL  string
	algorithm  jwa.SignatureAlgorithm
	cachedJWKS []byte // Cached JSON-encoded JWKS
	keyStorage keystorage.KeyStorage
	logger     *slog.Logger
)

// WhoIsInfo contains information about the Tailscale node making the request
type WhoIsInfo struct {
	NodeID   string
	NodeName string
	UserID   string
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
		slogkit.FatalError(logger, "Failed to load config", err)
	}
	cfg := config.Get()

	ctx := context.Background()

	// Initialize key storage if path is provided
	if cfg.SigningKey.StoragePath != "" {
		keyStorage, err = keystorage.NewFileKeyStorage(cfg.SigningKey.StoragePath)
		if err != nil {
			slogkit.FatalError(logger, "Failed to initialize key storage", err)
		}

		// Try to load existing key
		loadedKey, err := keyStorage.Load(ctx)
		if err != nil {
			slogkit.FatalError(logger, "Failed to load key from storage", err)
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
					slogkit.FatalError(logger, "Loaded key has invalid algorithm type", errors.New("invalid algorithm type"))
				}
			}
			kid, ok := signingKey.KeyID()
			if ok {
				keyID = kid
			}

			// Cache JWKS
			cachedJWKS, err = jwks.GetPublicJWKSAsJSON(signingKey)
			if err != nil {
				slogkit.FatalError(logger, "Failed to cache JWKS", err)
			}
		} else {
			// Generate new key
			signingKey, err = jwks.NewSigningKey(cfg.SigningKey.Algorithm, cfg.SigningKey.Curve)
			if err != nil {
				slogkit.FatalError(logger, "Failed to generate signing key", err)
			}

			// Persist the new key
			err = keyStorage.Store(ctx, signingKey)
			if err != nil {
				slogkit.FatalError(logger, "Failed to store key", err)
			}
			logger.Info("Generated and stored new signing key", "path", cfg.SigningKey.StoragePath)
		}
	} else {
		// Generate ephemeral key
		signingKey, err = jwks.NewSigningKey(cfg.SigningKey.Algorithm, cfg.SigningKey.Curve)
		if err != nil {
			slogkit.FatalError(logger, "Failed to generate signing key", err)
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
		slogkit.FatalError(logger, "Failed to listen", err)
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
		slogkit.FatalError(logger, "Failed to serve", err)
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
