package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/italypaleale/go-kit/httpserver"
	"github.com/italypaleale/tsiam/pkg/config"
	"github.com/italypaleale/tsiam/pkg/jwks"
)

// handleGetHealthz handles the requests to the healthcheck endpoint (`GET /healthz`)
func (s *Server) handleGetHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// handleGetRoot handles the requests to the root route (`GET /`)
func (s *Server) handleGetRoot(w http.ResponseWriter, r *http.Request) {
	// This route can be invoked as catch-all, so we need to make sure we only respond to /
	if r.URL.Path != "/" && r.URL.Path != "" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set(httpserver.HeaderContentType, "text/plain; charset=utf-8")
	_, _ = fmt.Fprintf(w, "👋")
}

func (s *Server) handlePostToken(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()

	// Get Tailscale connection info from tsnet
	whois, err := s.tsnetServer.WhoIs(r)
	if err != nil {
		slog.ErrorContext(r.Context(), "Failed to get Tailscale identity", slog.Any("error", err))
		errNodeIdentity.WriteResponse(w, r)
		return
	}

	// Create JWT token
	token, err := jwks.NewToken(s.signingKey, jwks.TokenRequest{
		Issuer:   s.tokenIssuer(),
		Audience: "", // TODO
		Lifetime: cfg.Tokens.Lifetime,
		Subject:  whois,
	})
	if err != nil {
		slog.ErrorContext(r.Context(), "Failed to generate token", slog.Any("error", err))
		errInternal.WriteResponse(w, r)
		return
	}

	//nolint:tagliatelle
	type postTokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   string `json:"expires_in"`
		ExpiresOn   string `json:"expires_on"`
		NotBefore   string `json:"not_before"`
	}

	// Return the token
	httpserver.RespondWithJSON(w, r, postTokenResponse{
		AccessToken: token.Token,
		TokenType:   "Bearer",
		ExpiresIn:   strconv.FormatInt(token.ExpiresIn, 10),
		ExpiresOn:   strconv.FormatInt(token.ExpiresOn, 10),
		NotBefore:   strconv.FormatInt(token.NotBefore, 10),
	})
}

func (s *Server) handleGetJWKS(w http.ResponseWriter, r *http.Request) {
	// Return cached JWKS
	w.Header().Set(httpserver.HeaderContentType, httpserver.ContentTypeJson)
	_, err := w.Write(s.publicJwks)
	if err != nil {
		slog.ErrorContext(r.Context(), "Failed to write JWKS", "error", err)
	}
}

func (s *Server) handleGetOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	//nolint:tagliatelle
	type oidcConfiguration struct {
		Issuer        string `json:"issuer"`
		TokenEndpoint string `json:"token_endpoint"`
		JWKSURI       string `json:"jwks_uri"`
	}

	// For the endpoints, we get the hostname used in the request
	// This enables the use of funnel too
	// However, we require the endpoint to use HTTPS; if using plain HTTP, we return the default hostname of the tsnet server
	var endpoint string
	if r.URL.Scheme == "https" {
		endpoint = "https://" + r.URL.Host
	} else {
		// If the request came with a non-HTTPS endpoint, use the default hostname, with HTTPS
		endpoint = "https://" + s.tsnetServer.Hostname()
	}

	w.Header().Set(httpserver.HeaderContentType, httpserver.ContentTypeJson)
	httpserver.RespondWithJSON(w, r, oidcConfiguration{
		Issuer:        s.tokenIssuer(),
		TokenEndpoint: endpoint + "/token",
		JWKSURI:       endpoint + "/.well-known/jwks.json",
	})
}
