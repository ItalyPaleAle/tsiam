package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/italypaleale/go-kit/httpserver"

	"github.com/italypaleale/tsiam/pkg/config"
	"github.com/italypaleale/tsiam/pkg/jwks"
	"github.com/italypaleale/tsiam/pkg/tsnet"
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

	// Extract and validate audience parameter
	audience, apiErr := extractAudience(r)
	if apiErr != nil {
		slog.WarnContext(r.Context(), "Invalid audience parameter",
			slog.String("nodeId", whois.NodeID),
			slog.String("nodeName", whois.Name),
			slog.Any("error", apiErr),
		)
		apiErr.WriteResponse(w, r)
		return
	}

	// Check if audience is globally allowed
	if !slices.Contains(cfg.Tokens.AllowedAudiences, audience) {
		slog.WarnContext(r.Context(), "Audience not in global allowlist",
			slog.String("nodeId", whois.NodeID),
			slog.String("nodeName", whois.Name),
			slog.String("requested_audience", audience),
		)
		errAudienceNotAllowed.WriteResponse(w, r)
		return
	}

	// Check per-caller authorization via Tailscale capabilities
	if !tsnet.IsAudiencePermittedForCaller(&whois, audience, cfg.Tokens.AllowEmptyNodeCapability) {
		slog.WarnContext(r.Context(), "Caller not permitted to request this audience",
			slog.String("nodeId", whois.NodeID),
			slog.String("nodeName", whois.Name),
			slog.String("requested_audience", audience),
		)
		errAudienceNotPermitted.WriteResponse(w, r)
		return
	}

	// Create JWT token
	token, err := jwks.NewToken(s.signingKey, jwks.TokenRequest{
		Issuer:   s.tokenIssuer(),
		Audience: audience,
		Lifetime: cfg.Tokens.Lifetime,
		Subject:  whois,
	})
	if err != nil {
		slog.ErrorContext(r.Context(), "Failed to generate token", slog.Any("error", err))
		errInternal.WriteResponse(w, r)
		return
	}

	// Log successful token issuance
	slog.InfoContext(r.Context(), "Token issued",
		slog.String("jti", token.JTI),
		slog.String("nodeId", whois.NodeID),
		slog.String("nodeName", whois.Name),
		slog.String("userLogin", whois.UserLoginName),
		slog.String("audience", audience),
		slog.Int64("expiresIn", token.ExpiresIn),
	)

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

// extractAudience extracts and validates the audience parameter from the request
func extractAudience(r *http.Request) (string, *httpserver.ApiError) {
	// Get both resource and audience parameters
	resource := strings.TrimSpace(r.URL.Query().Get("resource"))
	audience := strings.TrimSpace(r.URL.Query().Get("audience"))

	var res string
	switch {
	case resource != "" && audience != "" && resource != audience:
		// Both are provided and different
		return "", errAudienceConflict
	case resource != "":
		res = resource
	case audience != "":
		res = audience
	default:
		// At least one must be defined
		return "", errMissingAudience
	}

	// Validate the audience value
	if len(res) > 512 {
		return "", errAudienceTooLong
	}

	return res, nil
}
