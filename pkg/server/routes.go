package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/italypaleale/go-kit/httpserver"
	"github.com/italypaleale/go-kit/tsnetserver"
	"github.com/italypaleale/go-kit/utils"
	"tailscale.com/tailcfg"

	"github.com/italypaleale/tsiam/pkg/config"
	"github.com/italypaleale/tsiam/pkg/jwks"
	"github.com/italypaleale/tsiam/pkg/tsnet"
)

const publicCacheControl = "public, max-age=300"

// OIDC Discovery requires authorization_endpoint even though tokens are requested directly from /token
const authorizationEndpoint = "urn:tsiam:programmatic_authorization"

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

	// Prevent caching of token responses (RFC 6749 section 5.1)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Get Tailscale connection info from tsnet
	whois, err := s.whoIs(r)
	if err != nil {
		slog.ErrorContext(r.Context(), "Failed to get Tailscale identity", slog.Any("error", err))
		errNodeIdentity.WriteResponse(w, r)
		return
	}
	if whois.NodeID == "" {
		slog.ErrorContext(r.Context(), "Tailscale identity does not include a node ID", slog.String("nodeName", whois.Name))
		errNodeIdentity.WriteResponse(w, r)
		return
	}

	// Reject nodes from other tailnets (such as shared nodes)
	if whois.Shared || !tsnet.IsSameTailnet(whois.Name, s.hostname()) {
		slog.WarnContext(r.Context(), "Rejected caller from another tailnet",
			slog.String("nodeId", whois.NodeID),
			slog.String("nodeName", whois.Name),
			slog.Bool("shared", whois.Shared),
		)
		errNodeNotInTailnet.WriteResponse(w, r)
		return
	}

	// Reject nodes with expired keys or restricted access
	now := time.Now()
	if whois.KeyExpired || (!whois.KeyExpiry.IsZero() && !now.Before(whois.KeyExpiry)) {
		slog.WarnContext(r.Context(), "Rejected caller whose node key expired",
			slog.String("nodeId", whois.NodeID),
			slog.String("nodeName", whois.Name),
		)
		errNodeKeyExpired.WriteResponse(w, r)
		return
	}
	if whois.Jailed || whois.UnsignedPeerAPIOnly {
		slog.WarnContext(r.Context(), "Rejected restricted caller",
			slog.String("nodeId", whois.NodeID),
			slog.String("nodeName", whois.Name),
			slog.Bool("jailed", whois.Jailed),
			slog.Bool("unsignedPeerApiOnly", whois.UnsignedPeerAPIOnly),
		)
		errNodeRestricted.WriteResponse(w, r)
		return
	}

	whois = sanitizeWhois(whois)

	// Extract and validate audience parameter
	audience, err := extractAudience(r)
	if err != nil {
		slog.WarnContext(r.Context(), "Invalid audience parameter",
			slog.String("nodeId", whois.NodeID),
			slog.String("nodeName", whois.Name),
			slog.Any("error", err),
		)

		var apiErr httpserver.ApiError
		ok := errors.As(err, &apiErr)
		if !ok {
			apiErr = errInternal
		}
		apiErr.WriteResponse(w, r)
		return
	}

	// Check if audience is globally allowed
	if !slices.Contains(cfg.Tokens.AllowedAudiences, audience) {
		slog.WarnContext(r.Context(), "Audience not in global allowlist",
			slog.String("nodeId", whois.NodeID),
			slog.String("nodeName", whois.Name),
			slog.String("requestedAudience", audience),
		)
		errAudienceNotAllowed.WriteResponse(w, r)
		return
	}

	// Check per-caller authorization via Tailscale capabilities
	subjects, permitted := tsnet.MatchAudienceCapability(r.Context(), &whois, audience, cfg.Tokens.AllowEmptyNodeCapability)
	if !permitted {
		slog.WarnContext(r.Context(), "Caller not permitted to request this audience",
			slog.String("nodeId", whois.NodeID),
			slog.String("nodeName", whois.Name),
			slog.String("requestedAudience", audience),
		)
		errAudienceNotPermitted.WriteResponse(w, r)
		return
	}

	subject, err := resolveSubject(cfg, whois, subjects)
	if err != nil {
		slog.WarnContext(r.Context(), "Capability grants that authorize the audience set different subjects",
			slog.String("nodeId", whois.NodeID),
			slog.String("nodeName", whois.Name),
			slog.String("requestedAudience", audience),
			slog.Any("subjects", subjects),
		)
		errSubjectConflict.WriteResponse(w, r)
		return
	}

	// Cap token lifetime at the caller's node key expiry
	lifetime := cfg.Tokens.Lifetime
	if !whois.KeyExpiry.IsZero() {
		lifetime = min(lifetime, whois.KeyExpiry.Sub(now))
	}

	// Create JWT token
	token, err := jwks.NewToken(s.signingKey, jwks.TokenRequest{
		Issuer:    s.tokenIssuer(),
		Audience:  audience,
		Lifetime:  lifetime,
		Subject:   subject,
		Whois:     identityClaimWhois(whois, cfg.Tokens.IncludeCapabilities),
		ClaimName: cfg.Tokens.ClaimName,
	})
	if err != nil {
		slog.ErrorContext(r.Context(), "Failed to generate token", slog.Any("error", err))
		errInternal.WriteResponse(w, r)
		return
	}

	// Log successful token issuance
	slog.InfoContext(r.Context(), "Token issued",
		slog.String("jti", token.JTI),
		slog.String("subject", subject),
		slog.String("nodeId", whois.NodeID),
		slog.String("nodeName", whois.Name),
		slog.String("userLogin", whois.UserLoginName),
		slog.String("audience", audience),
		slog.Int64("expiresIn", token.ExpiresIn),
	)

	// Record the metric
	s.appMetrics.RecordAuth(r.Context(), whois.Name, audience)

	//nolint:tagliatelle
	type postTokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   string `json:"expires_in"`
		ExpiresOn   string `json:"expires_on"`
		NotBefore   string `json:"not_before"`
	}

	// Return the token
	w.Header().Set(httpserver.HeaderContentType, httpserver.ContentTypeJson)
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
	w.Header().Set("Cache-Control", publicCacheControl)
	_, err := w.Write(s.publicJwks)
	if err != nil {
		slog.ErrorContext(r.Context(), "Failed to write JWKS", "error", err)
	}
}

func (s *Server) handleGetOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()

	signingAlgorithm, ok := s.signingKey.Algorithm()
	if !ok {
		slog.ErrorContext(r.Context(), "Signing key does not contain an algorithm")
		errInternal.WriteResponse(w, r)
		return
	}

	// /token is not a standard OAuth 2.0 token endpoint, so token_endpoint is omitted
	//nolint:tagliatelle
	type oidcConfiguration struct {
		Issuer                           string   `json:"issuer"`
		AuthorizationEndpoint            string   `json:"authorization_endpoint"`
		JWKSURI                          string   `json:"jwks_uri"`
		ClaimsSupported                  []string `json:"claims_supported"`
		ResponseTypesSupported           []string `json:"response_types_supported"`
		SubjectTypesSupported            []string `json:"subject_types_supported"`
		IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	}

	endpoint := "https://" + s.hostname()

	w.Header().Set(httpserver.HeaderContentType, httpserver.ContentTypeJson)
	w.Header().Set("Cache-Control", publicCacheControl)
	httpserver.RespondWithJSON(w, r, oidcConfiguration{
		Issuer:                           s.tokenIssuer(),
		AuthorizationEndpoint:            authorizationEndpoint,
		JWKSURI:                          endpoint + "/.well-known/jwks.json",
		ClaimsSupported:                  []string{"aud", "exp", "iat", "iss", "jti", "nbf", "sub", cfg.Tokens.ClaimName},
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{signingAlgorithm.String()},
	})
}

// Clears UserLoginName on tagged nodes, where it contains the tag authorizer rather than a user owner
func sanitizeWhois(whois tsnetserver.TailscaleWhoIs) tsnetserver.TailscaleWhoIs {
	if len(whois.Tags) > 0 {
		whois.UserLoginName = ""
	}
	return whois
}

// Builds the TailscaleWhoIs value for the token's identity claim
func identityClaimWhois(whois tsnetserver.TailscaleWhoIs, includeCapabilities bool) tsnetserver.TailscaleWhoIs {
	// Derive hostname from the MagicDNS name rather than whois.Hostname, which uses the device's OS hostname
	hostname, _, _ := strings.Cut(whois.Name, ".")

	// Copy the object
	res := tsnetserver.TailscaleWhoIs{
		NodeID:        whois.NodeID,
		Name:          whois.Name,
		Hostname:      hostname,
		IP4:           whois.IP4,
		IP6:           whois.IP6,
		UserLoginName: whois.UserLoginName,
		Tags:          whois.Tags,
	}

	capValues, ok := whois.CapMap[tsnet.AudienceCapability]
	if includeCapabilities && ok {
		res.CapMap = tailcfg.PeerCapMap{
			tsnet.AudienceCapability: capValues,
		}
	}

	return res
}

// Returns the value for the JWT `sub` claim based on cfg.Tokens.SubjectClaim
func resolveSubject(cfg *config.Config, whois tsnetserver.TailscaleWhoIs, subjects []string) (string, error) {
	switch cfg.Tokens.SubjectClaim {
	case config.SubjectClaimName:
		return whois.Name, nil
	case config.SubjectClaimCapability:
		switch len(subjects) {
		case 0:
			// Fall back to the node ID
		case 1:
			return subjects[0], nil
		default:
			return "", errSubjectConflict
		}
	}

	return whois.NodeID, nil
}

// extractAudience extracts and validates the audience query parameter
func extractAudience(r *http.Request) (string, error) {
	// Use url.ParseQuery instead of r.URL.Query() so malformed query strings are rejected
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", errInvalidQuery
	}

	if len(query["resource"]) > 1 || len(query["audience"]) > 1 {
		return "", errAudienceDuplicate
	}

	// Get both resource and audience parameters
	resource := strings.TrimSpace(query.Get("resource"))
	audience := strings.TrimSpace(query.Get("audience"))

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

	// Reject control and non-printable characters
	if utils.HasControlChars(res) {
		return "", errAudienceInvalidChars
	}

	return res, nil
}
