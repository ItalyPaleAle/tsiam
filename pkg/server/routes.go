package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/italypaleale/go-kit/httpserver"
	"github.com/italypaleale/tsiam/pkg/jwks"
	sloghttp "github.com/samber/slog-http"
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

	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintf(w, "👋")
}

func (s *Server) handlePostToken(w http.ResponseWriter, r *http.Request) {
	// Get Tailscale connection info from tsnet
	whos, err := s.tsnetServer.WhoIs(r)
	if err != nil {
		slog.ErrorContext(r.Context(), "Failed to get Tailscale identity", slog.Any("error", err))
		errNodeIdentity.WriteResponse(w, r)
		return
	}

	// Create JWT token
	token, err := jwks.NewToken(jwks.TokenRequest{
		Issuer:   "",
		Audience: "",
		Lifetime: 0,
		Key:      nil,
		Subject:  whos,
	})
	if err != nil {
		slog.ErrorContext(r.Context(), "Failed to generate token", slog.Any("error", err))
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Return the token
	response := map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   defaultTokenLifetime,
		"expires_on":   "",
		"not_before":   "",
	}
	httpserver.RespondWithJSON(w, r, response)
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	// Return cached JWKS
	w.Header().Set("Content-Type", "application/json")
	_, err := w.Write(cachedJWKS)
	if err != nil {
		slog.ErrorContext(r.Context(), "Failed to write JWKS", "error", err)
	}
}

// handleGetCertificate handles certificate retrieval/creation requests
func (s *Server) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req CertificateRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		errInvalidBody.WriteResponse(w, r)
		return
	}

	if req.Domain == "" {
		errMissingBodyParam.
			Clone(httpserver.WithMetadata(map[string]string{"name": "domain"})).
			WriteResponse(w, r)
		return
	}

	sloghttp.AddCustomAttributes(r, slog.String("domain", req.Domain))

	// Check if the user can request certificates for the domain
	if !auth.DomainAllowed(r.Context(), req.Domain) {
		slog.WarnContext(r.Context(), "User is not authorized to perform operations on the requested domain")
		errDomainNotAllowed.WriteResponse(w, r)
		return
	}

	// Try to get or obtain certificate
	cert, cached, err := s.manager.ObtainCertificate(r.Context(), req.Domain)
	if err != nil {
		slog.ErrorContext(r.Context(), "Failed to obtain certificate", "error", err)
		errInternal.WriteResponse(w, r)
		return
	}

	// Prepare response
	resp := CertificateResponse{
		Domain:      cert.Domain,
		Certificate: string(cert.Certificate),
		PrivateKey:  string(cert.PrivateKey),
		IssuerCert:  string(cert.IssuerCert),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		Cached:      cached,
	}

	if s.appMetrics != nil {
		s.appMetrics.RecordCertRequest(resp.Domain, resp.Cached)
	}

	w.Header().Set(httpserver.HeaderContentType, httpserver.ContentTypeJson)
	httpserver.RespondWithJSON(w, r, resp)
}
