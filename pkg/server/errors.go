package server

import (
	"net/http"

	httpserver "github.com/italypaleale/go-kit/httpserver"
)

var (
	errInternal             = httpserver.NewApiError("internal", http.StatusInternalServerError, "Internal error")
	errNodeIdentity         = httpserver.NewApiError("node_identity", http.StatusForbidden, "Could not determine the Tailscale node's identity")
	errNoBrowser            = httpserver.NewApiError("no_browser", http.StatusForbidden, "To prevent web browsers from accessing protected endpoints, make sure to include the 'X-Tsiam: 1' header in the request. Additionally, headers typically set by web browsers are forbidden.")
	errMissingAudience      = httpserver.NewApiError("missing_audience", http.StatusBadRequest, "Missing required query parameter 'resource'")
	errAudienceConflict     = httpserver.NewApiError("audience_conflict", http.StatusBadRequest, "Conflicting query parameters: 'resource' and 'audience' have different values; only one should be provided")
	errAudienceTooLong      = httpserver.NewApiError("audience_too_long", http.StatusBadRequest, "Invalid audience: value exceeds maximum length of 512 characters")
	errAudienceNotAllowed   = httpserver.NewApiError("audience_not_allowed", http.StatusForbidden, "The requested audience is not allowed by service configuration")
	errAudienceNotPermitted = httpserver.NewApiError("audience_not_permitted", http.StatusForbidden, "The caller does not have permission to request tokens for this audience")
)
