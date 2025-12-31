package server

import (
	"net/http"

	httpserver "github.com/italypaleale/go-kit/httpserver"
)

var (
	errInternal     = httpserver.NewApiError("internal", http.StatusInternalServerError, "Internal error")
	errNodeIdentity = httpserver.NewApiError("node_identity", http.StatusForbidden, "Could not determine the Tailscale node's identity")
	errNoBrowser    = httpserver.NewApiError("no_browser", http.StatusForbidden, "To prevent web browsers from accessing protected endpoints, make sure to include the 'X-Tsiam: 1' header in the request. Additionally, headers typically set by web browsers are forbidden.")
)
