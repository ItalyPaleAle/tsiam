package server

import (
	"net/http"

	httpserver "github.com/italypaleale/go-kit/httpserver"
)

var (
	errInternal     = httpserver.NewApiError("internal", http.StatusInternalServerError, "Internal error")
	errNodeIdentity = httpserver.NewApiError("node_identity", http.StatusForbidden, "Could not determine the Tailscale node's identity")
)
