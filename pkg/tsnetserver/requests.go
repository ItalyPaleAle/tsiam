package tsnetserver

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"tailscale.com/ipn"
)

type ctxFunnelConn struct{}

// ConnContextFn returns a function that can be passed to http.Server.Conn
func (t *TSNetServer) ConnContextFn() func(ctx context.Context, c net.Conn) context.Context {
	return func(ctx context.Context, nc net.Conn) context.Context {
		// Unwrap the connection if wrapped with TLS
		tlsConn, ok := nc.(*tls.Conn)
		if ok {
			nc = tlsConn.NetConn()
		}

		// Check if the connection is of type *ipn.FunnelConn
		fc, ok := nc.(*ipn.FunnelConn)
		if ok {
			ctx = context.WithValue(ctx, ctxFunnelConn{}, fc)
		}

		return ctx
	}
}

// IsFunneledRequest returns true if the HTTP request is coming over Tailscale Funnel, as opposed to a direct connection.
func IsFunneledRequest(r *http.Request) bool {
	// The value in the context exists only if the request is from a Funnel
	_, ok := r.Context().Value(ctxFunnelConn{}).(*ipn.FunnelConn)
	return ok
}

// FunnelClientIP returns the IP of the client invoking over Tailscale Funnel.
// If the request is not coming through a Tailscale Funnel, the result is empty.
func FunnelClientIP(r *http.Request) string {
	// The value in the context exists only if the request is from a Funnel
	fc, ok := r.Context().Value(ctxFunnelConn{}).(*ipn.FunnelConn)
	if !ok || fc == nil {
		return ""
	}

	addr := fc.Src.Addr()
	if !addr.IsValid() {
		return ""
	}

	return addr.String()
}
