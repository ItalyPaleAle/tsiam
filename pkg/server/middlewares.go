package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/httprate"
	sloghttp "github.com/samber/slog-http"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
	"tailscale.com/net/tsaddr"

	"github.com/italypaleale/go-kit/httpserver"
	"github.com/italypaleale/go-kit/tsnetserver"
)

const tsiamHeaderName = "X-Tsiam"

// Overridden in tests
var (
	isFunneledRequest = tsnetserver.IsFunneledRequest
	funnelClientIP    = tsnetserver.FunnelClientIP
)

// Rate limit (requests/sec) per client for public endpoints
const publicRateLimitPerSecond = 10

// Rejects requests whose Content-Length exceeds maxSize before reading the body
func rejectOversizedRequest(maxSize int64) httpserver.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxSize {
				w.Header().Set("Connection", "close")
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Rate-limits requests per minute per client IP
func tokenRateLimit(rpm int) httpserver.MiddlewareFunc {
	if rpm <= 0 {
		// Disable the middleware
		return func(next http.HandlerFunc) http.HandlerFunc { return next }
	}

	return rateLimit(rpm, time.Minute)
}

func rateLimit(limit int, window time.Duration) httpserver.MiddlewareFunc {
	rl := httprate.LimitBy(limit, window, func(r *http.Request) (string, error) {
		return rateLimitKey(r), nil
	})
	return func(next http.HandlerFunc) http.HandlerFunc {
		return rl(next).ServeHTTP
	}
}

// Returns the client IP key for rate limiting
func rateLimitKey(r *http.Request) string {
	// For Funnel requests, use the original client IP (canonicalizing IPv6 to /64) instead of the Tailscale relay address
	ip := funnelClientIP(r)
	if ip != "" {
		return httprate.CanonicalizeIP(ip)
	}

	// For Tailnet peers, use the full node IP because nodes in a tailnet share the same IPv6 /64 prefix
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}

	addr = addr.Unmap().WithZone("")

	// Map Tailscale 4to6 addresses back to the node's IPv4 address
	v4, ok := tsaddr.Tailscale6to4(addr)
	if ok {
		return v4.String()
	}

	return addr.String()
}

// Rejects requests that include a body
func requireEmptyBody(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > 0 {
			rejectRequestBody(w, http.StatusRequestEntityTooLarge, "this endpoint does not accept a request body")
			return
		}

		if r.Body == nil {
			next(w, r)
			return
		}

		// Read 1 byte to detect chunked bodies when Content-Length is not set
		buf := make([]byte, 1)
		_, err := io.ReadFull(r.Body, buf)
		var maxBytesErr *http.MaxBytesError
		switch {
		case errors.Is(err, io.EOF):
			// The body is empty
			next(w, r)
		case err == nil, errors.As(err, &maxBytesErr):
			rejectRequestBody(w, http.StatusRequestEntityTooLarge, "this endpoint does not accept a request body")
		default:
			rejectRequestBody(w, http.StatusBadRequest, "failed to read the request body")
		}
	}
}

func rejectRequestBody(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Connection", "close")
	http.Error(w, msg, status)
}

// Rate-limits Funnel requests and allows only GET/HEAD on public endpoints
func requireFunnelAllowed(limit httpserver.MiddlewareFunc) httpserver.Middleware {
	return func(next http.Handler) http.Handler {
		limited := limit(func(w http.ResponseWriter, r *http.Request) {
			allowed := (r.Method == http.MethodGet || r.Method == http.MethodHead) && isAllowedFunnelPath(r.URL.Path)
			if !allowed {
				http.NotFound(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isFunneledRequest(r) {
				next.ServeHTTP(w, r)
				return
			}

			limited(w, r)
		})
	}
}

func isAllowedFunnelPath(path string) bool {
	switch path {
	case "/.well-known/jwks.json", "/.well-known/openid-configuration":
		return true
	default:
		return false
	}
}

// Rejects requests whose Host header does not match tsiam's hostname
func requireKnownHost(hostname func() string) httpserver.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expected := hostname()
			if expected != "" && !isKnownHost(r.Host, expected) {
				errMisdirectedRequest.WriteResponse(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Checks if host matches hostname or its short name (with optional port 443)
func isKnownHost(host string, hostname string) bool {
	h, port, err := net.SplitHostPort(host)
	if err == nil {
		if port != "443" {
			return false
		}
		host = h
	}

	host = strings.TrimSuffix(host, ".")
	hostname = strings.TrimSuffix(hostname, ".")
	shortName, _, _ := strings.Cut(hostname, ".")
	return strings.EqualFold(host, hostname) || strings.EqualFold(host, shortName)
}

func setNoSniff(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func requireNotFunneledRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isFunneledRequest(r) {
			// If the request is funneled, return a 404
			http.NotFound(w, r)
			return
		}

		next(w, r)
	}
}

// Rejects requests from web browsers to prevent CSRF attacks
func requireNoBrowser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := validateNoBrowser(r)
		if err != nil {
			errNoBrowser.Clone(httpserver.WithInnerError(err)).WriteResponse(w, r)
			return
		}

		next(w, r)
	}
}

var browserHeaders = []string{
	"Origin",
	"Sec-Fetch-Site",
	"Sec-Fetch-Mode",
	"Sec-Fetch-Dest",
	"Sec-Fetch-User",
}

func validateNoBrowser(r *http.Request) error {
	// Require a non-empty X-Tsiam header
	if strings.TrimSpace(r.Header.Get(tsiamHeaderName)) == "" {
		return errors.New("missing header X-Tsiam")
	}

	// Reject requests that include browser headers (even if empty)
	for _, h := range browserHeaders {
		_, ok := r.Header[h]
		if ok {
			return fmt.Errorf("found browser header '%s'", h)
		}
	}

	return nil
}

// Strips X-Forwarded-For so otelhttp uses the tsnet connection address
func removeForwardedFor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("X-Forwarded-For")
		next.ServeHTTP(w, r)
	})
}

// Sets the original Funnel client IP on the request span and log
func annotateFunnelClient(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := funnelClientIP(r)
		if ip != "" {
			trace.SpanFromContext(r.Context()).SetAttributes(semconv.ClientAddress(ip))
			sloghttp.AddCustomAttributes(r, slog.String("funnelClientIp", ip))
		}

		next.ServeHTTP(w, r)
	})
}
