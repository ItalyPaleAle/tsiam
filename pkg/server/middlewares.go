package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/httprate"
	"tailscale.com/net/tsaddr"

	"github.com/italypaleale/go-kit/httpserver"
	"github.com/italypaleale/go-kit/tsnetserver"
)

const tsiamHeaderName = "X-Tsiam"

// Indirection over tsnetserver.IsFunneledRequest and tsnetserver.FunnelClientIP so tests can simulate a funneled request without going through the real tsnet ConnContext (the funnel context key is unexported upstream)
var (
	isFunneledRequest = tsnetserver.IsFunneledRequest
	funnelClientIP    = tsnetserver.FunnelClientIP
)

// Maximum number of requests per second accepted from a single client on the public endpoints (`/.well-known/*`), which are reachable from the internet when Funnel is enabled
const publicRateLimitPerSecond = 10

// Rejects with 413 when the request's Content-Length exceeds maxSize, before any handler runs
// httpserver.MiddlewareMaxBodySize wraps r.Body with MaxBytesReader, but that only enforces the cap when the handler actually reads the body
// /token uses query parameters and never reads its body, so an attacker could otherwise force the server to receive arbitrary amounts of TLS-encrypted body data and pay the decrypt + keep-alive-drain cost
// This middleware short-circuits that by trusting Content-Length and closing the connection on requests that promise more than maxSize
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

// Returns a middleware that limits each caller to rpm requests per minute, keyed on the caller's IP address (see rateLimitKey)
func tokenRateLimit(rpm int) httpserver.MiddlewareFunc {
	if rpm <= 0 {
		// Disable the middleware
		return func(next http.HandlerFunc) http.HandlerFunc { return next }
	}

	return rateLimit(rpm, time.Minute)
}

// Returns a middleware that limits each client to limit requests in a sliding window, keyed on the client's IP address (see rateLimitKey)
func rateLimit(limit int, window time.Duration) httpserver.MiddlewareFunc {
	rl := httprate.LimitBy(limit, window, func(r *http.Request) (string, error) {
		return rateLimitKey(r), nil
	})
	return func(next http.HandlerFunc) http.HandlerFunc {
		return rl(next).ServeHTTP
	}
}

// Returns the key used to rate-limit the client that sent the request
// This server is only ever reached directly through tsnet, never behind a reverse proxy or load balancer, so r.RemoteAddr is the caller's real Tailscale IP and is trusted here
// Funnel connections are the exception: their r.RemoteAddr is the Tailscale relay, which would put every public client in the same bucket, so the original client IP from the Funnel connection is used instead
func rateLimitKey(r *http.Request) string {
	// Public clients reached through Funnel have their IPv6 addresses canonicalized to the /64 prefix, so a single client cannot dodge the limit by rotating addresses within its subnet
	ip := funnelClientIP(r)
	if ip != "" {
		return httprate.CanonicalizeIP(ip)
	}

	// Tailnet peers use their full address instead
	// Tailscale assigns each node a single IPv6 address, and many nodes in a tailnet share the same /64 prefix, so masking would put every IPv6 caller in one bucket
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}

	addr = addr.Unmap().WithZone("")

	// IPv6 addresses in the Tailscale 4to6 range map 1:1 to the node's IPv4 address, so a dual-stack node gets a single bucket
	v4, ok := tsaddr.Tailscale6to4(addr)
	if ok {
		return v4.String()
	}

	return addr.String()
}

// Rejects any request that carries a body (Content-Length > 0, or chunked encoding with any bytes available)
// Applied to /token which only consumes query parameters; reading 1 byte catches clients that omit Content-Length (chunked transfer-encoding) and stream a body anyway
// Requests whose body can't be read, such as a malformed chunked body, are rejected too
func requireEmptyBody(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > 0 {
			rejectRequestBody(w, http.StatusRequestEntityTooLarge, "this endpoint does not accept a request body")
			return
		}

		// The server always sets a body on incoming requests, but requests created in code can have none
		if r.Body == nil {
			next(w, r)
			return
		}

		// Probe the body for anything chunked/transfer-encoded that bypassed the Content-Length check
		// We only need to know "is there *any* byte"; the MaxBytesReader middleware caps the actual read at maxBodySize so a malicious chunked stream cannot make this read consume unbounded memory
		// io.ReadFull keeps reading until it gets the byte or an error, since a single Read can return neither
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

// Responds with an error and closes the connection, so the server doesn't read the rest of the body
func rejectRequestBody(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Connection", "close")
	http.Error(w, msg, status)
}

// Returns a middleware that responds with 404 to every Funnel request except GET or HEAD requests for the public endpoints
// It runs before logging, tracing, and routing, so requests from the internet are cheap to reject
// Every Funnel request, including rejected ones, counts against limit
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

// Returns true if the path is reachable over Funnel
func isAllowedFunnelPath(path string) bool {
	switch path {
	case "/.well-known/jwks.json", "/.well-known/openid-configuration":
		return true
	default:
		return false
	}
}

// Returns a middleware that responds with 421 to requests whose Host header isn't tsiam's own hostname
// Clients reach tsiam through its MagicDNS name, so other values only come from clients that make them up, and would end up in logs and traces
// The check is skipped while the hostname is unknown
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

// Returns true if the value of a Host header is hostname, or its short name (the first label)
// The TLS certificate is only valid for the full name, but clients that skip verification can use the short name
// The port is optional, and it must be 443 when present, since that's the only port tsiam listens on
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

// Stops browsers from interpreting responses as a content type other than the declared one
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

// This middleware is used to ensure that requests cannot be made directly by browsers
// It is helpful to prevent CSRF-like attacks, in which a web browser (including one visiting a malicious or compromised website, same or cross-origin) fetches a token from tsiam for the identity of the node the browser is running in
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
	// First, require the presence of the X-Tsiam header
	// While users are encouraged to set the value to 1, we accept anything that's non-empty
	if strings.TrimSpace(r.Header.Get(tsiamHeaderName)) == "" {
		return errors.New("missing header X-Tsiam")
	}

	// These headers are set by browsers and are a very reliable indication that there's a web browser making the request
	// Header.Get returns only the first value, so a request could hide a header behind an empty one; instead, any occurrence of the header is rejected, even with an empty value
	for _, h := range browserHeaders {
		_, ok := r.Header[h]
		if ok {
			return fmt.Errorf("found browser header '%s'", h)
		}
	}

	return nil
}
