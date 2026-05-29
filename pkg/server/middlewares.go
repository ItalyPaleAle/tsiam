package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/httprate"

	"github.com/italypaleale/go-kit/httpserver"
	"github.com/italypaleale/go-kit/tsnetserver"
)

const tsiamHeaderName = "X-Tsiam"

// Indirection over tsnetserver.IsFunneledRequest so tests can simulate a funneled request without going through the real tsnet ConnContext (the funnel context key is unexported upstream)
var isFunneledRequest = tsnetserver.IsFunneledRequest

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

// Returns a middleware that limits each caller to rpm requests per minute, keyed on the caller's IP address (from r.RemoteAddr)
// For tsnet-served requests the RemoteAddr is the caller's Tailscale IP, so each tailnet node is throttled independently
func tokenRateLimit(rpm int) httpserver.MiddlewareFunc {
	if rpm <= 0 {
		// Disable the middleware
		return func(next http.HandlerFunc) http.HandlerFunc { return next }
	}

	rl := httprate.LimitByIP(rpm, time.Minute)
	return func(next http.HandlerFunc) http.HandlerFunc {
		return rl(next).ServeHTTP
	}
}

// Rejects any request that carries a body (Content-Length > 0, or chunked encoding with any bytes available)
// Applied to /token which only consumes query parameters; reading 1 byte catches clients that omit Content-Length (chunked transfer-encoding) and stream a body anyway
func requireEmptyBody(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > 0 {
			w.Header().Set("Connection", "close")
			http.Error(w, "this endpoint does not accept a request body", http.StatusRequestEntityTooLarge)
			return
		}
		// Probe the body for anything chunked/transfer-encoded that bypassed the Content-Length check
		// We only need to know "is there *any* byte"; the MaxBytesReader middleware caps the actual read at maxBodySize so a malicious chunked stream cannot make this read consume unbounded memory
		buf := make([]byte, 1)
		n, _ := r.Body.Read(buf)
		if n > 0 {
			w.Header().Set("Connection", "close")
			http.Error(w, "this endpoint does not accept a request body", http.StatusRequestEntityTooLarge)
			return
		}
		next(w, r)
	}
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
	if r.Header.Get(tsiamHeaderName) == "" {
		return errors.New("missing header X-Tsiam")
	}

	// These headers are set by browsers and are a very reliable indication that there's a web browser making the request
	for _, h := range browserHeaders {
		if r.Header.Get(h) != "" {
			return fmt.Errorf("found browser header '%s'", h)
		}
	}

	return nil
}
