package server

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/italypaleale/go-kit/httpserver"
	"github.com/italypaleale/go-kit/tsnetserver"
)

const tsiamHeaderName = "X-Tsiam"

func requireNotFunneledRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if tsnetserver.IsFunneledRequest(r) {
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
