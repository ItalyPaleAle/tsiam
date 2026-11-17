package server

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/italypaleale/go-kit/tsnetserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"
	"tailscale.com/net/tsaddr"

	"github.com/italypaleale/tsiam/pkg/config"
)

func TestTokenRateLimit(t *testing.T) {
	t.Run("Zero or negative rpm disables the limiter", func(t *testing.T) {
		mw := tokenRateLimit(0)
		called := 0
		handler := mw(func(w http.ResponseWriter, r *http.Request) {
			called++
			w.WriteHeader(http.StatusOK)
		})
		// Hammer many requests from the same IP; none should be rejected
		for range 50 {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", nil)
			req.RemoteAddr = "100.64.0.1:1234"
			rr := httptest.NewRecorder()
			handler(rr, req)
			require.Equal(t, http.StatusOK, rr.Code)
		}
		assert.Equal(t, 50, called)
	})

	t.Run("Allows up to the configured limit then 429s", func(t *testing.T) {
		const rpm = 3
		mw := tokenRateLimit(rpm)
		called := 0
		handler := mw(func(w http.ResponseWriter, r *http.Request) {
			called++
			w.WriteHeader(http.StatusOK)
		})

		// First rpm requests from the same IP pass
		for range rpm {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", nil)
			req.RemoteAddr = "100.64.0.2:1234"
			rr := httptest.NewRecorder()
			handler(rr, req)
			require.Equal(t, http.StatusOK, rr.Code)
		}
		// The next request from the same IP is throttled
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", nil)
		req.RemoteAddr = "100.64.0.2:1234"
		rr := httptest.NewRecorder()
		handler(rr, req)
		assert.Equal(t, http.StatusTooManyRequests, rr.Code)
		assert.Equal(t, rpm, called, "throttled request must not reach the wrapped handler")
	})

	t.Run("Buckets are per IP", func(t *testing.T) {
		const rpm = 1
		mw := tokenRateLimit(rpm)
		handler := mw(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		mk := func(remote string) *httptest.ResponseRecorder {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", nil)
			req.RemoteAddr = remote
			rr := httptest.NewRecorder()
			handler(rr, req)
			return rr
		}

		// IP A: first request OK, second 429
		assert.Equal(t, http.StatusOK, mk("100.64.0.10:1111").Code)
		assert.Equal(t, http.StatusTooManyRequests, mk("100.64.0.10:2222").Code)
		// IP B is unaffected by A's throttling
		assert.Equal(t, http.StatusOK, mk("100.64.0.11:1111").Code)
	})
}

func TestRateLimitKey(t *testing.T) {
	// Helper that swaps the package-level seam for the duration of the subtest
	withFunnelClientIP := func(t *testing.T, ip string) {
		t.Helper()
		prev := funnelClientIP
		funnelClientIP = func(*http.Request) string { return ip }
		t.Cleanup(func() { funnelClientIP = prev })
	}

	keyFor := func(t *testing.T, remoteAddr string) string {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		req.RemoteAddr = remoteAddr
		return rateLimitKey(req)
	}

	t.Run("Direct request uses the RemoteAddr IP", func(t *testing.T) {
		withFunnelClientIP(t, "")
		assert.Equal(t, "100.64.0.1", keyFor(t, "100.64.0.1:1234"))
	})

	t.Run("RemoteAddr without a port is used as-is", func(t *testing.T) {
		withFunnelClientIP(t, "")
		assert.Equal(t, "100.64.0.1", keyFor(t, "100.64.0.1"))
	})

	t.Run("Direct IPv6 request uses the full address", func(t *testing.T) {
		// Many Tailscale nodes in a tailnet share the same /64 prefix, so each one needs its own bucket
		withFunnelClientIP(t, "")
		assert.Equal(t, "fd7a:115c:a1e0::1", keyFor(t, "[fd7a:115c:a1e0::1]:1234"))
		assert.NotEqual(t, keyFor(t, "[fd7a:115c:a1e0::1]:1234"), keyFor(t, "[fd7a:115c:a1e0::2]:1234"))
	})

	t.Run("Direct IPv6 request in the Tailscale 4to6 range uses the node's IPv4 address", func(t *testing.T) {
		withFunnelClientIP(t, "")
		ip6 := tsaddr.Tailscale4To6(netip.MustParseAddr("100.64.0.1"))
		assert.Equal(t, "100.64.0.1", keyFor(t, netip.AddrPortFrom(ip6, 1234).String()))

		other := tsaddr.Tailscale4To6(netip.MustParseAddr("100.64.0.2"))
		assert.NotEqual(t, keyFor(t, netip.AddrPortFrom(ip6, 1234).String()), keyFor(t, netip.AddrPortFrom(other, 1234).String()))
	})

	t.Run("Funneled request uses the original client IP rather than the relay", func(t *testing.T) {
		withFunnelClientIP(t, "203.0.113.7")
		assert.Equal(t, "203.0.113.7", keyFor(t, "100.100.100.100:443"))
	})

	t.Run("Funneled IPv6 addresses are canonicalized to their /64 prefix", func(t *testing.T) {
		withFunnelClientIP(t, "2001:db8:1:2::1")
		a := keyFor(t, "100.100.100.100:443")
		withFunnelClientIP(t, "2001:db8:1:2::ffff")
		b := keyFor(t, "100.100.100.100:443")
		withFunnelClientIP(t, "2001:db8:1:3::1")
		c := keyFor(t, "100.100.100.100:443")

		assert.Equal(t, a, b)
		assert.NotEqual(t, a, c)
	})
}

// Exercises the rate limiters through the full handler chain, to catch regressions in the order middlewares are applied
func TestRouteRateLimits(t *testing.T) {
	newServer := func(t *testing.T) *Server {
		t.Helper()
		s, restore := newTestServer(t, func(c *config.Config) {
			c.Tokens.RateLimitPerMinute = 3
		}, func(*http.Request) (tsnetserver.TailscaleWhoIs, error) {
			return defaultWhois(), nil
		})
		t.Cleanup(restore)
		s.initAppServer()
		return s
	}

	serve := func(t *testing.T, s *Server, method string, path string, remoteAddr string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), method, "https://"+testHostname+path, nil)
		req.RemoteAddr = remoteAddr
		rr := httptest.NewRecorder()
		s.handler.ServeHTTP(rr, req)
		return rr
	}
	do := func(t *testing.T, s *Server, method string, path string, remoteAddr string) int {
		t.Helper()
		return serve(t, s, method, path, remoteAddr).Code
	}

	t.Run("Token requests rejected by other middlewares count against the limit", func(t *testing.T) {
		s := newServer(t)

		// Missing X-Tsiam header, so requireNoBrowser rejects these requests
		for range 3 {
			require.Equal(t, http.StatusForbidden, do(t, s, http.MethodPost, "/token?resource="+testAudience, "100.64.0.1:1234"))
		}
		assert.Equal(t, http.StatusTooManyRequests, do(t, s, http.MethodPost, "/token?resource="+testAudience, "100.64.0.1:1234"))
	})

	t.Run("Public endpoints share a per-client limit", func(t *testing.T) {
		s := newServer(t)

		for i := range publicRateLimitPerSecond {
			path := "/.well-known/jwks.json"
			if i%2 == 1 {
				path = "/.well-known/openid-configuration"
			}
			require.Equal(t, http.StatusOK, do(t, s, http.MethodGet, path, "100.64.0.1:1234"), "request %d of the burst should be allowed", i+1)
		}
		rr := serve(t, s, http.MethodGet, "/.well-known/jwks.json", "100.64.0.1:1234")
		assert.Equal(t, http.StatusTooManyRequests, rr.Code)
		// httprate sets Retry-After to the window length, so this also checks that the window is one second
		assert.Equal(t, "1", rr.Header().Get("Retry-After"))
		assert.Equal(t, http.StatusTooManyRequests, do(t, s, http.MethodGet, "/.well-known/openid-configuration", "100.64.0.1:1234"))

		// Another client is unaffected
		assert.Equal(t, http.StatusOK, do(t, s, http.MethodGet, "/.well-known/jwks.json", "100.64.0.2:1234"))
	})
}

// Exercises the Funnel gate through the full handler chain
func TestRequireFunnelAllowed(t *testing.T) {
	newServer := func(t *testing.T) *Server {
		t.Helper()
		s, restore := newTestServer(t, func(c *config.Config) {
			c.Tokens.RateLimitPerMinute = 3
		}, func(*http.Request) (tsnetserver.TailscaleWhoIs, error) {
			return defaultWhois(), nil
		})
		t.Cleanup(restore)
		s.initAppServer()
		return s
	}

	withFunnel := func(t *testing.T, clientIP string) {
		t.Helper()
		prevFunneled, prevIP := isFunneledRequest, funnelClientIP
		isFunneledRequest = func(*http.Request) bool { return true }
		funnelClientIP = func(*http.Request) string { return clientIP }
		t.Cleanup(func() { isFunneledRequest, funnelClientIP = prevFunneled, prevIP })
	}

	serve := func(t *testing.T, s *Server, method string, path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), method, "https://"+testHostname+path, nil)
		req.Header.Set(tsiamHeaderName, "1")
		rr := httptest.NewRecorder()
		s.handler.ServeHTTP(rr, req)
		return rr
	}

	t.Run("Public endpoints are reachable", func(t *testing.T) {
		s := newServer(t)
		withFunnel(t, "203.0.113.1")

		for _, method := range []string{http.MethodGet, http.MethodHead} {
			for _, path := range []string{"/.well-known/jwks.json", "/.well-known/openid-configuration"} {
				assert.Equal(t, http.StatusOK, serve(t, s, method, path).Code, "%s %s", method, path)
			}
		}
	})

	t.Run("Everything else returns 404", func(t *testing.T) {
		s := newServer(t)
		withFunnel(t, "203.0.113.2")

		// Without the gate, the mux would respond to some of these with 405 and an Allow header, or with a redirect
		requests := []struct{ method, path string }{
			{http.MethodPost, "/token"},
			{http.MethodPut, "/token"},
			{http.MethodOptions, "/token"},
			{http.MethodGet, "/token"},
			{http.MethodPost, "/.well-known/jwks.json"},
			{http.MethodGet, "/healthz"},
			{http.MethodDelete, "/healthz"},
			{http.MethodGet, "/"},
			{http.MethodGet, "//.well-known/jwks.json"},
		}
		for _, req := range requests {
			rr := serve(t, s, req.method, req.path)
			assert.Equal(t, http.StatusNotFound, rr.Code, "%s %s", req.method, req.path)
			assert.Empty(t, rr.Header().Get("Allow"), "%s %s", req.method, req.path)
			assert.Empty(t, rr.Header().Get("Location"), "%s %s", req.method, req.path)
			// The token rate limiter would set this header to 3, overwriting the gate's value
			assert.Equal(t, strconv.Itoa(publicRateLimitPerSecond), rr.Header().Get("X-Ratelimit-Limit"), "%s %s should not reach the token rate limiter", req.method, req.path)
		}
	})

	t.Run("Rejected requests count against the public limit", func(t *testing.T) {
		s := newServer(t)
		withFunnel(t, "203.0.113.3")

		for i := range publicRateLimitPerSecond {
			require.Equal(t, http.StatusNotFound, serve(t, s, http.MethodPut, "/token").Code, "request %d of the burst should be allowed", i+1)
		}
		assert.Equal(t, http.StatusTooManyRequests, serve(t, s, http.MethodGet, "/.well-known/jwks.json").Code)

		// Another client is unaffected
		withFunnel(t, "203.0.113.4")
		assert.Equal(t, http.StatusOK, serve(t, s, http.MethodGet, "/.well-known/jwks.json").Code)
	})

	t.Run("Allowed requests are counted once", func(t *testing.T) {
		s := newServer(t)
		withFunnel(t, "203.0.113.5")

		// The gate and the route have separate limiters, so each allowed request is counted once and the client gets the full limit
		for i := range publicRateLimitPerSecond {
			require.Equal(t, http.StatusOK, serve(t, s, http.MethodGet, "/.well-known/jwks.json").Code, "request %d of the burst should be allowed", i+1)
		}
		assert.Equal(t, http.StatusTooManyRequests, serve(t, s, http.MethodGet, "/.well-known/jwks.json").Code)
	})

	t.Run("Tailnet requests are not affected", func(t *testing.T) {
		s := newServer(t)

		// The mux's own 405 response still applies to tailnet requests
		assert.Equal(t, http.StatusMethodNotAllowed, serve(t, s, http.MethodPut, "/token").Code)
		assert.Equal(t, http.StatusNoContent, serve(t, s, http.MethodGet, "/healthz").Code)
	})
}

func TestPanicRecovery(t *testing.T) {
	newServer := func(t *testing.T, whoIs func(*http.Request) (tsnetserver.TailscaleWhoIs, error)) *Server {
		t.Helper()
		s, restore := newTestServer(t, nil, whoIs)
		t.Cleanup(restore)
		s.initAppServer()
		return s
	}

	t.Run("Panic in a handler", func(t *testing.T) {
		s := newServer(t, func(*http.Request) (tsnetserver.TailscaleWhoIs, error) {
			panic("boom")
		})

		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+testHostname+"/token?resource="+testAudience, nil)
		req.Header.Set(tsiamHeaderName, "1")
		rr := httptest.NewRecorder()
		s.handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})

	t.Run("Panic in an outer middleware", func(t *testing.T) {
		s := newServer(t, nil)

		// The Funnel gate runs outside of logging and tracing, so only the outermost Recovery can catch this
		prev := isFunneledRequest
		isFunneledRequest = func(*http.Request) bool { panic("boom") }
		t.Cleanup(func() { isFunneledRequest = prev })

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+testHostname+"/.well-known/jwks.json", nil)
		rr := httptest.NewRecorder()
		s.handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestIsKnownHost(t *testing.T) {
	tests := []struct {
		host     string
		expected bool
	}{
		{host: testHostname, expected: true},
		{host: testHostname + ":443", expected: true},
		{host: testHostname + ".", expected: true},
		{host: testHostname + ".:443", expected: true},
		{host: strings.ToUpper(testHostname), expected: true},
		{host: "tsiam", expected: true},
		{host: "TSIAM:443", expected: true},
		{host: testHostname + ":8443", expected: false},
		{host: "tsiam.other-tailnet.ts.net", expected: false},
		{host: "test-tailnet", expected: false},
		{host: "example.com", expected: false},
		{host: "100.64.0.10", expected: false},
		{host: "[fd7a:115c:a1e0::1]:443", expected: false},
		{host: "", expected: false},
	}

	for _, test := range tests {
		assert.Equal(t, test.expected, isKnownHost(test.host, testHostname), "host %q", test.host)
	}
}

// Exercises the Host check and the nosniff header through the full handler chain
func TestRequireKnownHost(t *testing.T) {
	serve := func(t *testing.T, s *Server, host string, path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+testHostname+path, nil)
		req.Host = host
		rr := httptest.NewRecorder()
		s.handler.ServeHTTP(rr, req)
		return rr
	}

	s, restore := newTestServer(t, nil, nil)
	t.Cleanup(restore)
	s.initAppServer()

	t.Run("Own hostname is allowed", func(t *testing.T) {
		rr := serve(t, s, testHostname, "/healthz")
		assert.Equal(t, http.StatusNoContent, rr.Code)
		assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))

		assert.Equal(t, http.StatusNoContent, serve(t, s, "tsiam", "/healthz").Code)

		rr = serve(t, s, testHostname, "/not-found")
		assert.Equal(t, http.StatusNotFound, rr.Code)
		assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	})

	t.Run("Other hosts are rejected", func(t *testing.T) {
		for _, host := range []string{"example.com", testHostname + ":8443", "100.64.0.10"} {
			rr := serve(t, s, host, "/healthz")
			assert.Equal(t, http.StatusMisdirectedRequest, rr.Code, "host %q", host)
			assert.Contains(t, rr.Body.String(), "misdirected_request", "host %q", host)
			assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"), "host %q", host)
		}
	})

	t.Run("Check is skipped when the hostname is unknown", func(t *testing.T) {
		s, restore := newTestServer(t, nil, nil)
		t.Cleanup(restore)
		s.hostname = func() string { return "" }
		s.initAppServer()

		assert.Equal(t, http.StatusNoContent, serve(t, s, "example.com", "/healthz").Code)
	})
}

// Different spellings of the Host header must not create new metric series
func TestOtelServerName(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(prev) })

	s, restore := newTestServer(t, nil, nil)
	t.Cleanup(restore)
	s.initAppServer()

	// All of these pass requireKnownHost
	for _, host := range []string{testHostname, strings.ToUpper(testHostname), testHostname + ".", testHostname + ":443", "tsiam"} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+testHostname+"/healthz", nil)
		req.Host = host
		rr := httptest.NewRecorder()
		s.handler.ServeHTTP(rr, req)
		require.Equal(t, http.StatusNoContent, rr.Code, "host %q", host)
	}

	var rm metricdata.ResourceMetrics
	err := reader.Collect(t.Context(), &rm)
	require.NoError(t, err)

	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "http.server.request.duration" {
				continue
			}
			found = true

			hist, ok := m.Data.(metricdata.Histogram[float64])
			require.True(t, ok)
			require.Len(t, hist.DataPoints, 1, "all requests should be recorded in the same series")
			addr, ok := hist.DataPoints[0].Attributes.Value("server.address")
			require.True(t, ok)
			assert.Equal(t, testHostname, addr.AsString())
		}
	}
	require.True(t, found, "metric http.server.request.duration not found")
}

func TestRequireEmptyBody(t *testing.T) {
	called := false
	handler := requireEmptyBody(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	t.Run("No body passes through", func(t *testing.T) {
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", nil)
		rr := httptest.NewRecorder()
		handler(rr, req)
		assert.True(t, called)
		assert.Equal(t, http.StatusNoContent, rr.Code)
	})

	t.Run("Body with Content-Length rejected upfront", func(t *testing.T) {
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", bytes.NewReader([]byte("hi")))
		req.ContentLength = 2
		rr := httptest.NewRecorder()
		handler(rr, req)
		assert.False(t, called, "handler must not run when body is present")
		assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
	})

	t.Run("Chunked body (ContentLength = -1) detected and rejected", func(t *testing.T) {
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", bytes.NewReader([]byte("chunked-data")))
		req.ContentLength = -1 // Simulates chunked transfer encoding
		rr := httptest.NewRecorder()
		handler(rr, req)
		assert.False(t, called, "handler must not run when chunked body has data")
		assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
	})

	t.Run("Empty chunked body (ContentLength = -1, no data) passes through", func(t *testing.T) {
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", bytes.NewReader(nil))
		req.ContentLength = -1
		rr := httptest.NewRecorder()
		handler(rr, req)
		assert.True(t, called, "empty chunked body should be allowed")
		assert.Equal(t, http.StatusNoContent, rr.Code)
	})

	t.Run("Nil body passes through", func(t *testing.T) {
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", nil)
		req.Body = nil
		rr := httptest.NewRecorder()
		handler(rr, req)
		assert.True(t, called)
		assert.Equal(t, http.StatusNoContent, rr.Code)
	})

	t.Run("Body that fails to read is rejected", func(t *testing.T) {
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", iotest.ErrReader(errors.New("malformed chunked encoding")))
		req.ContentLength = -1
		rr := httptest.NewRecorder()
		handler(rr, req)
		assert.False(t, called, "handler must not run when the body can't be read")
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Equal(t, "close", rr.Header().Get("Connection"))
	})

	t.Run("Body that returns no data on the first read is still probed", func(t *testing.T) {
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", &emptyFirstReader{data: []byte("x")})
		req.ContentLength = -1
		rr := httptest.NewRecorder()
		handler(rr, req)
		assert.False(t, called, "handler must not run when the body has data")
		assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
	})

	t.Run("Body over the size limit is rejected", func(t *testing.T) {
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", bytes.NewReader([]byte("chunked-data")))
		req.ContentLength = -1
		rr := httptest.NewRecorder()
		req.Body = http.MaxBytesReader(rr, req.Body, 0)
		handler(rr, req)
		assert.False(t, called, "handler must not run when the body is over the limit")
		assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
	})

	t.Run("Malformed chunked body from a real connection is rejected", func(t *testing.T) {
		srv := httptest.NewServer(requireEmptyBody(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		var dialer net.Dialer
		conn, err := dialer.DialContext(t.Context(), "tcp", srv.Listener.Addr().String())
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()

		// "zz" isn't a valid chunk size
		_, err = conn.Write([]byte("POST /token HTTP/1.1\r\nHost: tsiam\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"))
		require.NoError(t, err)

		res, err := http.ReadResponse(bufio.NewReader(conn), nil)
		require.NoError(t, err)
		defer func() { _ = res.Body.Close() }()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
}

// Reader that returns no data and no error on the first read, which io.Reader allows
type emptyFirstReader struct {
	data []byte
	read bool
}

func (r *emptyFirstReader) Read(p []byte) (int, error) {
	if !r.read {
		r.read = true
		return 0, nil
	}
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestRejectOversizedRequest(t *testing.T) {
	mw := rejectOversizedRequest(maxBodySize)
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	t.Run("Under cap passes through", func(t *testing.T) {
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader([]byte("hi")))
		req.ContentLength = 2
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.True(t, called)
		assert.Equal(t, http.StatusNoContent, rr.Code)
	})

	t.Run("At cap passes through", func(t *testing.T) {
		called = false
		payload := bytes.Repeat([]byte("a"), maxBodySize)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(payload))
		req.ContentLength = int64(len(payload))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.True(t, called)
		assert.Equal(t, http.StatusNoContent, rr.Code)
	})

	t.Run("Over cap returns 413 and skips handler", func(t *testing.T) {
		called = false
		payload := bytes.Repeat([]byte("a"), maxBodySize*2)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(payload))
		req.ContentLength = int64(len(payload))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.False(t, called, "handler must not be called when the body is oversized")
		assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
		assert.Equal(t, "close", rr.Header().Get("Connection"))
	})

	t.Run("Unknown Content-Length passes through to handler / MaxBytesReader backstop", func(t *testing.T) {
		// Chunked transfer encoding sends ContentLength = -1; the upfront check must let it through (the backstop middleware will still cap any actual body read)
		called = false
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader([]byte("ignored")))
		req.ContentLength = -1
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.True(t, called)
		assert.Equal(t, http.StatusNoContent, rr.Code)
	})
}

func TestRequireNoBrowser(t *testing.T) {
	tests := []struct {
		name           string
		headers        map[string]string
		expectedStatus int
		expectError    bool
	}{
		{
			name: "Valid request with X-Tsiam header set to 1",
			headers: map[string]string{
				"X-Tsiam": "1",
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "Valid request with X-Tsiam header set to non-standard value",
			headers: map[string]string{
				"X-Tsiam": "true",
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name: "Valid request with X-Tsiam header set to random string",
			headers: map[string]string{
				"X-Tsiam": "my-custom-value",
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "Missing X-Tsiam header",
			headers:        map[string]string{},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Empty X-Tsiam header",
			headers: map[string]string{
				"X-Tsiam": "",
			},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Request with Origin header (browser)",
			headers: map[string]string{
				"X-Tsiam": "1",
				"Origin":  "https://example.com",
			},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Request with Sec-Fetch-Site header (browser)",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-Site": "cross-site",
			},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Request with Sec-Fetch-Mode header (browser)",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-Mode": "navigate",
			},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Request with Sec-Fetch-Dest header (browser)",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-Dest": "document",
			},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Request with Sec-Fetch-User header (browser)",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-User": "?1",
			},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Request with multiple browser headers",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Origin":         "https://example.com",
				"Sec-Fetch-Site": "same-origin",
				"Sec-Fetch-Mode": "cors",
			},
			expectedStatus: http.StatusForbidden,
			expectError:    true,
		},
		{
			name: "Request with non-browser headers is allowed",
			headers: map[string]string{
				"X-Tsiam":      "1",
				"User-Agent":   "curl/7.68.0",
				"Content-Type": "application/json",
				"Accept":       "*/*",
			},
			expectedStatus: http.StatusOK,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler that should be called only if validation passes
			handlerCalled := false
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with middleware
			handler := requireNoBrowser(testHandler)

			// Create request
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", nil)

			// Set headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Execute request
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			// Verify status code
			assert.Equal(t, tt.expectedStatus, rr.Code)

			// Verify handler was called only when no error expected
			if tt.expectError {
				assert.False(t, handlerCalled, "Handler should not be called when validation fails")
			} else {
				assert.True(t, handlerCalled, "Handler should be called when validation passes")
			}
		})
	}
}

func TestRequireNotFunneledRequest(t *testing.T) {
	// Helper that swaps the package-level seam for the duration of the subtest
	withFunneled := func(t *testing.T, funneled bool) {
		t.Helper()
		prev := isFunneledRequest
		isFunneledRequest = func(*http.Request) bool { return funneled }
		t.Cleanup(func() { isFunneledRequest = prev })
	}

	t.Run("Non-funneled request passes through", func(t *testing.T) {
		withFunneled(t, false)

		handlerCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusNoContent)
		})

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/whatever", nil)
		rr := httptest.NewRecorder()
		requireNotFunneledRequest(next)(rr, req)

		assert.True(t, handlerCalled, "non-funneled request should reach the wrapped handler")
		assert.Equal(t, http.StatusNoContent, rr.Code)
	})

	t.Run("Funneled request returns 404 and skips handler", func(t *testing.T) {
		withFunneled(t, true)

		handlerCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/whatever", nil)
		rr := httptest.NewRecorder()
		requireNotFunneledRequest(next)(rr, req)

		assert.False(t, handlerCalled, "funneled request must not reach the wrapped handler")
		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
}

func TestValidateNoBrowser(t *testing.T) {
	tests := []struct {
		name        string
		headers     map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid request",
			headers: map[string]string{
				"X-Tsiam": "1",
			},
			expectError: false,
		},
		{
			name:        "Missing X-Tsiam header",
			headers:     map[string]string{},
			expectError: true,
			errorMsg:    "missing header X-Tsiam",
		},
		{
			name: "Empty X-Tsiam header",
			headers: map[string]string{
				"X-Tsiam": "",
			},
			expectError: true,
			errorMsg:    "missing header X-Tsiam",
		},
		{
			name: "Origin header present",
			headers: map[string]string{
				"X-Tsiam": "1",
				"Origin":  "https://example.com",
			},
			expectError: true,
			errorMsg:    "found browser header 'Origin'",
		},
		{
			name: "Sec-Fetch-Site header present",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-Site": "same-origin",
			},
			expectError: true,
			errorMsg:    "found browser header 'Sec-Fetch-Site'",
		},
		{
			name: "Sec-Fetch-Mode header present",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-Mode": "navigate",
			},
			expectError: true,
			errorMsg:    "found browser header 'Sec-Fetch-Mode'",
		},
		{
			name: "Sec-Fetch-Dest header present",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-Dest": "document",
			},
			expectError: true,
			errorMsg:    "found browser header 'Sec-Fetch-Dest'",
		},
		{
			name: "Sec-Fetch-User header present",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-User": "?1",
			},
			expectError: true,
			errorMsg:    "found browser header 'Sec-Fetch-User'",
		},
		{
			name: "Case sensitivity - X-Tsiam with different casing",
			headers: map[string]string{
				"x-tsiam": "1",
			},
			expectError: false,
		},
		{
			name: "Whitespace-only X-Tsiam header",
			headers: map[string]string{
				"X-Tsiam": "  ",
			},
			expectError: true,
			errorMsg:    "missing header X-Tsiam",
		},
		{
			name: "Empty Origin header present",
			headers: map[string]string{
				"X-Tsiam": "1",
				"Origin":  "",
			},
			expectError: true,
			errorMsg:    "found browser header 'Origin'",
		},
		{
			name: "Empty Sec-Fetch-Site header present",
			headers: map[string]string{
				"X-Tsiam":        "1",
				"Sec-Fetch-Site": "",
			},
			expectError: true,
			errorMsg:    "found browser header 'Sec-Fetch-Site'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", nil)

			// Set headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Validate
			err := validateNoBrowser(req)

			// Check error
			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}

	// Header.Get only returns the first value, so a browser header after an empty one must still be found
	for _, h := range browserHeaders {
		t.Run("Second "+h+" header after an empty one", func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", nil)
			req.Header.Set("X-Tsiam", "1")
			req.Header.Add(h, "")
			req.Header.Add(h, "same-origin")

			err := validateNoBrowser(req)
			require.ErrorContains(t, err, "found browser header '"+h+"'")
		})
	}
}

// Trace context sent by the caller in the tests, with the sampled flag off
const (
	callerTraceID     = "4bf92f3577b34da6a3ce929d0e0e4736"
	callerTraceparent = "00-" + callerTraceID + "-00f067aa0ba902b7-00"
)

// Builds a server whose middlewares record spans and logs, which otelhttp and sloghttp read from the globals when the middlewares are created
func newTelemetryTestServer(t *testing.T) (s *Server, spans *tracetest.SpanRecorder, logs *strings.Builder) {
	t.Helper()

	spans = tracetest.NewSpanRecorder()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans)))
	otel.SetTextMapPropagator(propagation.TraceContext{})

	logs = &strings.Builder{}
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))

	t.Cleanup(func() {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
		slog.SetDefault(prevLogger)
	})

	s, restore := newTestServer(t, nil, func(*http.Request) (tsnetserver.TailscaleWhoIs, error) {
		return defaultWhois(), nil
	})
	t.Cleanup(restore)
	s.initAppServer()

	return s, spans, logs
}

// Returns the only span that was recorded
func onlySpan(t *testing.T, spans *tracetest.SpanRecorder) sdktrace.ReadOnlySpan {
	t.Helper()
	ended := spans.Ended()
	require.Len(t, ended, 1)
	return ended[0]
}

// Returns the value of a span attribute, or an empty string if it's not set
func spanAttr(span sdktrace.ReadOnlySpan, key attribute.Key) string {
	for _, kv := range span.Attributes() {
		if kv.Key == key {
			return kv.Value.AsString()
		}
	}
	return ""
}

func TestTelemetry(t *testing.T) {
	newRequest := func(t *testing.T, path string) *http.Request {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+testHostname+path, nil)
		req.RemoteAddr = "100.64.0.1:4321"
		req.Header.Set("Traceparent", callerTraceparent)
		req.Header.Set("X-Forwarded-For", "198.51.100.7")
		return req
	}

	t.Run("Tailnet requests continue the caller's trace and ignore X-Forwarded-For", func(t *testing.T) {
		s, spans, _ := newTelemetryTestServer(t)

		rr := httptest.NewRecorder()
		s.handler.ServeHTTP(rr, newRequest(t, "/healthz"))
		require.Equal(t, http.StatusNoContent, rr.Code)

		// With the sampled flag off in the caller's trace context, the default sampler doesn't record the span
		assert.Empty(t, spans.Ended())

		// With the flag on, the span is part of the caller's trace
		req := newRequest(t, "/healthz")
		req.Header.Set("Traceparent", strings.TrimSuffix(callerTraceparent, "00")+"01")
		s.handler.ServeHTTP(httptest.NewRecorder(), req)

		span := onlySpan(t, spans)
		assert.Equal(t, callerTraceID, span.SpanContext().TraceID().String())
		assert.Equal(t, "100.64.0.1", spanAttr(span, "client.address"))
	})

	t.Run("Funnel requests start a new trace and record the client's IP", func(t *testing.T) {
		prevFunneled, prevIP := isFunneledRequest, funnelClientIP
		isFunneledRequest = func(*http.Request) bool { return true }
		funnelClientIP = func(*http.Request) string { return "203.0.113.9" }
		t.Cleanup(func() { isFunneledRequest, funnelClientIP = prevFunneled, prevIP })

		s, spans, logs := newTelemetryTestServer(t)

		rr := httptest.NewRecorder()
		s.handler.ServeHTTP(rr, newRequest(t, "/.well-known/jwks.json"))
		require.Equal(t, http.StatusOK, rr.Code)

		// The span is recorded even though the caller turned sampling off, because it's not part of the caller's trace
		span := onlySpan(t, spans)
		assert.NotEqual(t, callerTraceID, span.SpanContext().TraceID().String())
		assert.False(t, span.Parent().IsValid())

		// The caller's span is only linked
		links := span.Links()
		require.Len(t, links, 1)
		assert.Equal(t, callerTraceID, links[0].SpanContext.TraceID().String())

		// The span and the request log have the client's IP instead of the Tailscale relay
		assert.Equal(t, "203.0.113.9", spanAttr(span, "client.address"))
		assert.Contains(t, logs.String(), "funnelClientIp=203.0.113.9")
	})
}

func TestPanicsAreLogged(t *testing.T) {
	t.Run("Panics are logged and the client gets an internal error", func(t *testing.T) {
		s, _, logs := newTelemetryTestServer(t)
		s.whoIs = func(*http.Request) (tsnetserver.TailscaleWhoIs, error) {
			panic("simulated panic")
		}

		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+testHostname+"/token?resource="+testAudience, nil)
		req.Header.Set(tsiamHeaderName, "1")
		rr := httptest.NewRecorder()
		s.handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		assert.Contains(t, rr.Body.String(), `"internal"`)
		assert.Contains(t, logs.String(), "level=ERROR")
		assert.Contains(t, logs.String(), "Panic while handling the request")
		assert.Contains(t, logs.String(), "simulated panic")
		assert.Contains(t, logs.String(), "stack=")
	})
}
