package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	httpserver "github.com/italypaleale/go-kit/httpserver"
	"github.com/italypaleale/go-kit/tsnetserver"
	"github.com/lestrrat-go/jwx/v4/jwk"
	sloghttp "github.com/samber/slog-http"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/italypaleale/tsiam/pkg/config"
	"github.com/italypaleale/tsiam/pkg/jwks"
	"github.com/italypaleale/tsiam/pkg/metrics"
)

// Max size for request bodies.
// 1KB
const maxBodySize = 1 << 10

// Default time that Run waits for active requests to complete during shutdown
const defaultShutdownTimeout = 5 * time.Second

// Server is the HTTP API server
type Server struct {
	appSrv  *http.Server
	handler http.Handler
	running atomic.Bool
	wg      sync.WaitGroup

	// Time that Run waits for active requests to complete during shutdown
	shutdownTimeout time.Duration

	appMetrics *metrics.AppMetrics

	// Listener for the app server
	// This can be used for testing without having to start an actual TCP listener
	tsListener net.Listener

	// TSNet server instance
	tsnetServer *tsnetserver.TSNetServer

	// Request-time tsnet dependencies, broken out so handler tests can supply mocks
	// In production both delegate to tsnetServer
	whoIs    func(r *http.Request) (tsnetserver.TailscaleWhoIs, error)
	hostname func() string

	// Token signing key
	signingKey jwk.Key
	// Public JWKS, pre-computed (encoded as JSON)
	publicJwks []byte
}

// NewServerOpts contains options for the NewServer method
type NewServerOpts struct {
	AppMetrics  *metrics.AppMetrics
	TSNetServer *tsnetserver.TSNetServer
	SigningKey  jwk.Key
}

// NewServer creates a new Server object and initializes it
func NewServer(opts NewServerOpts) (s *Server, err error) {
	if opts.SigningKey == nil {
		return nil, errors.New("signing key is required")
	}

	err = jwks.ValidateSigningKey(opts.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("invalid signing key: %w", err)
	}

	if opts.TSNetServer == nil {
		return nil, errors.New("tsnet server is required")
	}

	s = &Server{
		appMetrics:      opts.AppMetrics,
		tsnetServer:     opts.TSNetServer,
		whoIs:           opts.TSNetServer.WhoIs,
		hostname:        opts.TSNetServer.Hostname,
		signingKey:      opts.SigningKey,
		shutdownTimeout: defaultShutdownTimeout,
	}

	// Pre-compute the JWKS, encoded as JSON
	s.publicJwks, err = jwks.GetPublicJWKSAsJSON(opts.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to precompute JWKS: %w", err)
	}

	// Init the app server
	s.initAppServer()

	return s, nil
}

func (s *Server) initAppServer() {
	cfg := config.Get()

	// Create the mux
	mux := http.NewServeMux()

	// Register routes
	// Note: we do not enable CORS in the server on purpose, as we don't want browsers to make direct connections
	// If needed, it can be added to public endpoints (.well-known/*) in the future
	// httpserver.UseFunc wraps the handler with each middleware in turn, so the last middleware listed is the outermost and runs first
	mux.HandleFunc("POST /token", httpserver.UseFunc(s.handlePostToken, requireEmptyBody, requireNoBrowser, requireNotFunneledRequest, tokenRateLimit(cfg.Tokens.RateLimitPerMinute)))
	// The public endpoints share a single limiter, so a client's budget covers both
	publicLimit := rateLimit(publicRateLimitPerSecond, time.Second)
	mux.HandleFunc("GET /.well-known/jwks.json", httpserver.UseFunc(s.handleGetJWKS, publicLimit))
	mux.HandleFunc("GET /.well-known/openid-configuration", httpserver.UseFunc(s.handleGetOpenIDConfiguration, publicLimit))
	mux.HandleFunc("GET /healthz", httpserver.UseFunc(s.handleGetHealthz, requireNotFunneledRequest))
	mux.HandleFunc("GET /", httpserver.UseFunc(s.handleGetRoot, requireNotFunneledRequest))

	filters := []sloghttp.Filter{
		sloghttp.IgnoreStatus(401, 404),
	}
	if cfg.Logs.OmitHealthChecks {
		filters = append(filters,
			func(w sloghttp.WrapResponseWriter, r *http.Request) bool {
				return r.URL.Path != "/healthz"
			},
		)
	}

	// httpserver.Use wraps the handler with each middleware in turn, so the first middleware listed is the innermost and the last one runs first
	middlewares := []httpserver.Middleware{
		// Recover from panics in handlers
		sloghttp.Recovery,
		// Wrap r.Body with MaxBytesReader as a backstop against chunked / no-Content-Length attacks that bypass the upfront check, in case a future handler does read the body
		httpserver.MiddlewareMaxBodySize(maxBodySize),
		// Log requests
		sloghttp.NewWithFilters(slog.Default(), filters...),
		// Wrap with OpenTelemetry HTTP instrumentation for metrics and tracing
		otelhttp.NewMiddleware("server", otelhttp.WithServerName(net.JoinHostPort(s.hostname(), "443"))),
		// Only the public endpoints are reachable over Funnel, and Funnel requests are rate-limited before they're logged or traced
		// It has its own limiter, because sharing the routes' limiter would count allowed Funnel requests twice
		requireFunnelAllowed(rateLimit(publicRateLimitPerSecond, time.Second)),
		// Reject oversized requests upfront based on Content-Length so we never read or TLS-decrypt the body
		rejectOversizedRequest(maxBodySize),
		// Reject requests for other hosts before they're logged or traced
		requireKnownHost(s.hostname),
		// Set on every response, including errors returned by the middlewares above
		setNoSniff,
		// Recover from panics in the middlewares above
		sloghttp.Recovery,
	}

	// Add middlewares
	s.handler = httpserver.Use(mux, middlewares...)
}

// Run the web server
// Note this function is blocking, and will return only when the server is shut down via context cancellation.
func (s *Server) Run(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("server is already running")
	}
	defer s.running.Store(false)
	defer s.wg.Wait()

	// App server
	s.wg.Add(1)
	appSrvErrCh := make(chan error, 1)
	err := s.startAppServer(ctx, appSrvErrCh)
	if err != nil {
		s.wg.Done()
		return fmt.Errorf("failed to start app server: %w", err)
	}
	defer func() {
		// Handle graceful shutdown
		defer s.wg.Done()
		s.stopAppServer(ctx)
	}()

	// Block until the context is canceled or the app server exits unexpectedly
	select {
	case <-ctx.Done():
	case err = <-appSrvErrCh:
		return fmt.Errorf("app server failed: %w", err)
	}

	// Servers are stopped with deferred calls
	return nil
}

// Stops the app server, waiting up to shutdownTimeout for active requests to complete
// After that, it closes the connections that are still open, which also cancels their requests' contexts, so handlers stop using the tsnet server and the metrics, which are shut down after Run returns
func (s *Server) stopAppServer(parentCtx context.Context) {
	// The parent context is already canceled at this point, but it can carry values for logging
	ctx := context.WithoutCancel(parentCtx)

	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, s.shutdownTimeout)
	defer shutdownCancel()

	err := s.appSrv.Shutdown(shutdownCtx)
	if err == nil {
		return
	}

	slog.WarnContext(ctx, "App server didn't shut down in time, closing the remaining connections", slog.Any("error", err))
	err = s.appSrv.Close()
	if err != nil {
		slog.WarnContext(ctx, "Error closing the app server", slog.Any("error", err))
	}
}

func (s *Server) startAppServer(ctx context.Context, appSrvErrCh chan<- error) (err error) {
	cfg := config.Get()

	// Create the HTTP server
	s.appSrv = &http.Server{
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		Handler:           s.handler,
	}

	// Create the listener if we don't have one already
	// The tsnet listener is already TLS-wrapped
	// A listener created here is closed when the server stops, so it's not stored in s.tsListener, and the next call to Run creates a new one
	ln := s.tsListener
	if ln == nil {
		// Set the ConnContext function which augments the context with information about the tsnet connection
		s.appSrv.ConnContext = s.tsnetServer.ConnContextFn()

		if cfg.TSNet.Funnel {
			// Start the Funnel listener if enabled
			ln, err = s.tsnetServer.ListenFunnel(443)
			if err != nil {
				return fmt.Errorf("failed to listen on tsnet with funnel: %w", err)
			}
		} else {
			ln, err = s.tsnetServer.Listen(443)
			if err != nil {
				return fmt.Errorf("failed to listen on tsnet: %w", err)
			}
		}

		ip4, ip6 := s.tsnetServer.TailscaleIPs()
		slog.InfoContext(ctx, "Starting app server on tsnet",
			slog.String("hostname", s.tsnetServer.Hostname()),
			slog.String("ip4", ip4),
			slog.String("ip6", ip6),
			slog.Int("port", 443),
		)
	} else {
		slog.InfoContext(ctx, "Starting app server on local listener")
	}

	// Start the HTTP server in a background goroutine
	// Tracked by s.wg so Run does not return while Serve is still draining connections after shutdown
	s.wg.Go(func() { //nolint:contextcheck
		defer ln.Close() //nolint:errcheck

		// Next call blocks until the server is shut down
		srvErr := s.appSrv.Serve(ln)
		if !errors.Is(srvErr, http.ErrServerClosed) {
			select {
			case appSrvErrCh <- srvErr:
			default:
			}
		}
	})

	return nil
}

// Returns the issuer URL emitted in the JWT `iss` claim and as the `issuer` field of the OIDC discovery document
func (s *Server) tokenIssuer() string {
	return "https://" + s.hostname()
}
