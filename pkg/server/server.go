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
	slogkit "github.com/italypaleale/go-kit/slog"
	"github.com/lestrrat-go/jwx/v3/jwk"
	sloghttp "github.com/samber/slog-http"

	"github.com/italypaleale/tsiam/pkg/config"
	"github.com/italypaleale/tsiam/pkg/jwks"
	"github.com/italypaleale/tsiam/pkg/metrics"
	"github.com/italypaleale/tsiam/pkg/tsnetserver"
)

// Server is the server based on Gin
type Server struct {
	appSrv  *http.Server
	handler http.Handler
	running atomic.Bool
	wg      sync.WaitGroup

	appMetrics *metrics.AppMetrics

	// Listener for the app server
	// This can be used for testing without having to start an actual TCP listener
	tsListener net.Listener

	// TSNet server instance
	tsnetServer *tsnetserver.TSNetServer

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
	s = &Server{
		appMetrics:  opts.AppMetrics,
		tsnetServer: opts.TSNetServer,
		signingKey:  opts.SigningKey,
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
	mux.HandleFunc("POST /token", requireNotFunneledRequest(s.handlePostToken))
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleGetJWKS)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleGetOpenIDConfiguration)
	mux.HandleFunc("GET /healthz", requireNotFunneledRequest(s.handleGetHealthz))
	mux.HandleFunc("GET /", s.handleGetRoot)

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

	middlewares := []httpserver.Middleware{
		// Recover from panics
		sloghttp.Recovery,
		// Limit request body to 1KB
		httpserver.MiddlewareMaxBodySize(1 << 10),
		// Log requests
		sloghttp.NewWithFilters(slog.Default(), filters...),
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
	err := s.startAppServer(ctx)
	if err != nil {
		return fmt.Errorf("failed to start app server: %w", err)
	}

	s.wg.Add(1)
	defer func() { //nolint:contextcheck
		// Handle graceful shutdown
		defer s.wg.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.appSrv.Shutdown(shutdownCtx)
		shutdownCancel()
		if err != nil {
			// Log the error only (could be context canceled)
			slog.WarnContext(shutdownCtx,
				"App server shutdown error",
				slog.Any("error", err),
			)
		}
	}()

	// Block until the context is canceled
	<-ctx.Done()

	// Servers are stopped with deferred calls
	return nil
}

func (s *Server) startAppServer(ctx context.Context) (err error) {
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
	if s.tsListener == nil {
		// Set the ConnContext function which augments the context with information about the tsnet connection
		s.appSrv.ConnContext = s.tsnetServer.ConnContextFn()

		if cfg.TSNet.Funnel {
			// Start the Funnel listener if enabled
			s.tsListener, err = s.tsnetServer.ListenFunnel(443)
			if err != nil {
				return fmt.Errorf("failed to listen on tsnet with funnel: %w", err)
			}
		} else {
			s.tsListener, err = s.tsnetServer.Listen(443)
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
	go func() { //nolint:contextcheck
		defer s.tsListener.Close() //nolint:errcheck

		// Next call blocks until the server is shut down
		srvErr := s.appSrv.Serve(s.tsListener)
		if !errors.Is(srvErr, http.ErrServerClosed) {
			slogkit.FatalError(slog.Default(), "Error starting app server", srvErr)
		}
	}()

	return nil
}

func (s *Server) tokenIssuer() string {
	return "https://" + s.tsnetServer.Hostname()
}

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
