package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	configkit "github.com/italypaleale/go-kit/config"
	"github.com/italypaleale/go-kit/observability"
	"github.com/italypaleale/go-kit/servicerunner"
	"github.com/italypaleale/go-kit/signals"
	slogkit "github.com/italypaleale/go-kit/slog"
	"github.com/italypaleale/go-kit/tsnetserver"

	"github.com/italypaleale/tsiam/pkg/buildinfo"
	"github.com/italypaleale/tsiam/pkg/config"
	appmetrics "github.com/italypaleale/tsiam/pkg/metrics"
	"github.com/italypaleale/tsiam/pkg/server"
)

const (
	// Maximum time to load or create the signing key at startup, which can involve Azure Key Vault
	getKeyTimeout = 2 * time.Minute
	// Maximum time to join the tailnet at startup, which includes waiting for interactive login
	joinTailnetTimeout = 5 * time.Minute
	// Maximum time for each step of the shutdown
	shutdownTimeout = 5 * time.Second
)

func main() {
	exit, code := handleArgs(os.Args[1:], os.Stdout, os.Stderr)
	if exit {
		os.Exit(code)
	}

	// Init a logger used for initialization only, to report initialization errors
	initLogger := slog.Default().
		With(slog.String("app", buildinfo.AppName)).
		With(slog.String("version", buildinfo.AppVersion))

	// Load config
	cfg := config.Get()
	err := configkit.LoadConfig(cfg, configkit.LoadConfigOpts{
		EnvVar:  "TSIAM_CONFIG",
		DirName: "tsiam",
	})
	if err != nil {
		ce, ok := errors.AsType[*configkit.ConfigError](err)
		if ok {
			ce.LogFatal(initLogger)
		} else {
			slogkit.FatalError(initLogger, "Failed to load configuration", err)
			return
		}
	}

	// List of services to run
	services := make([]servicerunner.Service, 0, 3)

	shutdowns := &shutdownManager{
		fns:     make([]servicerunner.Service, 0, 4),
		timeout: shutdownTimeout,
	}

	// Check the log level first: creating the logger would fail too, but its error doesn't name the configuration option
	err = cfg.Logs.Validate()
	if err != nil {
		slogkit.FatalError(initLogger, "Invalid configuration", err)
		return
	}

	// Get the logger and set it in the context
	log, loggerShutdownFn, err := observability.InitLogs(context.Background(), observability.InitLogsOpts{
		Config:     cfg,
		Level:      cfg.Logs.Level,
		JSON:       cfg.Logs.JSON,
		AppName:    buildinfo.AppName,
		AppVersion: buildinfo.AppVersion,
	})
	if err != nil {
		slogkit.FatalError(initLogger, "Failed to create logger", err)
		return
	}
	slog.SetDefault(log)
	shutdowns.Add(loggerShutdownFn)

	// Validate the configuration
	err = cfg.Validate(log)
	if err != nil {
		shutdowns.Fatal(log, "Invalid configuration", err)
		return
	}

	log.Info("Starting tsiam", slog.String("build", buildinfo.BuildDescription))

	// Get a context that is canceled when the application receives a termination signal
	ctx := signals.SignalContext(context.Background())

	// Init appMetrics
	appMetrics, metricsShutdownFn, err := appmetrics.NewAppMetrics(ctx)
	if err != nil {
		shutdowns.Fatal(log, "Failed to init metrics", err)
		return
	}
	shutdowns.Add(metricsShutdownFn)

	// Init tracing
	_, tracerShutdownFn, err := observability.InitTraces(ctx, observability.InitTracesOpts{
		Config:  cfg,
		AppName: buildinfo.AppName,
	})
	if err != nil {
		shutdowns.Fatal(log, "Failed to init tracing", err)
		return
	}
	shutdowns.Add(tracerShutdownFn)

	// Get the signing key
	// Startup steps that call external services have a timeout, so tsiam exits with an error instead of hanging
	keyCtx, keyCancel := context.WithTimeout(ctx, getKeyTimeout)
	signingKey, err := getKey(keyCtx)
	keyCancel()
	if err != nil {
		shutdowns.Fatal(log, "Failed to get signing key", err)
		return
	}

	// If we were given an IDToken or IDTokenFile, use them
	idToken := cfg.TSNet.IDToken
	if cfg.TSNet.IDTokenFile != "" {
		idToken, err = readIDTokenFile(cfg.TSNet.IDTokenFile)
		if err != nil {
			shutdowns.Fatal(log, "Failed to read tsnet ID token file", err)
			return
		}
	}

	// Init tsnetServer
	tsnetCtx, tsnetCancel := context.WithTimeout(ctx, joinTailnetTimeout)
	ts, err := tsnetserver.NewTSNetServer(tsnetCtx, tsnetserver.NewTSNetServerOpts{
		Hostname:      cfg.TSNet.Hostname,
		ClientID:      cfg.TSNet.ClientID,
		IDToken:       idToken,
		Audience:      cfg.TSNet.Audience,
		AuthKey:       cfg.TSNet.AuthKey,
		StateDir:      cfg.GetTSNetStateDir(),
		Ephemeral:     cfg.TSNet.Ephemeral,
		AdvertiseTags: cfg.TSNet.AdvertiseTags,
	})
	tsnetCancel()
	if err != nil {
		shutdowns.Fatal(log, "Failed to init TSNet server", err)
		return
	}
	shutdowns.Add(ts.Close)

	// Create server
	log.Info("Initializing server")
	apiServer, err := server.NewServer(server.NewServerOpts{
		AppMetrics:  appMetrics,
		TSNetServer: ts,
		SigningKey:  signingKey,
	})
	if err != nil {
		shutdowns.Fatal(log, "Failed to init API server", err)
		return
	}
	services = append(services, apiServer.Run)

	// Run all services
	// This call blocks until the context is canceled
	err = servicerunner.
		NewServiceRunner(services...).
		Run(ctx)
	if err != nil {
		shutdowns.Fatal(log, "Failed to run service", err)
		return
	}

	shutdowns.Run(log)
}

type shutdownManager struct {
	fns     []servicerunner.Service
	timeout time.Duration
}

func (s *shutdownManager) Add(fn servicerunner.Service) {
	if fn == nil {
		return
	}
	s.fns = append(s.fns, fn)
}

// Run calls the shutdown functions one at a time, in the reverse order they were added
// Each function gets its own timeout, so one that hangs doesn't stop the others from running
func (s *shutdownManager) Run(log *slog.Logger) {
	for _, fn := range slices.Backward(s.fns) {
		err := s.runOne(fn)
		if err != nil {
			log.Error("Error shutting down services", slog.Any("error", err))
		}
	}
	s.fns = nil
}

// Runs a single shutdown function, converting panics into errors so the remaining functions still run
func (s *shutdownManager) runOne(fn servicerunner.Service) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	defer func() {
		p := recover()
		if p != nil {
			err = fmt.Errorf("shutdown function panicked: %v", p)
		}
	}()

	return fn(ctx)
}

// Fatal logs the error, shuts down everything that was started, and exits with code 1
// The error is logged before the logger is shut down, so it's exported like every other log
func (s *shutdownManager) Fatal(log *slog.Logger, message string, err error) {
	log.Error(message, slog.Any("error", err))
	s.Run(log)
	os.Exit(1)
}

func readIDTokenFile(filePath string) (string, error) {
	data, err := os.ReadFile(filePath) // #nosec G304 -- Reading user-provided path by design
	if err != nil {
		return "", fmt.Errorf("error reading token file %q: %w", filePath, err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("token file is empty")
	}

	return token, nil
}
