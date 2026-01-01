package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/italypaleale/go-kit/servicerunner"
	"github.com/italypaleale/go-kit/signals"
	slogkit "github.com/italypaleale/go-kit/slog"
	"github.com/italypaleale/go-kit/tsnetserver"

	"github.com/italypaleale/tsiam/pkg/buildinfo"
	"github.com/italypaleale/tsiam/pkg/config"
	appmetrics "github.com/italypaleale/tsiam/pkg/metrics"
	"github.com/italypaleale/tsiam/pkg/server"
)

func main() {
	// Init a logger used for initialization only, to report initialization errors
	initLogger := slog.Default().
		With(slog.String("app", buildinfo.AppName)).
		With(slog.String("version", buildinfo.AppVersion))

	// Load config
	err := config.LoadConfig()
	if err != nil {
		var ce *config.ConfigError
		if errors.As(err, &ce) {
			ce.LogFatal(initLogger)
		} else {
			slogkit.FatalError(initLogger, "Failed to load configuration", err)
			return
		}
	}
	cfg := config.Get()

	// List of services to run
	services := make([]servicerunner.Service, 0, 3)

	// Shutdown functions
	shutdownFns := make([]servicerunner.Service, 0, 4)

	// Get the logger and set it in the context
	log, loggerShutdownFn, err := config.GetLogger(context.Background())
	if err != nil {
		slogkit.FatalError(initLogger, "Failed to create logger", err)
		return
	}
	slog.SetDefault(log)
	if loggerShutdownFn != nil {
		shutdownFns = append(shutdownFns, loggerShutdownFn)
	}

	// Validate the configuration
	err = cfg.Validate(log)
	if err != nil {
		slogkit.FatalError(log, "Invalid configuration", err)
		return
	}

	log.Info("Starting tsiam", slog.String("build", buildinfo.BuildDescription))

	// Get a context that is canceled when the application receives a termination signal
	// We store the logger in the context too
	ctx := signals.SignalContext(context.Background())

	// Init appMetrics
	appMetrics, metricsShutdownFn, err := appmetrics.NewAppMetrics(ctx)
	if err != nil {
		slogkit.FatalError(log, "Failed to init metrics", err)
		return
	}
	if metricsShutdownFn != nil {
		shutdownFns = append(shutdownFns, metricsShutdownFn)
	}

	// Get the signing signingKey
	signingKey, err := getKey(ctx)
	if err != nil {
		slogkit.FatalError(log, "Failed to get signing key", err)
	}

	// Init tsnetServer
	ts, err := tsnetserver.NewTSNetServer(ctx, tsnetserver.NewTSNetServerOpts{
		Hostname:  cfg.TSNet.Hostname,
		AuthKey:   cfg.TSNet.AuthKey,
		StateDir:  cfg.GetTSNetStateDir(),
		Ephemeral: cfg.TSNet.Ephemeral,
	})
	if err != nil {
		slogkit.FatalError(log, "Failed to init TSNet server", err)
		return
	}
	shutdownFns = append(shutdownFns, ts.Close)

	// Create server
	log.Info("Initializing server")
	apiServer, err := server.NewServer(server.NewServerOpts{
		AppMetrics:  appMetrics,
		TSNetServer: ts,
		SigningKey:  signingKey,
	})
	if err != nil {
		slogkit.FatalError(log, "Failed to init API server", err)
		return
	}
	services = append(services, apiServer.Run)

	// Run all services
	// This call blocks until the context is canceled
	err = servicerunner.
		NewServiceRunner(services...).
		Run(ctx)
	if err != nil {
		slogkit.FatalError(log, "Failed to run service", err)
		return
	}

	// Invoke all shutdown functions
	// We give these a timeout of 5s
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	err = servicerunner.
		NewServiceRunner(shutdownFns...).
		Run(shutdownCtx)
	if err != nil {
		log.Error("Error shutting down services", slog.Any("error", err))
	}
}
