package main

import (
	"context"
	"errors"
	"log/slog"
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

func main() {
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
		var ce *configkit.ConfigError
		if errors.As(err, &ce) {
			ce.LogFatal(initLogger)
		} else {
			slogkit.FatalError(initLogger, "Failed to load configuration", err)
			return
		}
	}

	// List of services to run
	services := make([]servicerunner.Service, 0, 3)

	shutdowns := &shutdownManager{
		fns: make([]servicerunner.Service, 0, 4),
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
		shutdowns.Run(log)
		slogkit.FatalError(log, "Invalid configuration", err)
		return
	}

	log.Info("Starting tsiam", slog.String("build", buildinfo.BuildDescription))

	// Get a context that is canceled when the application receives a termination signal.
	ctx := signals.SignalContext(context.Background())

	// Init appMetrics
	appMetrics, metricsShutdownFn, err := appmetrics.NewAppMetrics(ctx)
	if err != nil {
		shutdowns.Run(log)
		slogkit.FatalError(log, "Failed to init metrics", err)
		return
	}
	shutdowns.Add(metricsShutdownFn)

	// Init tracing
	_, tracerShutdownFn, err := observability.InitTraces(ctx, observability.InitTracesOpts{
		Config:  cfg,
		AppName: buildinfo.AppName,
	})
	if err != nil {
		shutdowns.Run(log)
		slogkit.FatalError(log, "Failed to init tracing", err)
		return
	}
	shutdowns.Add(tracerShutdownFn)

	// Get the signing signingKey
	signingKey, err := getKey(ctx)
	if err != nil {
		shutdowns.Run(log)
		slogkit.FatalError(log, "Failed to get signing key", err)
		return
	}

	// Init tsnetServer
	ts, err := tsnetserver.NewTSNetServer(ctx, tsnetserver.NewTSNetServerOpts{
		Hostname:  cfg.TSNet.Hostname,
		AuthKey:   cfg.TSNet.AuthKey,
		StateDir:  cfg.GetTSNetStateDir(),
		Ephemeral: cfg.TSNet.Ephemeral,
	})
	if err != nil {
		shutdowns.Run(log)
		slogkit.FatalError(log, "Failed to init TSNet server", err)
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
		shutdowns.Run(log)
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
		shutdowns.Run(log)
		slogkit.FatalError(log, "Failed to run service", err)
		return
	}

	shutdowns.Run(log)
}

type shutdownManager struct {
	fns []servicerunner.Service
}

func (s *shutdownManager) Add(fn servicerunner.Service) {
	if fn == nil {
		return
	}
	s.fns = append(s.fns, fn)
}

func (s *shutdownManager) Run(log *slog.Logger) {
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	err := servicerunner.
		NewServiceRunner(s.fns...).
		Run(shutdownCtx)
	if err != nil {
		log.Error("Error shutting down services", slog.Any("error", err))
	}
}
