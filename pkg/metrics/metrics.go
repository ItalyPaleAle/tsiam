package metrics

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel/sdk/metric"

	"github.com/italypaleale/tsiam/pkg/buildinfo"
	"github.com/italypaleale/tsiam/pkg/config"
)

// const prefix = "tsiam"

type AppMetrics struct {
}

func NewAppMetrics(ctx context.Context) (m *AppMetrics, shutdownFn func(ctx context.Context) error, err error) {
	cfg := config.Get()

	m = &AppMetrics{}

	resource, err := cfg.GetOtelResource(buildinfo.AppName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get OpenTelemetry resource: %w", err)
	}

	// Get the metric reader
	// If the env var OTEL_METRICS_EXPORTER is empty, we set it to "none"
	if os.Getenv("OTEL_METRICS_EXPORTER") == "" {
		_ = os.Setenv("OTEL_METRICS_EXPORTER", "none") //nolint:errcheck
	}
	mr, err := autoexport.NewMetricReader(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize OpenTelemetry metric reader: %w", err)
	}

	mp := metric.NewMeterProvider(
		metric.WithResource(resource),
		metric.WithReader(mr),
	)
	// TODO
	// meter := mp.Meter(prefix)

	return m, mp.Shutdown, nil
}
