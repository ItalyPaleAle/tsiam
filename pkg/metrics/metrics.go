package metrics

import (
	"context"
	"fmt"

	"github.com/italypaleale/go-kit/observability"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel/attribute"
	api "go.opentelemetry.io/otel/metric"

	"github.com/italypaleale/tsiam/pkg/buildinfo"
	"github.com/italypaleale/tsiam/pkg/config"
)

const prefix = "tsiam"

type AppMetrics struct {
	auths           api.Int64Counter
	includeNodeName bool
}

func NewAppMetrics(ctx context.Context) (m *AppMetrics, shutdownFn func(ctx context.Context) error, err error) {
	cfg := config.Get()

	m = &AppMetrics{
		includeNodeName: cfg.Metrics.IncludeNodeName,
	}

	meter, shutdownFn, err := observability.InitMetrics(ctx, observability.InitMetricsOpts{
		Config:  cfg,
		AppName: buildinfo.AppName,
		Prefix:  prefix,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init metrics: %w", err)
	}

	// The meter provider is running from here on, so it's shut down if the rest of the initialization fails
	// Runtime instrumentation for Go runtime metrics
	err = runtime.Start()
	if err != nil {
		_ = shutdownFn(ctx)
		return nil, nil, fmt.Errorf("failed to start runtime instrumentation: %w", err)
	}

	// Counter for number of authentications
	m.auths, err = meter.Int64Counter(
		prefix+"_auths",
		api.WithDescription("The number of authentications"),
	)
	if err != nil {
		_ = shutdownFn(ctx)
		return nil, nil, fmt.Errorf("failed to create "+prefix+"_auths meter: %w", err)
	}

	return m, shutdownFn, nil
}

//nolint:contextcheck
func (m *AppMetrics) RecordAuth(ctx context.Context, nodeName string, audience string) {
	if m == nil {
		return
	}

	attrs := make([]attribute.KeyValue, 0, 2)
	attrs = append(attrs, attribute.String("endpoint", audience))
	if m.includeNodeName {
		attrs = append(attrs, attribute.String("node", nodeName))
	}

	m.auths.Add(
		context.WithoutCancel(ctx),
		1,
		api.WithAttributeSet(attribute.NewSet(attrs...)),
	)
}
