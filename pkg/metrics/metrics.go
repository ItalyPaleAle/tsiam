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
	auths api.Int64Counter
}

func NewAppMetrics(ctx context.Context) (m *AppMetrics, shutdownFn func(ctx context.Context) error, err error) {
	cfg := config.Get()

	m = &AppMetrics{}

	meter, shutdownFn, err := observability.InitMetrics(ctx, observability.InitMetricsOpts{
		Config:  cfg,
		AppName: buildinfo.AppName,
		Prefix:  prefix,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init metrics: %w", err)
	}

	// Runtime instrumentation for Go runtime metrics
	err = runtime.Start()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start runtime instrumentation: %w", err)
	}

	// Counter for number of authentications
	m.auths, err = meter.Int64Counter(
		prefix+"_auths",
		api.WithDescription("The number of authentications"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create "+prefix+"_auths meter: %w", err)
	}

	return m, shutdownFn, nil
}

//nolint:contextcheck
func (m *AppMetrics) RecordAuth(nodeName string, audience string) {
	if m == nil {
		return
	}

	m.auths.Add(
		context.Background(),
		1,
		api.WithAttributeSet(
			attribute.NewSet(
				attribute.KeyValue{Key: "node", Value: attribute.StringValue(nodeName)},
				attribute.KeyValue{Key: "endpoint", Value: attribute.StringValue(audience)},
			),
		),
	)
}
