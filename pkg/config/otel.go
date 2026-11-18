package config

import (
	"context"

	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"

	"github.com/italypaleale/tsiam/pkg/buildinfo"
)

// GetOtelResource returns the OpenTelemetry Resource object
// Environment attributes are applied last so OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES can override defaults
func (c *Config) GetOtelResource(name string) (*resource.Resource, error) {
	version := buildinfo.BuildId
	if version == "" {
		version = buildinfo.AppVersion
	}

	//nolint:wrapcheck
	return resource.New(context.Background(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(
			semconv.ServiceName(name),
			semconv.ServiceInstanceID(c.GetInstanceID()),
			semconv.ServiceVersion(version),
		),
		resource.WithFromEnv(),
	)
}
