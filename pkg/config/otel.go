package config

import (
	"context"

	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"

	"github.com/italypaleale/tsiam/pkg/buildinfo"
)

// GetOtelResource returns the OpenTelemetry Resource object
// tsiam's attributes come before the ones from the environment, so `OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES` can override them
// resource.Default can't be merged on top instead, because it always sets `service.name`, to `unknown_service:<binary>` when `OTEL_SERVICE_NAME` is unset
func (c *Config) GetOtelResource(name string) (*resource.Resource, error) {
	// Builds without a build ID, such as local builds, still have a version
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
