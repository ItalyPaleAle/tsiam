---
title: "Observability"
weight: 60
---

tsiam emits structured logs and metrics via OpenTelemetry, making it straightforward to integrate with any modern observability stack.

## Logs

Logs include contextual fields such as trace IDs and span IDs for correlation with distributed traces.

Configure the log level in `config.yaml`:

```yaml
logs:
  # debug, info, warn, error
  level: info
  # Suppress /healthz log lines (default: true)
  omitHealthChecks: true
  # Force JSON output (auto-detected based on TTY when not set)
  json: true
```

To ship logs to an OpenTelemetry collector, set `OTEL_EXPORTER_OTLP_ENDPOINT`. No additional config is needed.

## Metrics

To export metrics to an OpenTelemetry collector:

```sh
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
export OTEL_SERVICE_NAME=tsiam
export OTEL_RESOURCE_ATTRIBUTES=environment=production,region=us-east-1
```

To expose a Prometheus-compatible scrape endpoint instead:

```sh
export OTEL_METRICS_EXPORTER=prometheus
export OTEL_EXPORTER_PROMETHEUS_PORT=9464
```

This starts a `/metrics` endpoint on the configured port that Prometheus can scrape.

## OpenTelemetry environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OTEL_SDK_DISABLED` | Disable OpenTelemetry entirely | `false` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint | — |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | Protocol: `grpc` or `http/protobuf` | `http/protobuf` |
| `OTEL_LOGS_EXPORTER` | Logs exporter: `otlp`, `console`, `none` | `otlp` |
| `OTEL_METRICS_EXPORTER` | Metrics exporter: `otlp`, `prometheus`, `console`, `none` | `otlp` |
| `OTEL_EXPORTER_PROMETHEUS_HOST` | Host for Prometheus endpoint | `localhost` |
| `OTEL_EXPORTER_PROMETHEUS_PORT` | Port for Prometheus endpoint | `9464` |
| `OTEL_SERVICE_NAME` | Service name in telemetry | `tsiam` |
| `OTEL_RESOURCE_ATTRIBUTES` | Additional resource attributes | — |

For a complete list, see the [OpenTelemetry SDK configuration docs](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/).

## Example: Docker with OpenTelemetry Collector

```sh
docker run -d \
  --name tsiam \
  -v /path/to/config.yaml:/etc/tsiam/config.yaml:ro \
  -v /path/to/tsnet-state:/etc/tsiam/tsnet \
  -v /path/to/tsiam-state:/var/lib/tsiam \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318 \
  -e OTEL_SERVICE_NAME=tsiam \
  -e OTEL_RESOURCE_ATTRIBUTES=environment=production \
  ghcr.io/italypaleale/tsiam:v0
```

tsiam works with any OpenTelemetry-compatible backend, including Grafana Cloud, Datadog, Honeycomb, and self-hosted collectors.
