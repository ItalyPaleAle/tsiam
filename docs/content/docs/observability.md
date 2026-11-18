---
title: "Observability"
weight: 60
---

tsiam writes structured logs to stdout, and it can export logs, metrics, and traces with OpenTelemetry.

## Logs

Configure logging in `config.yaml`:

```yaml
logs:
  # debug, info, warn, error
  level: info
  # Suppress /healthz log lines (default: true)
  omitHealthChecks: true
  # JSON logs, which is the default when stdout isn't a terminal (for example, in containers)
  json: true
```

### Tailscale client logs

With `logs.level: debug`, logs also include messages from the embedded Tailscale client (`scope=tsnet`).

By default, the embedded Tailscale client uploads logs to Tailscale's log service for support. Set `TS_NO_LOGS_NO_SUPPORT=true` to disable this.

## Exporting with OpenTelemetry

tsiam doesn't export anything by default. To send logs, metrics, and traces to an OpenTelemetry collector, set the collector's endpoint and enable each signal you want:

```sh
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
export OTEL_LOGS_EXPORTER=otlp
export OTEL_METRICS_EXPORTER=otlp
export OTEL_TRACES_EXPORTER=otlp
```

The default service name is `tsiam` (override with `OTEL_SERVICE_NAME`). Use `OTEL_RESOURCE_ATTRIBUTES` to set additional resource attributes.

### Metrics

| Metric | Description |
| --- | --- |
| `tsiam_auths` | Number of tokens issued, with the audience in the `endpoint` attribute |

tsiam also exports Go runtime metrics and HTTP server metrics.

Set [`metrics.includeNodeName`](/docs/configuration#metrics) to `true` to add the caller's node name (`node` attribute) to `tsiam_auths`. Only enable this when the set of nodes is small and stable, as each node name creates a new time series.

To expose a Prometheus-compatible scrape endpoint instead of pushing metrics:

```sh
export OTEL_METRICS_EXPORTER=prometheus
export OTEL_EXPORTER_PROMETHEUS_HOST=0.0.0.0
export OTEL_EXPORTER_PROMETHEUS_PORT=9464
```

This exposes `/metrics` on the host network (not on the Tailnet). Because it listens on `localhost` by default, set `OTEL_EXPORTER_PROMETHEUS_HOST=0.0.0.0` when running in a container.

### Traces

tsiam creates a span for every request. Requests from your Tailnet that include a `traceparent` header continue the caller's trace. Requests via Tailscale Funnel always start a new trace and link to the caller's span.

## OpenTelemetry environment variables

| Variable | Description | Default |
| --- | --- | --- |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint | — |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | Protocol: `grpc` or `http/protobuf` | `http/protobuf` |
| `OTEL_LOGS_EXPORTER` | Logs exporter: `otlp`, `console`, `none` | `none` |
| `OTEL_METRICS_EXPORTER` | Metrics exporter: `otlp`, `prometheus`, `console`, `none` | `none` |
| `OTEL_TRACES_EXPORTER` | Traces exporter: `otlp`, `console`, `none` | `none` |
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
  -e OTEL_LOGS_EXPORTER=otlp \
  -e OTEL_METRICS_EXPORTER=otlp \
  -e OTEL_TRACES_EXPORTER=otlp \
  -e OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=production \
  ghcr.io/italypaleale/tsiam:v0
```

tsiam works with any OpenTelemetry-compatible backend, including Grafana Cloud, Datadog, Honeycomb, and self-hosted collectors.
