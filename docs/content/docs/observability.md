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

With `logs.level: debug`, tsiam's logs also include the logs of its embedded Tailscale client (`scope=tsnet`), which help debug problems with joining the tailnet or with connections.

Like every Tailscale client, the embedded client also uploads its logs to Tailscale's log service, to help Tailscale with support. Set the environment variable `TS_NO_LOGS_NO_SUPPORT=true` to turn that off.

## Exporting with OpenTelemetry

tsiam doesn't export anything by default. To send logs, metrics, and traces to an OpenTelemetry collector, set the collector's endpoint and enable each signal you want:

```sh
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
export OTEL_LOGS_EXPORTER=otlp
export OTEL_METRICS_EXPORTER=otlp
export OTEL_TRACES_EXPORTER=otlp
```

Telemetry has the service name `tsiam`, which you can change with `OTEL_SERVICE_NAME`. `OTEL_RESOURCE_ATTRIBUTES` adds other attributes, or overrides tsiam's, such as `service.version`.

### Metrics

| Metric | Description |
| --- | --- |
| `tsiam_auths` | Number of tokens issued, with the audience in the `endpoint` attribute |

tsiam also exports Go runtime metrics, and HTTP server metrics for every request.

To also add the name of the node that requested each token to `tsiam_auths`, in the `node` attribute, set [`metrics.includeNodeName`](/docs/configuration#metrics) to `true`. Every node name creates a new time series, so only enable it when your set of nodes is small and stable. Tailnets with ephemeral nodes, such as CI runners, would keep creating new series.

To expose a Prometheus-compatible scrape endpoint instead of pushing metrics:

```sh
export OTEL_METRICS_EXPORTER=prometheus
export OTEL_EXPORTER_PROMETHEUS_HOST=0.0.0.0
export OTEL_EXPORTER_PROMETHEUS_PORT=9464
```

This starts a `/metrics` endpoint on the configured port that Prometheus can scrape. The endpoint is on the machine's network, not on your tailnet. It listens on `localhost` by default, which isn't reachable from outside a container, so containers need `OTEL_EXPORTER_PROMETHEUS_HOST=0.0.0.0`.

### Traces

tsiam creates a span for every request. When a node on your tailnet sends a `traceparent` header, tsiam's span becomes part of the caller's trace.

Requests through Tailscale Funnel always start a new trace, and the caller's span (if any) is only linked to it, so clients on the internet can't choose trace IDs or the sampling of their requests.

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
