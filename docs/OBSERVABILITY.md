# OpenTelemetry Observability

Polly includes comprehensive OpenTelemetry (OTEL) tracing for full observability across HTTP requests, business logic, and external API calls. All manual spans are created via a `TelemetryHelper` which standardizes span attributes and error recording.

## Features

- **Auto-Instrumentation**: HTTP server and client requests (GitHub API, OPA) are automatically traced
- **Manual Spans**: Business logic operations include detailed tracing with relevant attributes
- **Context Propagation**: Trace context flows through the entire request lifecycle
- **Structured Logging Integration**: OTEL errors and debug info use your configured structured logger

## Trace / Span Hierarchy (Representative)

```
webhook.handle (root span)
├── webhook.handle_pull_request
│   ├── checks.create_policy_check
│   │   └── [GitHub API: POST /repos/{owner}/{repo}/check-runs]
│   ├── checks.start_policy_check
│   │   └── [GitHub API: PATCH /repos/{owner}/{repo}/check-runs/{id}]
│   ├── policy.evaluate
│   │   └── [OPA API: POST /v1/data/{policy_path}]
│   └── checks.complete_policy_check
│       └── [GitHub API: PATCH /repos/{owner}/{repo}/check-runs/{id}]
```

## Setup with OTLP Collector

### 1. Start OTLP Collector (Docker)
```bash
# docker-compose.yml
version: '3.8'
services:
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"
      - "14250:14250"

  otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    command: ["--config=/etc/otel-collector-config.yaml"]
    volumes:
      - ./otel-collector-config.yaml:/etc/otel-collector-config.yaml
    ports:
      - "4317:4317"   # OTLP gRPC receiver
      - "4318:4318"   # OTLP HTTP receiver
    depends_on:
      - jaeger

# Start with: docker-compose up -d
```

### 2. OTLP Collector Configuration
```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:

exporters:
  jaeger:
    endpoint: jaeger:14250
    tls:
      insecure: true

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [jaeger]
```

### 3. Configure Polly
```bash
# Enable OTLP export
export POLLY_OTLP_ENABLED=true
export POLLY_OTLP_ENDPOINT=localhost:4317

# Start Polly
go run cmd/server/main.go
```

### 4. View Traces
- **Jaeger UI**: http://localhost:16686
- **Service**: Select "polly" from the service dropdown
- **Operations**: View traces for `webhook.handle`, `health.handle`, etc.

## Local Development (Stdout Traces)

For local development without an OTLP collector:

```bash
# Disable OTLP, use stdout exporter
export POLLY_OTLP_ENABLED=false

# Traces will be logged through your structured logger
go run cmd/server/main.go
```

## Trace Attributes

Polly includes rich trace attributes for filtering and analysis. Errors are consistently annotated using `telemetry.SetErrorAttribute(span, err)` for improved filtering.

### GitHub Operations
```
github.owner: "octocat"
github.repo: "hello-world"
github.sha: "abc123def456"
github.check_run_id: 42
pr.number: 15
pr.action: "opened"
```

### Policy Evaluation
```
policy.path: "/v1/data/playground/hello"
policy.type: "hello"
policy.result: true
opa.response_code: 200
opa.timeout: "5s"
```

### Health Checks
```
health.status: "healthy"
service.name: "polly"
service.version: "1.0.0"
opa.status: "healthy"
```

## Performance Monitoring

Use traces to identify bottlenecks:

1. **GitHub API Latency** - Auto-instrumented HTTP calls show response times
2. **OPA Policy Evaluation** - Manual spans track policy execution duration
3. **Overall Request Processing** - End-to-end webhook processing time
4. **Error Rates** - Failed spans indicate error conditions

## Troubleshooting

### OTLP Connection Issues

```bash
# Check if collector is running
curl -i http://localhost:4318/v1/traces

# View logs for connection errors
{"level":"ERROR","msg":"OpenTelemetry error","error":"connection refused"}
```

**Solution**: Ensure OTLP collector is running or set `POLLY_OTLP_ENABLED=false`

### Missing Traces

1. **Verify Configuration**:
   ```bash
   echo $POLLY_OTLP_ENABLED
   echo $POLLY_OTLP_ENDPOINT
   ```

2. **Check Logs**:
   ```bash
   {"level":"INFO","msg":"OpenTelemetry initialized successfully"}
   ```

3. **Test with Health Endpoint**:
   ```bash
   curl http://localhost:8080/health
   # Should generate traces
   ```

## Performance Testing

For load testing with tracing enabled, see performance testing tools like k6, Hey, or Artillery.js that can generate webhook traffic while you monitor traces for bottlenecks.
