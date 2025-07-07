# Polly

A GitHub App that validates pull requests against Open Policy Agent (OPA) policies. Polly creates GitHub check runs based on policy evaluation results, helping enforce compliance requirements before merging.

## Quick Start

### Prerequisites
- Go 1.21+
- OPA server running on `localhost:8181`
- GitHub App with appropriate permissions

### Configuration
Set environment variables:
```bash
POLLY_GITHUB_APP_ID=your_app_id
POLLY_GITHUB_INSTALLATION_ID=your_installation_id
POLLY_GITHUB_PRIVATE_KEY_PATH=/path/to/private-key.pem
POLLY_OPA_SERVER_URL=http://localhost:8181

# OpenTelemetry Configuration (optional)
POLLY_OTLP_ENABLED=true
POLLY_OTLP_ENDPOINT=localhost:4317
POLLY_SERVICE_NAME=polly
POLLY_SERVICE_VERSION=1.0.0
```

### Run
```bash
go run cmd/server/main.go
```

## Architecture

```
GitHub Webhook → Policy Validation → Check Run Result
```

### Core Components
- **Handlers** (`internal/handlers/`) - HTTP endpoints for webhooks
- **Services** (`internal/services/`) - Business logic and orchestration
- **Clients** (`internal/clients/`) - GitHub and OPA API integration
- **Config** (`internal/config/`) - Environment-based configuration

### Policy Integration
Polly evaluates OPA policies at `/v1/data/{bundle}/{rule}` with webhook payloads as input. Policy results determine GitHub check run status (success/failure).

## Development

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for detailed design documentation.

## Observability

Polly includes comprehensive OpenTelemetry tracing for HTTP requests, business logic, and external API calls. All GitHub API calls, OPA policy evaluations, and webhook processing are automatically traced.

**Quick Setup:**
```bash
# Enable OTLP export (optional)
export POLLY_OTLP_ENABLED=true
export POLLY_OTLP_ENDPOINT=localhost:4317

# For local development, use stdout traces
export POLLY_OTLP_ENABLED=false
```

See [`docs/OBSERVABILITY.md`](docs/OBSERVABILITY.md) for complete setup with Jaeger, trace attributes, and performance monitoring.
