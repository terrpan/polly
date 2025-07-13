# Polly

[![Test](https://github.com/terrpan/polly/actions/workflows/test.yml/badge.svg)](https://github.com/terrpan/polly/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/terrpan/polly)](https://goreportcard.com/report/github.com/terrpan/polly)
[![codecov](https://codecov.io/gh/terrpan/polly/branch/main/graph/badge.svg)](https://codecov.io/gh/terrpan/polly)

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

See [`opa/opa.md`](tools/opa/opa.md) for policy details and examples.

## Development

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for detailed design documentation.

See [`docs/opa/opa.md`](docs/opa/opa.md) for OPA-specific information.

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

## Project Directory Structure

```
polly/
├── cmd/                  # Application entrypoints (main.go)
├── internal/             # Private application and business logic
│   ├── app/              # App container, middleware, server setup
│   ├── clients/          # External service clients (GitHub, OPA)
│   ├── config/           # Configuration and logger
│   ├── handlers/         # HTTP handlers (webhook, health)
│   ├── otel/             # OpenTelemetry integration
│   └── services/         # Core business logic (checks, policy, security)
├── pkg/                  # Public Go packages (if any)
├── tools/                # Development tools, local infrastructure configs, and OPA policies
│   ├── docker-compose.yml
│   ├── otelcol.yaml
│   └── opa/              # OPA policies and related files
├── docs/                 # Documentation and architecture decision records
├── .github/              # GitHub Actions workflows, PR templates
├── go.mod, go.sum        # Go module files
├── README.md             # Project overview and badges
└── ...                   # Other project files
```

- Place all development and infrastructure tools (Docker Compose, OTel config, OPA policies, etc.) in the `tools/` directory.
- See `docs/` for architecture and CI documentation.

## Documentation

- **[Architecture Overview](docs/ARCHITECTURE.md)** - System architecture and component overview
- **[Check Run Flow](docs/CHECK-RUN-FLOW.md)** - Detailed explanation of the security check run system
- **[Observability](docs/OBSERVABILITY.md)** - OpenTelemetry setup and monitoring
- **[CI Pipeline](docs/CI-PIPELINE.md)** - Continuous integration configuration

## TODOs and Future Work
- [ ] Implement ValKey for persistent PR context storage
- [ ] Improve Observability with Prometheus metrics
- [ ] Add integration tests
- [ ] Implement event queuing for better event handling
- [ ] Split server/reception and worker into separate components for scalability
- [ ] Add support for validating workflow settings and inputs
