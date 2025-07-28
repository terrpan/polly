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

# Storage Configuration (optional)
POLLY_STORAGE_TYPE=memory          # Options: memory, valkey (default: memory)
POLLY_VALKEY_ADDRESS=localhost:6379
POLLY_VALKEY_USERNAME=
POLLY_VALKEY_PASSWORD=
POLLY_VALKEY_DB=0

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
- **Storage** (`internal/storage/`) - Configurable storage abstraction (memory/Valkey)
- **Config** (`internal/config/`) - Environment-based configuration

### Policy Integration
Polly evaluates OPA policies at `/v1/data/{bundle}/{rule}` with webhook payloads as input. Policy results determine GitHub check run status (success/failure).

See [`opa/opa.md`](tools/opa/opa.md) for policy details and examples.

## Storage

Polly uses a flexible storage abstraction to maintain PR context and check run state across GitHub webhook events. The storage layer supports multiple backends:

### Memory Storage (Default)
- **Use Case**: Local development and testing
- **Features**: Fast, no external dependencies
- **Limitations**: Data lost on restart, single instance only

### Valkey Storage
- **Use Case**: Production deployments
- **Features**: Persistent, supports multiple instances, automatic expiration
- **Requirements**: Valkey/Redis server

```bash
# Use memory storage (default)
POLLY_STORAGE_TYPE=memory

# Use Valkey storage
POLLY_STORAGE_TYPE=valkey
POLLY_VALKEY_ADDRESS=localhost:6379
POLLY_VALKEY_USERNAME=your_username
POLLY_VALKEY_PASSWORD=your_password
POLLY_VALKEY_DB=0
```

The storage layer manages:
- **PR Context**: SHA → PR number mappings for connecting workflow events to pull requests
- **Check Run State**: Vulnerability and license check run IDs for proper GitHub integration
- **Workflow State**: Workflow run IDs for handling re-runs and concurrent processing

See [`docs/STORAGE.md`](docs/STORAGE.md) for detailed storage architecture and configuration options.

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
│   ├── services/         # Core business logic (checks, policy, security, state)
│   └── storage/          # Storage abstraction layer (memory, Valkey)
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
- **[Webhook Development Guide](docs/WEBHOOK_DEVELOPMENT_GUIDE.md)** - Developer guide for working with the refactored webhook system
- **[Code Quality Improvements](docs/CODE-QUALITY-IMPROVEMENTS.md)** - Details of function length fixes and duplication elimination
- **[Observability](docs/OBSERVABILITY.md)** - OpenTelemetry setup and monitoring
- **[CI Pipeline](docs/CI-PIPELINE.md)** - Continuous integration configuration

## Recent Improvements

### Code Quality & Maintainability Improvements
The webhook handling system has undergone significant refactoring to improve code quality and maintainability:

- **Function Length Compliance**: All handler functions now comply with <80 line limit (funlen linter)
- **Eliminated Code Duplication**: Removed ~300+ lines of duplicate code through shared helper functions
- **Standardized Processing**: Created `PolicyProcessingResult` and `WebhookProcessingConfig` types for consistent data handling
- **Shared Helper Functions**: Extracted common logic into reusable functions in `helpers.go`
- **Enhanced Testing**: All existing tests pass with additional coverage for new shared functions
- **Zero Regressions**: Maintained full backward compatibility with improved internal structure
- **Backward Compatibility**: All existing APIs remain unchanged
- **Better Observability**: Consistent tracing patterns across all webhook operations

For detailed information, see the [Refactoring Summary](REFACTORING_SUMMARY.md).

## TODOs and Future Work
- [x] Implement ValKey for persistent PR context storage
    - [x] Add otel to ValKey
    - [x] Add tests for ValKey integration
    - [x] Add support for ValKey sentinel
    - [x] Add Valkey compression for performance
- [x] Refactor webhook handler for better maintainability
    - [x] Split monolithic webhook.go into event-specific handlers
    - [x] Centralize tracing utilities and shared processing functions
    - [x] Implement modular architecture with clear separation of concerns
    - [x] Maintain backward compatibility with existing APIs
- [ ] Improve security and credential handling
    - [ ] Implement configuration sanitization for safe logging
    - [ ] Audit and fix credential exposure in logs and error messages
    - [ ] Add security tests to prevent credential leaks
- [ ] Extend refactoring patterns to other components
    - [ ] Apply similar modular patterns to services layer
    - [ ] Create shared utilities for consistent error handling
    - [ ] Implement consistent logging patterns across all components
- [ ] Improve Observability with Prometheus metrics
- [ ] Add integration tests for refactored webhook handlers
- [ ] Implement event queuing for better event handling
- [ ] Split server/reception and worker into separate components for scalability
- [ ] Add support for validating workflow settings and inputs
