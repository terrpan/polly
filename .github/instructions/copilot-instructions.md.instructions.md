---
applyTo: '**'
---
Provide project context and coding guidelines that AI should follow when generating code, answering questions, or reviewing changes.

# Project Overview
A GitHub App that validates pull requests against Open Policy Agent (OPA) policies. Polly creates GitHub check runs based on policy evaluation results, helping enforce compliance requirements before merging.

## Architecture & Key Components

### Service Layer Pattern (`internal/services/`)
- **Constructor Pattern**: All services use `NewXxxService(dependencies...) *XxxService`
- **Dependency Injection**: Services injected via `internal/app/container.go` with clear dependency graph
- **Interface Segregation**: Use `PolicyServiceInterface` for testing - see `internal/handlers/helpers_test.go`

### Webhook Handler Architecture (`internal/handlers/`)
- **Event-Specific Handlers**: `webhook_pullrequest.go`, `webhook_checkrun.go`, `webhook_workflow.go`
- **Strategy Pattern**: Policy processing uses `PolicyProcessor` interface - see `VulnerabilityPolicyProcessor`
- **Shared Infrastructure**: All common logic in `helpers.go` with `BaseWebhookHandler` and `SecurityWebhookHandler`
- **Function Length Rule**: Keep all functions under 80 lines (enforced by golangci-lint)

### Critical Data Flow
```
GitHub Webhook → WebhookRouter → Event Handler → SecurityService → PolicyService → OPA → Check Results
```

## Development Workflows

### Testing Strategy
```bash
# Unit tests only (fast)
go test -short ./...

# All tests (includes integration with testcontainers)
go test ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
```

### Testing Patterns
- **Unit vs Integration**: Use `testing.Short()` to distinguish - integration tests skipped with `-short`
- **Mocking**: Create interfaces for external dependencies (see `PolicyServiceInterface`)
- **Testify Suites**: Use `github.com/stretchr/testify/suite` for complex test setups

### Code Quality
```bash
# Run linter (fixes function length, duplication, etc)
golangci-lint run

# Key rules: funlen (<80 lines), dupl (no code duplication), errcheck
```

## Project-Specific Patterns

### Strategy Pattern Implementation
- **Policy Processing**: `VulnerabilityPolicyProcessor` and `LicensePolicyProcessor` implement `PolicyProcessor`
- **Result Standardization**: All policy results use `PolicyProcessingResult` struct
- **Extension Point**: Add new policy types by implementing `PolicyProcessor` interface

### Error Handling & Logging
- **Structured Logging**: Use `slog.Logger` with context - `logger.ErrorContext(ctx, "message", "key", value)`
- **OpenTelemetry**: Use `TracingHelper` for consistent span creation in webhook handlers
- **Error Wrapping**: Always wrap errors with context - `fmt.Errorf("operation failed: %w", err)`

### Storage Abstraction
- **Factory Pattern**: `storage.NewStore(config)` supports memory/Valkey backends
- **Interface**: All storage operations through `storage.Store` interface
- **State Management**: Use `StateService` for check run ID storage and retrieval

### Go File Layout (Enforced)
1. package declaration
2. imports
3. const blocks (exported first)
4. var blocks (exported first)
5. type declarations (interfaces → structs → aliases)
6. constructor functions (NewXxx)
7. methods on core types
8. package‑level functions
9. init() (if needed; at bottom)
10. main() (in package main; last)

## Documentation Requirements
- **ADRs**: Create architectural decision records in `docs/` for significant changes
- **Pattern Documentation**: Update development guides when introducing new patterns
- **Integration Points**: Document external service integrations in architecture docs
