---
applyTo: '**'
---
Provide project context and coding guidelines that AI should follow when generating code, answering questions, or reviewing changes.

# Project Overview
A GitHub App that validates pull requests against Open Policy Agent (OPA) policies. Polly creates GitHub check runs based on policy evaluation results, helping enforce compliance requirements before merging.

## Architecture & Key Components

### Service Layer Pattern (`internal/services/`)
- **Constructor Pattern**: All services use `NewXxxService(dependencies...) *XxxService`
- **Service Registry**: Services managed via registry pattern in `internal/app/container.go` - see [Container Development Guide](docs/CONTAINER_DEVELOPMENT_GUIDE.md)
- **Easy Service Addition**: Adding services requires only one registration entry in `createServiceRegistrations()`
- **Private Encapsulation**: Internal services are private fields, only handlers exported for external access
- **Type Safety**: All dependencies are concrete types with compile-time checking
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

- Always start with a new branch: `git checkout -b feature/your-feature-name` instead of `main`
- Use conventional commit messages: `feat: add new policy`, `fix: correct validation logic`

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

### Code Reuse & Architecture Patterns
- **DRY Principle**: Before implementing new functionality, always check for existing similar code that can be reused or extended
- **Delegation Pattern**: Prefer composition and delegation over inheritance - new handlers should delegate to existing handlers rather than reimplementing logic
- **Handler Architecture**:
  - New webhook handlers should embed or compose existing handlers (`SecurityWebhookHandler`, `CheckRunHandler`)
  - Use `BaseWebhookHandler` for shared dependencies, not direct service injection
  - Follow pattern: `NewXxxHandler(base *BaseWebhookHandler) *XxxHandler`
- **Service Reuse**: Before adding new service methods, check if existing methods can be reused with configuration parameters
- **State Management**: Follow existing state service patterns exactly - don't create new storage patterns
- **Integration Strategy**: New features should integrate with existing infrastructure rather than creating parallel implementations

### Implementation Guidelines
- **Start with Existing Code Analysis**: Before proposing new code, identify what existing handlers/services can be reused
- **Minimal Implementation Principle**: Aim for <100 lines of new code when adding orchestration features
- **Composition Over Implementation**: New handlers should coordinate existing functionality, not reimplement it
- **Test Pattern Reuse**: Copy and modify existing test patterns rather than creating new test infrastructure

### Examples of Correct Patterns
```go
// ✅ GOOD: Delegates to existing handlers
type CheckSuiteWebhookHandler struct {
    *SecurityWebhookHandler
    checkRunHandler *CheckRunHandler
}

func (h *CheckSuiteWebhookHandler) rerunExistingChecks(...) error {
    return h.checkRunHandler.handleVulnerabilityCheckRerun(...) // Delegates
}

// ❌ BAD: Reimplements existing logic
func (h *CheckSuiteWebhookHandler) rerunExistingChecks(...) error {
    // 200+ lines of duplicated policy processing logic
}
```

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

### Type Safety Philosophy
- **Prioritize Type Safety**: Always prefer compile-time type safety over runtime flexibility
- **Pragmatic Generics**: Use Go generics (type parameters) where they provide clear value without adding complexity
- **Avoid `interface{}`**: Minimize `interface{}` usage - only use at parsing boundaries, not in business logic
- **Type Assertions**: Eliminate runtime type assertions where types are known at compile time
- **Ease of Use**: Choose the simplest solution that provides type safety - don't force generics where concrete types work better

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

## Testing Best Practices

### Testcontainers Usage
- **Container Image Constants**: Always define container images as constants at the top of test files, never hardcode them in test functions
- **Example Pattern**:
  ```go
  const (
      valkeyTestImage = "valkey/valkey:8-alpine"
      opaTestImage    = "openpolicyagent/opa:latest"
  )
  ```
- **Benefits**: Easy version management, consistency across tests, clear visibility of dependencies

## Documentation Requirements
- **ADRs**: Create architectural decision records in `docs/` for significant changes
- **Pattern Documentation**: Update development guides when introducing new patterns
- **Integration Points**: Document external service integrations in architecture docs
