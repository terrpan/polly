# Webhook Handler Development Guide

## Quick Reference for the Refactored Webhook System

### File Structure

```
internal/handlers/
├── webhook_router.go          # Main event dispatcher
├── webhook_pullrequest.go     # Pull request event handler
├── webhook_checkrun.go        # Check run event handler (reruns)
├── webhook_workflow.go        # Workflow event handler
├── webhook_security.go        # Security check management
└── helpers.go                 # All shared utilities, types, and infrastructure
```

### Common Patterns

#### 1. Creating a New Event Handler

```go
// NewEventHandler creates a new event-specific handler
type EventHandler struct {
    *BaseWebhookHandler
}

func NewEventHandler(base *BaseWebhookHandler) *EventHandler {
    return &EventHandler{
        BaseWebhookHandler: base,
    }
}

func (h *EventHandler) HandleEvent(ctx context.Context, event EventPayload) error {
    ctx, span := h.telemetry.StartSpan(ctx, "event.handle_event")
    defer span.End()

    // Add tracing attributes
    span.SetAttributes(
        attribute.String("event.type", "example"),
        attribute.String("event.action", event.Action),
    )

    // Your handler logic here
    return nil
}
```

#### 2. Using Shared Telemetry

```go
// In any handler method
ctx, span := h.telemetry.StartSpan(ctx, "operation.name")
// On error
if err != nil { h.telemetry.SetErrorAttribute(span, err) }
defer span.End()

// Add attributes
span.SetAttributes(
    attribute.String("github.owner", owner),
    attribute.String("github.repo", repo),
    attribute.String("github.sha", sha),
)
```

#### 3. Using Security Check Manager

```go
// Create security checks
err := h.securityCheckMgr.CreateSecurityCheckRuns(ctx, owner, repo, sha, prNumber)

// Complete checks as neutral (no artifacts)
err := h.securityCheckMgr.CompleteSecurityChecksAsNeutral(ctx, owner, repo, sha)
```

#### 4. Using Shared Processing Functions

```go
// Use standardized configuration type
config := WebhookProcessingConfig{
    Owner:    owner,
    Repo:     repo,
    SHA:      sha,
    PRNumber: prNumber,
}

// Process vulnerability policies with shared types
result, err := processVulnerabilityPolicies(ctx, h.policyService, vulnPayloads, owner, repo, sha)
if err != nil {
    return err
}

// Build standardized check result
checkResult := buildVulnerabilityCheckResult(result)

// Post comments using shared functions
err = postVulnerabilityComments(ctx, h.commentService, result, owner, repo, prNumber)

// Process license policies (similar pattern)
result, err := processLicensePolicies(ctx, h.policyService, sbomPayloads, owner, repo, sha)
```

#### 5. Using Shared Types for Consistency

```go
// PolicyProcessingResult provides standardized policy evaluation results
type PolicyProcessingResult struct {
    AllPassed           bool
    Violations          []VulnerabilityPolicyVuln  // For vulnerability checks
    ConditionalComponents []SBOMPolicyComponent     // For license checks  
    Summary             string
    Details             string
}

// WebhookProcessingConfig standardizes common parameters
type WebhookProcessingConfig struct {
    Owner    string
    Repo     string
    SHA      string
    PRNumber int64
}
```

### Component Responsibilities

#### WebhookRouter
- Parses incoming GitHub webhook events
- Routes to appropriate event-specific handlers  
- Maintains backward compatibility

#### Event-Specific Handlers
- **PullRequestHandler**: Handle PR opened/reopened/synchronize events
- **CheckRunHandler**: Handle check run rerequests, restart checks with stored artifacts
- **WorkflowHandler**: Handle workflow started/completed events, process security artifacts

#### SecurityCheckManager
- Centralized management of security check lifecycle
- Create and start vulnerability and license checks concurrently
- Complete checks as neutral when no artifacts are available

#### Shared Utilities (`helpers.go`)
- **Infrastructure**: `BaseWebhookHandler`, `TelemetryHelper`, `SecurityCheckManager` for common dependencies
- **Processing Functions**: `processVulnerabilityPolicies()`, `processLicensePolicies()` with standardized `PolicyProcessingResult`
- **Comment Management**: `postVulnerabilityComments()`, `postLicenseComments()` for consistent PR feedback
- **Check Result Building**: `buildVulnerabilityCheckResult()`, `buildLicenseCheckResult()` for standardized GitHub check runs
- **Configuration Types**: `WebhookProcessingConfig` for common webhook parameters
- **Artifact Processing**: `processWorkflowSecurityArtifacts()`, `processVulnerabilityArtifacts()`, `processLicenseArtifacts()`
- **State Management**: `findVulnerabilityCheckRun()`, `findLicenseCheckRun()`, `storeCheckRunID()` helpers
- **Benefits**: Function length compliance (all functions <80 lines), eliminates ~300+ lines of duplicate code, single source of truth
- **TelemetryHelper**: Consistent OpenTelemetry tracing & error attributes (supersedes deprecated TracingHelper)
- **BaseWebhookHandler**: Common dependencies and utility methods
- **Processing Functions**: Shared vulnerability and license processing logic (all consolidated in `helpers.go`)

### Testing Patterns

#### Testing Event Handlers

```go
func TestEventHandler(t *testing.T) {
    // Create base handler with mocked dependencies
    base := &BaseWebhookHandler{
        logger:          testLogger,
        policyService:   mockPolicyService,
        // ... other dependencies
    }

    handler := NewEventHandler(base)

    // Test the handler
    err := handler.HandleEvent(ctx, testEvent)
    assert.NoError(t, err)
}
```

#### Testing Security Check Manager

```go
func TestSecurityCheckManager(t *testing.T) {
    mgr := NewSecurityCheckManager(testLogger, mockCheckService, mockStateService)

    err := mgr.CreateSecurityCheckRuns(ctx, "owner", "repo", "sha", 123)
    assert.NoError(t, err)
}
```

### Migration Guide

#### Adding New Event Types

1. Create new handler file: `webhook_newevent.go`
2. Implement handler struct extending `BaseWebhookHandler`
3. Add handler creation to `WebhookRouter.NewWebhookRouter()`
4. Add event routing in `WebhookRouter.HandleWebhook()`
5. Add tests for the new handler

#### Extending Existing Handlers

1. Add new methods to the appropriate handler struct
2. Use existing patterns (tracing, error handling, logging)
3. Reuse shared utilities where applicable
4. Add corresponding tests

#### Adding New Shared Utilities

1. Add to `helpers.go` for all webhook-related utilities and processing functions
2. Update `BaseWebhookHandler` if new dependencies are needed
3. Ensure all handlers can access the new utilities
4. Update tests in `helpers_test.go`

### Best Practices

1. **Use Consistent Tracing**: Always use `TelemetryHelper` for span creation & error attributes
2. **Follow Error Patterns**: Log errors with context, return meaningful error messages
3. **Leverage Shared Functions**: Reuse processing logic from `helpers.go` to maintain consistency and avoid duplication
4. **Use Standardized Types**: Prefer `PolicyProcessingResult` and `WebhookProcessingConfig` for consistent data structures
5. **Function Length Compliance**: Keep functions under 80 lines by extracting shared helpers when needed
6. **Test Independently**: Each handler should be testable in isolation
7. **Maintain Backward Compatibility**: Changes should not break existing APIs
8. **Document Changes**: Update architecture docs when adding new patterns

### Shared Processing Best Practices

1. **Policy Processing**: Use `processVulnerabilityPolicies()` and `processLicensePolicies()` instead of inline policy evaluation
2. **Comment Management**: Use `postVulnerabilityComments()` and `postLicenseComments()` for consistent PR feedback
3. **Check Results**: Use `buildVulnerabilityCheckResult()` and `buildLicenseCheckResult()` for standardized GitHub check runs
4. **Configuration Reuse**: Pass `WebhookProcessingConfig` instead of individual owner/repo/sha parameters
5. **Error Handling**: Shared functions provide consistent error handling and logging patterns

### Common Gotchas

1. **Event Info Extraction**: Use `getEventInfo()` helper for consistent event data extraction
2. **Concurrent Processing**: Use `utils.ExecuteConcurrently()` for parallel operations
3. **State Management**: Always store and retrieve state using the `StateService`
4. **Check Run IDs**: Store check run IDs immediately after creation for later retrieval
5. **PR Context**: Handle cases where PR context might not exist (workflow events without associated PRs)

### Performance Considerations

1. **Concurrent Operations**: Security checks are created and processed concurrently
2. **Shared Processing**: Common logic is executed once and reused
3. **Minimal Allocations**: Reuse slices and avoid unnecessary allocations in hot paths
4. **Efficient Logging**: Use structured logging with appropriate log levels
5. **Span Management**: Ensure spans are properly closed to avoid memory leaks

This guide should help developers work effectively with the refactored webhook system while maintaining consistency and best practices.
