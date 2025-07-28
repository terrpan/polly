# ADR-009: Concurrent Security Policy Processing and Sequential GitHub API Operations

## Status
Accepted

## Context
The security policy processing system had two performance issues that needed to be addressed:

1. **Sequential Policy Processing**: Vulnerability and SBOM (Software Bill of Materials) checks were executing sequentially, causing unnecessary delays in security validation workflows. OpenTelemetry trace analysis revealed total processing times of ~1000ms when they could complete in ~60ms with concurrent execution.

2. **Concurrent GitHub API Issues**: GitHub check run creation was implemented concurrently, causing context cancellation errors and API rate limiting issues due to the external I/O nature of GitHub API calls.

### Sequential Policy Processing Problem
The sequential processing occurred in the `processWorkflowSecurityArtifacts` function in `internal/handlers/artifact_processors.go`:

```go
// BEFORE: Sequential processing
if config.CheckVuln && len(vulnPayloads) > 0 {
    if err := h.processVulnerabilityArtifacts(ctx, config, vulnPayloads); err != nil {
        return err
    }
}

if config.CheckLicense && len(sbomPayloads) > 0 {
    if err := h.processLicenseArtifacts(ctx, config, sbomPayloads); err != nil {
        return err
    }
}
```

### Concurrent GitHub API Problem
The concurrent check run creation in `CreateSecurityCheckRuns` function caused context cancellation:

```go
// PROBLEMATIC: Concurrent GitHub API calls
tasks := make([]func() error, len(checkTypes))
// ... populate tasks with GitHub API calls
errs := utils.ExecuteConcurrently(tasks) // Causes context cancellation
```

## Decision
Implement a hybrid approach that optimizes based on operation type:
- **CPU-bound operations (policy processing)**: Execute concurrently for performance
- **I/O-bound operations (GitHub API calls)**: Execute sequentially for reliability

### Architecture Changes

#### 1. Concurrent Policy Processing
Modified `processWorkflowSecurityArtifacts` to use concurrent task execution for CPU-intensive policy evaluation:

```go
// AFTER: Concurrent policy processing
var tasks []func() error

// Add vulnerability check task if requested
if config.CheckVuln && len(vulnPayloads) > 0 {
    tasks = append(tasks, func() error {
        return h.processVulnerabilityArtifacts(ctx, config, vulnPayloads)
    })
}

// Add license check task if requested
if config.CheckLicense && len(sbomPayloads) > 0 {
    tasks = append(tasks, func() error {
        return h.processLicenseArtifacts(ctx, config, sbomPayloads)
    })
}

// Execute policy checks concurrently
if len(tasks) > 0 {
    errs := utils.ExecuteConcurrently(tasks)
    for _, err := range errs {
        if err != nil {
            return fmt.Errorf("concurrent policy processing failed: %w", err)
        }
    }
}
```

#### 2. Sequential GitHub API Operations
Modified `CreateSecurityCheckRuns` to process GitHub API calls sequentially:

```go
// AFTER: Sequential GitHub API processing
checkTypes := s.getSecurityCheckTypes(ctx, owner, repo, sha)

// Process check run creation sequentially to avoid GitHub API rate limits
// and context cancellation issues
for _, ct := range checkTypes {
    checkRun, err := ct.create()
    if err != nil {
        return fmt.Errorf("failed to create %s check: %w", ct.name, err)
    }

    if err := ct.start(checkRun.GetID()); err != nil {
        return fmt.Errorf("failed to start %s check: %w", ct.name, err)
    }

    ct.store(checkRun.GetID())
}
```

## Rationale

### Performance Optimization Strategy
- **CPU-bound Concurrency**: Policy evaluations benefit from parallel execution as they are computationally intensive and independent
- **I/O-bound Sequential**: GitHub API calls require sequential processing to avoid rate limits and context cancellation

### Design Principles Applied
1. **Operation-Specific Optimization**: Different concurrency strategies based on operation characteristics
2. **Reliability First**: GitHub API reliability prioritized over marginal performance gains
3. **Resource Awareness**: Respect external service limits and constraints
4. **Error Isolation**: Maintain clear error boundaries and context

### Alignment with Project Guidelines
- **Existing Patterns**: Uses the project's established `utils.ExecuteConcurrently` utility
- **Function Length Compliance**: Maintains functions under 80 lines as required by golangci-lint
- **Error Handling Consistency**: Preserves existing error wrapping and context patterns
- **Tracing Compatibility**: Maintains OpenTelemetry tracing without modification

## Consequences

### Positive
- **Faster Policy Processing**: Concurrent execution reduces policy evaluation time from ~1000ms to ~60ms
- **Reliable GitHub Integration**: Sequential API calls eliminate context cancellation errors
- **Better Resource Efficiency**: Parallel execution maximizes CPU utilization for policy evaluation
- **Clear Architectural Pattern**: Establishes principle for future I/O vs CPU-bound operation decisions

### Negative
- **GitHub API Latency**: Sequential check run creation may add latency (typically 2-3 API calls @ ~100ms each)
- **Increased Complexity**: Different concurrency strategies for different operation types
- **Debugging Complexity**: Mixed sequential/concurrent patterns require careful tracing

### Mitigation Strategies
- **Structured Logging**: Detailed logging in both concurrent and sequential operations
- **OpenTelemetry Tracing**: Monitor performance characteristics of both approaches
- **Error Context**: Preserve error context to identify specific failures
- **Performance Monitoring**: Track GitHub API response times and policy processing duration

## Implementation Status
- ✅ Concurrent policy processing implemented in `processWorkflowSecurityArtifacts`
- ✅ Sequential GitHub API operations implemented in `CreateSecurityCheckRuns`
- ✅ Existing test suite passes with hybrid implementation
- ✅ Error handling patterns preserved for both approaches
- ✅ OpenTelemetry tracing compatibility maintained

## Performance Verification
Verify implementation through OpenTelemetry traces:
- **Policy Processing**: Vulnerability and SBOM spans show overlapping execution (~60ms total)
- **GitHub API**: Check run creation spans show sequential execution without context cancellation
- **Overall Flow**: Total processing time optimized while maintaining reliability

## Architectural Pattern Established
This ADR establishes the following pattern for future development:

**CPU-Bound Operations**: Use `utils.ExecuteConcurrently` for parallel execution
- Policy evaluations
- Data transformations
- Computational operations

**I/O-Bound Operations**: Use sequential processing for reliability
- External API calls (GitHub, third-party services)
- Database operations under high concurrency
- File system operations with potential conflicts

## Future Considerations
- **GitHub API Optimization**: Consider batch operations if GitHub API supports them
- **Policy Processing Scaling**: Monitor OPA server performance under concurrent load
- **Circuit Breakers**: Implement circuit breaker patterns for external API calls
- **Metrics Collection**: Add operation-specific metrics for both concurrent and sequential patterns
