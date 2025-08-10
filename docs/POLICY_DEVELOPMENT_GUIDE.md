# Policy Development Guide

## Overview

This comprehensive guide explains how to implement new policy types in Polly and documents the policy caching implementation. The system uses a **Strategy Pattern** with **Factory Registry** for extensible policy evaluation while maintaining type safety, consistent telemetry, and performance optimization through caching.

## Architecture Overview

### Core Components

1. **PolicyEvaluator Interface**: Defines the contract for policy evaluation strategies
2. **PolicyService**: Core service for pure policy evaluation with OPA integration
3. **PolicyCacheService**: Wrapper service that adds caching functionality to PolicyService
4. **Policy Processors**: Strategy implementations for webhook-level policy processing
5. **Helper Functions**: Utility functions for data transformation and payload building
6. **Telemetry Integration**: Consistent observability across all policy types

For broader architectural rationale (strategy vs factory distinctions, future enhancement opportunities) see the complementary [Architecture Patterns Guide](./ARCHITECTURE_PATTERNS.md). This guide focuses on concrete implementation; the patterns guide explains why certain abstractions were chosen and when to extend them.

### Current Policy Types

- **Vulnerability Policies**: Evaluate security vulnerabilities using Trivy JSON reports
- **SBOM/License Policies**: Evaluate software bill of materials and license compliance using SPDX documents

## Policy Cache Implementation

### Implementation Overview

We have successfully implemented a comprehensive policy caching solution that respects configuration settings and maintains clean architecture patterns.

### Key Components

#### 1. PolicyCacheService (`internal/services/policy_cache.go`)

A new service layer that wraps the core PolicyService and adds caching functionality:

- **CheckVulnerabilityPolicyWithCache()**: Cached vulnerability policy evaluation
- **CheckSBOMPolicyWithCache()**: Cached SBOM policy evaluation
- Configuration-aware caching (only caches when `config.AppConfig.Storage.PolicyCache.Enabled` is true)
- Uses repository context (owner, repo, sha) as cache keys
- Implements proper OpenTelemetry tracing with cache hit/miss tracking

#### 2. Clean Architecture Restoration

**PolicyService** (`internal/services/policy.go`):
- Reverted to clean architecture with only OPAClient and Logger dependencies
- Pure policy evaluation without coupling to StateService
- Single responsibility principle maintained

**Container** (`internal/app/container.go`):
- Added PolicyCacheService to dependency injection
- Proper separation of concerns between PolicyService and PolicyCacheService

#### 3. Handler-Level Integration

**BaseWebhookHandler** (`internal/handlers/helpers.go`):
- Added PolicyCacheService as a dependency alongside existing PolicyService
- Both services available for different use cases

**Policy Processors** (`internal/handlers/policy_processing.go`):
- Updated strategy pattern to use PolicyCacheServiceInterface
- ProcessPayloads methods now use cached policy evaluation
- Configuration-aware caching built into the workflow

#### 4. Configuration Integration

The cache respects the existing configuration:
```go
if config.AppConfig.Storage.PolicyCache.Enabled {
    // Cache operations only happen when enabled
}
```

### Cache Flow

1. **Cache Check**: When a policy evaluation is requested, first check if cached results exist
2. **Cache Miss**: If no cache hit, evaluate policy using the core PolicyService
3. **Cache Store**: Store the policy results (not raw artifacts) with TTL
4. **Cache Hit**: Return cached results with telemetry marking

### Benefits

#### 1. Performance
- Eliminates redundant OPA policy evaluations for the same commit
- Significant performance improvement for GitHub re-runs
- Maintains existing functionality while adding caching layer

#### 2. Clean Architecture
- PolicyService remains pure and focused on policy evaluation
- Caching is a separate concern handled by PolicyCacheService
- No coupling violations between services

#### 3. Configuration Respect
- Cache behavior controlled by existing config settings
- Can be disabled/enabled without code changes
- Follows established configuration patterns

#### 4. Observability
- OpenTelemetry tracing for cache operations
- Cache hit/miss metrics available
- Proper logging for debugging

### Key Design Decisions

#### 1. Wrapper Service Pattern
Instead of modifying PolicyService directly, we created PolicyCacheService as a wrapper. This:
- Preserves clean architecture
- Allows both cached and non-cached usage
- Maintains backwards compatibility

#### 2. Handler-Level Caching
Cache logic is implemented at the handler level where repository context naturally exists:
- Handlers have access to owner/repo/sha for cache keys
- Avoids passing repository context through service layers
- Maintains proper separation of concerns

#### 3. PolicyResult Caching
We cache the processed PolicyResults rather than raw artifacts:
- More efficient storage
- Cached data matches actual usage patterns
- Avoids re-processing cached artifacts

### Configuration

The cache uses existing configuration structure:
```yaml
storage:
  policy_cache:
    enabled: true
    ttl: "1h"
    max_size: 1000
```

### Usage

The cache is transparent to existing code. Handlers automatically use cached policy evaluation when:
1. PolicyCacheService is available (via dependency injection)
2. Configuration enables caching
3. Repository context is available (owner/repo/sha)

## Implementing New Policy Types

### Step 1: Define Payload Types

Create type-safe structures for your policy input and result in `internal/services/security_types.go`:

```go
// Input payload for your policy
type CustomPolicyPayload struct {
    Metadata PayloadMetadata `json:"metadata"`
    // Your specific fields
    CustomData []CustomItem `json:"custom_data"`
    Summary    CustomSummary `json:"summary"`
}

type CustomItem struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    // Policy-specific fields
    RiskLevel   string `json:"risk_level"`
    Compliance  bool   `json:"compliance"`
}

type CustomSummary struct {
    TotalItems      int `json:"total_items"`
    CompliantItems  int `json:"compliant_items"`
    RiskDistribution map[string]int `json:"risk_distribution"`
}

// Result type for policy evaluation
type CustomPolicyResult struct {
    Compliant            bool                `json:"compliant"`
    TotalItems          int                 `json:"total_items"`
    CompliantItems      int                 `json:"compliant_items"`
    NonCompliantItems   []CustomPolicyItem  `json:"non_compliant_items"`
    Details             []string            `json:"details,omitempty"`
}

type CustomPolicyItem struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    RiskLevel   string `json:"risk_level"`
    Reason      string `json:"reason"`
}
```

### Step 2: Implement PolicyEvaluator

Create a new evaluator in `internal/services/policy.go`:

```go
// CustomPolicyEvaluator handles custom policy evaluation
type CustomPolicyEvaluator struct {
    service *PolicyService
}

func (c *CustomPolicyEvaluator) PolicyType() string {
    return "custom"  // Used for registry key and routing
}

func (c *CustomPolicyEvaluator) PolicyPath() string {
    return "/v1/data/compliance/custom_policy"  // OPA policy path
}

func (c *CustomPolicyEvaluator) Evaluate(ctx context.Context, payload any) (any, error) {
    customPayload, ok := payload.(*CustomPolicyPayload)
    if !ok {
        return nil, fmt.Errorf(
            "%w: expected *CustomPolicyPayload, got %T",
            payload,
        )
    }

    ctx, span := c.service.telemetry.StartSpan(ctx, "policy.check_custom")
    defer span.End()

    c.service.telemetry.SetPolicyAttributes(span, "custom")
    span.SetAttributes(
        attribute.Int("input.item_count", len(customPayload.CustomData)),
        attribute.String("input.scan_target", customPayload.Metadata.ScanTarget),
        attribute.String("input.tool_name", customPayload.Metadata.ToolName),
    )

    c.service.logger.DebugContext(ctx, "Checking custom policy",
        "item_count", len(customPayload.CustomData),
        "scan_target", customPayload.Metadata.ScanTarget,
        "tool_name", customPayload.Metadata.ToolName)

    // Use the generic policy evaluation helper
    result, err := evaluatePolicy[*CustomPolicyPayload, CustomPolicyResult](
        ctx,
        c.service,
        c.PolicyPath(),
        customPayload,
    )

    if err != nil {
        c.service.telemetry.SetErrorAttribute(span, err)
        return result, err
    }

    span.SetAttributes(
        attribute.Bool("result.compliant", result.Compliant),
        attribute.Int("result.total_items", result.TotalItems),
        attribute.Int("result.compliant_items", result.CompliantItems),
    )

    c.service.logger.InfoContext(ctx, "Custom policy evaluation completed",
        "compliant", result.Compliant,
        "total_items", result.TotalItems,
        "compliant_items", result.CompliantItems)

    return result, nil
}
```

### Step 3: Add to Standard Evaluators

Update the `NewStandardEvaluators` function in `internal/services/policy.go`:

```go
// NewStandardEvaluators creates the default set of policy evaluators
func NewStandardEvaluators(service *PolicyService) []PolicyEvaluator {
    return []PolicyEvaluator{
        &VulnerabilityEvaluator{service: service},
        &SBOMEvaluator{service: service},
        &CustomPolicyEvaluator{service: service},  // Add your evaluator
    }
}
```

### Step 4: Add PolicyService Methods

Add convenience methods to `PolicyService` in `internal/services/policy.go`:

```go
// CheckCustomPolicy evaluates custom policies
func (p *PolicyService) CheckCustomPolicy(ctx context.Context, payload *CustomPolicyPayload) (CustomPolicyResult, error) {
    return p.Evaluate(ctx, "custom", payload)
}
```

### Step 5: Add Caching Support

Add caching methods to `PolicyCacheService` in `internal/services/policy_cache.go`:

```go
// CheckCustomPolicyWithCache evaluates custom policies with caching
func (p *PolicyCacheService) CheckCustomPolicyWithCache(
    ctx context.Context,
    payload *CustomPolicyPayload,
    owner, repo, sha string,
) (CustomPolicyResult, error) {
    if !config.AppConfig.Storage.PolicyCache.Enabled {
        return p.policyService.CheckCustomPolicy(ctx, payload)
    }

    cacheKey := fmt.Sprintf("custom:%s:%s:%s", owner, repo, sha)

    ctx, span := p.telemetry.StartSpan(ctx, "policy_cache.check_custom")
    defer span.End()

    span.SetAttributes(
        attribute.String("cache.key", cacheKey),
        attribute.String("policy.type", "custom"),
    )

    // Try cache first
    var result CustomPolicyResult
    if p.getCachedResult(ctx, cacheKey, &result) {
        span.SetAttributes(attribute.Bool("cache.hit", true))
        p.logger.DebugContext(ctx, "Custom policy cache hit", "cache_key", cacheKey)
        return result, nil
    }

    span.SetAttributes(attribute.Bool("cache.hit", false))
    p.logger.DebugContext(ctx, "Custom policy cache miss", "cache_key", cacheKey)

    // Cache miss - evaluate and store
    result, err := p.policyService.CheckCustomPolicy(ctx, payload)
    if err != nil {
        p.telemetry.SetErrorAttribute(span, err)
        return result, err
    }

    // Store in cache
    if err := p.storeCachedResult(ctx, cacheKey, result); err != nil {
        p.logger.WarnContext(ctx, "Failed to cache custom policy result",
            "cache_key", cacheKey,
            "error", err)
    }

    return result, nil
}
```

### Step 6: Create Helper Functions

Add helper functions for payload building in `internal/services/helpers.go`:

```go
// buildCustomPayloadFromData creates a normalized custom payload from raw data
func buildCustomPayloadFromData(
    artifact *SecurityArtifact,
    owner, repo, sha string,
    prNumber int,
) (*CustomPolicyPayload, error) {
    // Parse your specific data format
    var rawData CustomRawData
    if err := json.Unmarshal(artifact.Content, &rawData); err != nil {
        return nil, err
    }

    // Build metadata
    metadata := buildPayloadMetadata(
        "custom_format",
        "custom_tool",
        fmt.Sprintf("%s/%s", owner, repo),
        sha,
        artifact.FileName,
        rawData.SchemaVersion,
        prNumber,
        rawData.ScanTime,
    )

    // Transform raw data to policy format
    customItems := make([]CustomItem, 0, len(rawData.Items))
    compliantCount := 0
    riskDistribution := make(map[string]int)

    for _, item := range rawData.Items {
        customItem := CustomItem{
            ID:         item.ID,
            Name:       item.Name,
            RiskLevel:  item.Risk,
            Compliance: item.IsCompliant,
        }
        customItems = append(customItems, customItem)

        if item.IsCompliant {
            compliantCount++
        }
        riskDistribution[item.Risk]++
    }

    summary := CustomSummary{
        TotalItems:       len(customItems),
        CompliantItems:   compliantCount,
        RiskDistribution: riskDistribution,
    }

    return &CustomPolicyPayload{
        Metadata:   metadata,
        CustomData: customItems,
        Summary:    summary,
    }, nil
}
```

### Step 7: Add Content Detection

If your policy works with specific file formats, add detection in `internal/services/security_detectors.go`:

```go
// CustomDetector identifies custom policy files
type CustomDetector struct{}

func (d *CustomDetector) CanHandle(content []byte, filename string) bool {
    // Check file extension
    if !strings.HasSuffix(filename, ".custom") {
        return false
    }

    // Validate content structure
    return isCustomContent(content)
}

func (d *CustomDetector) GetArtifactType() ArtifactType {
    return ArtifactTypeCustom  // Add this constant to security_types.go
}

func (d *CustomDetector) GetPriority() int {
    return 30  // Lower number = higher priority
}

// Helper function to validate custom content
func isCustomContent(content []byte) bool {
    var data map[string]interface{}
    if err := json.Unmarshal(content, &data); err != nil {
        return false
    }

    // Check for required fields that identify your format
    if _, ok := data["custom_format_version"]; ok {
        return true
    }
    if _, ok := data["custom_schema"]; ok {
        return true
    }

    return false
}
```

### Step 8: Integrate with Security Service

Update `BuildPayloadsFromArtifacts` in `internal/services/security.go`:

```go
// In the switch statement, add your case:
case ArtifactTypeCustom:
    payload, err := buildCustomPayloadFromData(
        artifact,
        owner,
        repo,
        sha,
        0, // prNumber
    )
    if err != nil {
        s.logger.ErrorContext(ctx, "Failed to build custom payload",
            "artifact_name", artifact.ArtifactName,
            "error", err,
        )
        continue
    }

    customPayloads = append(customPayloads, payload)
```

### Step 9: Create Policy Processor (Optional)

For webhook-level processing, implement a strategy in `internal/handlers/policy_processing.go`:

```go
// CustomPolicyProcessor handles custom policy processing in webhooks
type CustomPolicyProcessor struct{}

func (p *CustomPolicyProcessor) ProcessPayloads(
    ctx context.Context,
    logger *slog.Logger,
    policyService PolicyCacheServiceInterface,  // Use cached service
    payloads []*services.CustomPolicyPayload,
    owner, repo, sha string,
) PolicyProcessingResult {
    result := PolicyProcessingResult{
        AllPassed:     true,
        PolicyType:    "custom",
        NonCompliantCustomItems: []services.CustomPolicyItem{},
    }

    for _, payload := range payloads {
        logger.InfoContext(ctx, "Processing custom policy",
            "item_count", len(payload.CustomData),
            "scan_target", payload.Metadata.ScanTarget,
        )

        // Use cached policy evaluation
        policyResult, err := policyService.CheckCustomPolicyWithCache(ctx, payload, owner, repo, sha)
        if err != nil {
            logger.ErrorContext(ctx, "Custom policy evaluation failed", "error", err)
            result.AllPassed = false
            continue
        }

        if !policyResult.Compliant {
            result.AllPassed = false
            result.NonCompliantCustomItems = append(result.NonCompliantCustomItems, policyResult.NonCompliantItems...)
        }
    }

    return result
}

func (p *CustomPolicyProcessor) GetPolicyType() string {
    return "custom"
}
```

### Step 10: Add Tests

Create comprehensive tests in `internal/services/policy_test.go` and `internal/services/policy_cache_test.go`:

```go
func TestCustomPolicyEvaluator_Evaluate(t *testing.T) {
    service := createTestPolicyService(t)
    evaluator := &CustomPolicyEvaluator{service: service}

    tests := []struct {
        name        string
        payload     *CustomPolicyPayload
        expectError bool
        expected    CustomPolicyResult
    }{
        {
            name: "compliant custom policy",
            payload: &CustomPolicyPayload{
                CustomData: []CustomItem{
                    {ID: "1", Compliance: true},
                    {ID: "2", Compliance: true},
                },
            },
            expectError: false,
            expected: CustomPolicyResult{
                Compliant: true,
                TotalItems: 2,
                CompliantItems: 2,
            },
        },
        // Add more test cases...
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := evaluator.Evaluate(ctx, tt.payload)
            if tt.expectError {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.expected, result)
            }
        })
    }
}

func TestPolicyCacheService_CheckCustomPolicyWithCache(t *testing.T) {
    // Test caching behavior for custom policies
    // ... implementation
}
```

## Best Practices

### 1. Type Safety
- Always use strongly typed payload and result structures
- Implement proper type assertions in evaluators
- Use generics for reusable patterns

### 2. Error Handling
- Provide meaningful error messages with context
- Use error wrapping with `fmt.Errorf("%w: ...", ErrPolicyEvaluation, ...)`
- Handle OPA communication failures gracefully

### 3. Observability
- Use consistent telemetry patterns with spans and attributes
- Log at appropriate levels (Debug for details, Info for results, Error for failures)
- Include relevant context in logs and traces
- Add cache hit/miss tracking for performance monitoring

### 4. Performance
- Keep payloads efficient - avoid unnecessary data transformation
- Use streaming for large datasets when possible
- Leverage caching for expensive operations
- Consider cache warming for common scenarios

### 5. Testing
- Test all evaluator methods independently
- Mock OPA responses for unit tests
- Include integration tests with real OPA policies
- Test error conditions and edge cases
- Test both cached and non-cached code paths
- Verify cache hit/miss behavior

### 6. Caching Considerations
- Use meaningful cache keys that include all relevant context
- Set appropriate TTL values based on policy update frequency
- Handle cache misses gracefully
- Monitor cache hit rates for optimization

## OPA Policy Development

Your OPA policy should follow this structure:

```rego
package compliance.custom_policy

import rego.v1

# Main policy decision
default allow := false

allow if {
    compliant_items_count >= required_threshold
}

# Calculate compliance metrics
compliant_items_count := count([item |
    some item in input.custom_data
    item.compliance == true
])

required_threshold := input.summary.total_items * 0.8  # 80% compliance required

# Detailed results for the response
result := {
    "compliant": allow,
    "total_items": count(input.custom_data),
    "compliant_items": compliant_items_count,
    "non_compliant_items": non_compliant_items
}

non_compliant_items := [item_result |
    some item in input.custom_data
    item.compliance == false
    item_result := {
        "id": item.id,
        "name": item.name,
        "risk_level": item.risk_level,
        "reason": sprintf("Item '%s' failed compliance check", [item.name])
    }
]
```

## Registration and Service Initialization

The policy evaluators are automatically registered when creating a `PolicyService`. The initialization follows this pattern:

```go
// In your service initialization (internal/app/container.go)
policyService := services.NewPolicyService(
    opaClient,
    logger,
    telemetryHelper,
    []services.PolicyEvaluator{}, // Empty initially
)

// Create evaluators with service reference
evaluators := services.NewStandardEvaluators(policyService)
for _, evaluator := range evaluators {
    policyService.evaluators[evaluator.PolicyType()] = evaluator
}

// Create cache service wrapper
policyCacheService := services.NewPolicyCacheService(
    policyService,
    stateService,
    logger,
    telemetryHelper,
)
```

This pattern avoids circular dependency issues during service construction while maintaining the factory registry pattern.

## Testing

All tests have been updated to work with the new architecture:
- Services tests verify core policy evaluation functionality
- Cache service tests verify caching behavior and cache hit/miss scenarios
- Handlers tests use MockPolicyCacheService for testing cached behavior
- Integration tests ensure proper dependency injection
- All existing functionality preserved

## Files Modified for Cache Implementation

- `internal/services/policy_cache.go` - New cache service
- `internal/services/policy.go` - Reverted to clean architecture
- `internal/app/container.go` - Added cache service to DI
- `internal/handlers/helpers.go` - Added cache service to handlers
- `internal/handlers/policy_processing.go` - Updated strategy pattern
- `internal/handlers/check_processors.go` - Updated to use cache service
- `internal/handlers/webhook_router.go` - Updated constructor
- Various test files - Updated for new architecture

## Extension Points

The architecture provides several extension points:

1. **New Evaluators**: Implement `PolicyEvaluator` interface
2. **New Content Types**: Implement `ContentDetector` interface
3. **New Processors**: Implement `PolicyProcessor` interface
4. **New Helper Functions**: Add to `helpers.go` for data transformation
5. **New Check Types**: Extend webhook handlers for specialized processing
6. **Cache Strategies**: Extend `PolicyCacheService` for specialized caching behavior

## Future Enhancements

### 1. Cache Improvements
- **Cache Metrics**: Add detailed cache hit/miss metrics
- **Cache Warming**: Pre-populate cache for common scenarios
- **Advanced TTL**: Dynamic TTL based on artifact type or policy complexity
- **Cache Eviction**: LRU or other intelligent eviction strategies

### 2. Policy Enhancements
- **Policy Versioning**: Support for multiple policy versions
- **Dynamic Policy Loading**: Hot-reload policies without restart
- **Policy Templates**: Common policy patterns for easier implementation

### 3. Performance Optimizations
- **Parallel Policy Evaluation**: Evaluate multiple policies concurrently
- **Result Streaming**: Stream results for large datasets
- **Optimized Serialization**: Use more efficient serialization for cache storage

## Conclusion

This modular approach ensures that new policy types can be added without modifying existing code, following the Open/Closed Principle. The combination of clean architecture, comprehensive caching, and extensible patterns provides a robust foundation for policy evaluation that scales with the application's needs.

The caching implementation successfully adds performance optimization while:
- Maintaining clean architecture principles
- Respecting configuration settings
- Preserving all existing functionality
- Adding proper observability and testing
- Following established patterns in the codebase
