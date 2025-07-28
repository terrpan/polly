# Strategy Pattern Opportunities Analysis

## Overview
Following the successful implementation of the strategy pattern for policy processing functions, this document identifies additional opportunities where the strategy pattern could provide significant benefits in the polly codebase.

## Completed Implementation: Policy Processing Functions ✅
**Status**: Implemented
**Location**: `internal/handlers/helpers.go`
**Impact**: High - Eliminated ~80 lines of duplicate code

### Benefits Achieved
- Eliminated duplication between `processVulnerabilityPolicies` and `processLicensePolicies`
- Enabled extensible architecture for future policy types
- Improved testability and maintainability
- Maintained type safety through generics

## Additional Strategy Pattern Opportunities

### 1. Check Run Result Building Functions (High Impact)
**Status**: Identified
**Location**: `internal/handlers/helpers.go` (lines 507-572)
**Functions**: `buildVulnerabilityCheckResult()`, `buildLicenseCheckResult()`

#### Current Duplication
Both functions follow identical patterns with only minor differences:
- Check result title format ("Vulnerability Check" vs "License Check")
- Success message content ("vulnerability findings" vs "SBOM findings")
- Failure summary format (same structure, different terminology)

```go
// Current duplicated pattern
func buildVulnerabilityCheckResult(result PolicyProcessingResult, payloadCount int) (services.CheckRunConclusion, services.CheckRunResult) {
    if result.AllPassed {
        return services.ConclusionSuccess, services.CheckRunResult{
            Title:   "Vulnerability Check - Passed",
            Summary: fmt.Sprintf("Processed %d vulnerability findings", payloadCount),
            Text:    "All vulnerability policies passed.",
        }
    }
    // ... failure handling
}

func buildLicenseCheckResult(result PolicyProcessingResult, payloadCount int) (services.CheckRunConclusion, services.CheckRunResult) {
    if result.AllPassed {
        return services.ConclusionSuccess, services.CheckRunResult{
            Title:   "License Check - Passed",
            Summary: fmt.Sprintf("Processed %d SBOM findings", payloadCount),
            Text:    "All license policies passed.",
        }
    }
    // ... failure handling (nearly identical)
}
```

#### Proposed Strategy Implementation
```go
type CheckResultBuilder interface {
    GetCheckType() string
    GetFindingType() string
    BuildSuccessResult(payloadCount int) services.CheckRunResult
    BuildFailureResult(result PolicyProcessingResult) services.CheckRunResult
}

type VulnerabilityCheckResultBuilder struct{}
type LicenseCheckResultBuilder struct{}

func buildCheckResultWithStrategy(
    builder CheckResultBuilder,
    result PolicyProcessingResult,
    payloadCount int,
) (services.CheckRunConclusion, services.CheckRunResult)
```

#### Benefits
- **Code Reduction**: ~40-50 lines of duplicated code eliminated
- **Consistency**: Standardized check result format across all types
- **Extensibility**: Easy to add new check types (GitHub Actions, Docker, etc.)
- **Maintainability**: Single point of change for check result formatting

### 2. Artifact Processing Functions (Medium-High Impact)
**Status**: Identified
**Location**: `internal/services/security.go` (lines 195-225)
**Pattern**: Switch statement with repeated structure

#### Current Implementation
```go
switch artifact.Type {
case ArtifactTypeVulnerabilityJSON:
    payload, err := s.BuildVulnerabilityPayloadFromTrivy(ctx, artifact, owner, repo, sha, 0, workflowID)
    if err != nil {
        s.logger.ErrorContext(ctx, "Failed to build vulnerability payload", ...)
        continue
    }
    vulnPayloads = append(vulnPayloads, payload)

case ArtifactTypeSBOMSPDX:
    payload, err := s.BuildSBOMPayloadFromSPDX(ctx, artifact, owner, repo, sha, 0, workflowID)
    if err != nil {
        s.logger.ErrorContext(ctx, "Failed to build SBOM payload", ...)
        continue
    }
    sbomPayloads = append(sbomPayloads, payload)
}
```

#### Proposed Strategy Implementation
```go
type ArtifactProcessor interface {
    GetArtifactType() ArtifactType
    ProcessArtifact(ctx context.Context, artifact *SecurityArtifact, owner, repo, sha string, prNumber int64, workflowID int64) (interface{}, error)
    GetPayloadType() string
}

type VulnerabilityArtifactProcessor struct{}
type SBOMArtifactProcessor struct{}

func processArtifactWithStrategy(processor ArtifactProcessor, ...) error
```

#### Benefits
- **Extensibility**: Easy to add new artifact types (SARIF, GitHub Actions, etc.)
- **Error Handling**: Consistent error logging and handling patterns
- **Type Safety**: Eliminate runtime type assertion errors
- **Testing**: Each processor can be unit tested independently

### 3. Comment Building Functions (Medium Impact)
**Status**: Identified
**Location**: `internal/handlers/helpers.go` (lines 296-395)
**Functions**: `buildVulnerabilityViolationComment()`, `buildLicenseComment()`, `buildLicenseViolationSection()`, etc.

#### Current Patterns
Multiple functions build different types of comments with similar structures:
- Header formatting with emojis and markdown
- List building with consistent indentation
- Component information formatting

#### Proposed Strategy Implementation
```go
type CommentBuilder interface {
    GetCommentType() string
    BuildHeader(count int) string
    BuildItemList(items interface{}) string
    FormatItem(item interface{}) string
}

type VulnerabilityCommentBuilder struct{}
type LicenseViolationCommentBuilder struct{}
type LicenseConditionalCommentBuilder struct{}
```

#### Benefits
- **Consistency**: Standardized comment formatting across all types
- **Maintainability**: Single place to update comment styling
- **Extensibility**: Easy to add new comment types
- **Testing**: Isolated testing of comment formatting logic

### 4. Storage Factory Pattern (Low-Medium Impact)
**Status**: Identified
**Location**: `internal/storage/factory.go`
**Pattern**: Simple switch statement for storage type creation

#### Current Implementation
```go
switch config.StoreType {
case string(StoreTypeMemory):
    return NewMemoryStore(), nil
case string(StoreTypeValkey):
    return NewValkeyStore(config.ValkeyConfig)
}
```

#### Strategic Value
While simple now, this could benefit from strategy pattern as more storage types are added (Redis, PostgreSQL, etc.).

### 5. Health Check Functions (Low Impact)
**Status**: Identified
**Location**: `internal/services/health.go`
**Functions**: `checkStorageHealth()`, `checkOPAHealth()`

#### Current Patterns
Similar structure for different dependency health checks with consistent error handling and status determination.

#### Potential Benefits
- Standardized health check interface
- Easy addition of new dependencies
- Consistent health status reporting

## Implementation Priority Recommendations

### Phase 1: High Impact (Immediate)
1. **Check Run Result Building Functions** - Most immediate benefit, clear duplication
2. **Artifact Processing Functions** - High extensibility value for future artifact types

### Phase 2: Medium Impact (Next Sprint)
3. **Comment Building Functions** - Improves consistency and maintainability

### Phase 3: Low Impact (Future Consideration)
4. **Storage Factory Pattern** - Only when adding new storage types
5. **Health Check Functions** - Only when adding new dependencies

## Implementation Template

Based on the successful policy processing implementation, here's the recommended approach:

```go
// 1. Define the strategy interface
type [Domain]Processor interface {
    Process[Action](ctx context.Context, ...) ([ReturnType], error)
    Get[Type]() string
}

// 2. Implement concrete strategies
type [Specific][Domain]Processor struct{}

func (p *[Specific][Domain]Processor) Process[Action](...) ([ReturnType], error) {
    // Specific implementation
}

func (p *[Specific][Domain]Processor) Get[Type]() string {
    return "[specific-type]"
}

// 3. Create strategy executor
func process[Domain]WithStrategy[T any](
    ctx context.Context,
    processor [Domain]Processor,
    input T,
    ...,
) ([ReturnType], error) {
    // Common algorithm implementation
}

// 4. Update existing functions to use strategy
func existing[Domain]Function(...) ([ReturnType], error) {
    processor := &[Specific][Domain]Processor{}
    return process[Domain]WithStrategy(ctx, processor, input, ...)
}
```

## Testing Strategy for New Implementations

### Unit Testing Approach
1. **Interface Compliance Tests**: Verify each concrete strategy implements the interface correctly
2. **Strategy-Specific Tests**: Test the unique logic in each concrete implementation
3. **Strategy Executor Tests**: Test the common algorithm with different strategies
4. **Integration Tests**: Verify end-to-end functionality with strategy pattern

### Test Coverage Goals
- Each concrete strategy: 90%+ coverage
- Strategy executor function: 95%+ coverage
- Integration with existing code: 100% backward compatibility

## Migration Strategy

### Incremental Approach
1. **Implement Strategy Pattern**: Add interface and concrete implementations
2. **Maintain Existing APIs**: Keep current function signatures for backward compatibility
3. **Update Implementation**: Change function internals to use strategy pattern
4. **Add Tests**: Comprehensive test coverage for new pattern
5. **Document Changes**: Update ADRs and development guides

### Risk Mitigation
- All existing tests must continue to pass
- No changes to external APIs
- Gradual rollout with feature flags if needed
- Clear rollback plan for each implementation

## Conclusion

The strategy pattern offers significant opportunities for code quality improvement in the polly codebase. The successful implementation of policy processing functions demonstrates the pattern's effectiveness in this context. The recommended phased approach ensures maximum benefit while minimizing risk and maintaining system stability.

**Total Impact Estimate**:
- **Code Reduction**: 100-150 lines of duplicate code eliminated
- **Maintainability**: Single point of change for common algorithms
- **Extensibility**: Foundation for adding new types without code duplication
- **Testing**: Improved unit test coverage and isolation
