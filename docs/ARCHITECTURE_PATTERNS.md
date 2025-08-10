# Architecture Patterns Guide

## Overview

This document outlines architectural patterns and enhancement opportunities for the Polly codebase, with a focus on the Service Layer (`internal/services/`) and the successful implementation of the Strategy Pattern for extensible, maintainable code.

For hands-on steps to add new policy types, caching behaviors, or evaluators see the complementary [Policy Development Guide](./POLICY_DEVELOPMENT_GUIDE.md). Read this file first for rationale and pattern classification, then the development guide for execution details.

## Completed Implementations

### Policy Processing Strategy Pattern ✅

**Status**: Successfully Implemented
**Location**: `internal/handlers/policy_processing.go`
**Impact**: High - Eliminated ~80 lines of duplicate code

#### Benefits Achieved
- Eliminated duplication between `processVulnerabilityPolicies` and `processLicensePolicies`
- Enabled extensible architecture for future policy types
- Improved testability and maintainability
- Maintained type safety through generics

#### Implementation Pattern
```go
type PolicyProcessor interface {
    ProcessPayloads(ctx context.Context, logger *slog.Logger,
        policyService PolicyServiceInterface,
        payloads interface{},
        owner, repo, sha string,
    ) PolicyProcessingResult
    GetPolicyType() string
}

// Strategy implementations
type VulnerabilityPolicyProcessor struct{}
type LicensePolicyProcessor struct{}

// Generic executor function
func processPoliciesWithStrategy[T any](
    ctx context.Context,
    processor PolicyProcessor,
    payloads []T,
    // ... other parameters
) PolicyProcessingResult
```

## Service Layer Enhancement Opportunities

### Current State Analysis

#### Services Package Structure
- `policy.go` - Policy evaluation with hardcoded methods for different policy types
- `security.go` - Security content detection with if-else chains for different formats
- `checks.go` - Check run management with type-specific logic
- `state.go` - State management with mixed responsibilities
- `policy_cache.go` - Policy caching with conversion utilities

### Pattern Classification

#### True Strategy Patterns (Different Algorithms)

##### ✅ **Security Content Detection**
- **Why it's Strategy**: Each detector uses **different logic** to identify file types
- **Algorithm Variety**: Pattern matching, content analysis, filename rules
- **Benefit**: Easy to add new detection algorithms

```go
type ContentDetector interface {
    CanHandle(filename string) bool
    GetContentType() string
}

type TrivyJSONDetector struct{}
type SPDXDetector struct{}
type SARIFDetector struct{}
```

##### ✅ **State Storage** (if implemented with different serialization)
- **Why it's Strategy**: Different **serialization/caching algorithms** per data type
- **Algorithm Variety**: JSON, binary, compressed, TTL strategies
- **Benefit**: Optimized storage per data type

#### Organization Patterns (Not Strategy)

##### ❌ **Policy Evaluation** → **Factory Pattern**
- **Why NOT Strategy**: No algorithm differences - just delegation to existing methods
- **What it IS**: Factory pattern for creating policy evaluators
- **Benefit**: Better organization, easier registration

##### ❌ **Check Run Configuration** → **Configuration Pattern**
- **Why NOT Strategy**: No algorithm differences - just different settings
- **What it IS**: Configuration holder pattern
- **Benefit**: Centralized configuration, easier customization

## High-Priority Enhancement Opportunities

### 1. Check Run Result Building Functions (HIGH IMPACT)

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

### 2. Security Content Detection (MEDIUM-HIGH PRIORITY)

**Status**: Identified
**Location**: `internal/services/security.go` (lines 195-225)
**Pattern**: If-else chains in content detection logic

#### Current Issues
- Hardcoded content type checks
- Difficult to add new security report formats
- No priority-based detection ordering

#### Proposed Strategy Implementation
```go
type ContentDetector interface {
    CanHandle(filename string) bool
    GetContentType() string
    GetPriority() int
}

// Simple, focused implementations
type TrivyJSONDetector struct{}

func (t *TrivyJSONDetector) CanHandle(filename string) bool {
    return strings.Contains(filename, "trivy") && strings.HasSuffix(filename, ".json")
}

func (t *TrivyJSONDetector) GetContentType() string {
    return "vulnerability"
}

func (t *TrivyJSONDetector) GetPriority() int {
    return 10 // Higher priority for specific patterns
}

type SPDXDetector struct{}
type SARIFDetector struct{}

// Enhanced SecurityService
type SecurityService struct {
    githubClient *clients.GitHubClient
    detectors    []ContentDetector
}

func (s *SecurityService) DetectContentType(filename string) (string, error) {
    // Sort by priority and iterate
    for _, detector := range s.sortedDetectors {
        if detector.CanHandle(filename) {
            return detector.GetContentType(), nil
        }
    }
    return "", fmt.Errorf("unsupported file type: %s", filename)
}
```

#### Benefits
- Easy addition of new security report formats (CycloneDX, custom formats)
- Priority-based detection order
- Better separation of format-specific logic
- Improved testability

### 3. Artifact Processing Functions (MEDIUM-HIGH IMPACT)

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

## Medium-Priority Opportunities

### 4. Comment Building Functions (MEDIUM IMPACT)

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

### 5. Check Run Configuration (MEDIUM PRIORITY)

**Status**: Identified
**Location**: `internal/services/checks.go`
**Pattern**: Type-specific logic scattered throughout CheckService

#### Current Issues
- Hardcoded check run types and behaviors
- Difficult to customize check run behavior per type
- Mixed responsibilities

#### Proposed Configuration Pattern
```go
type CheckRunStrategy interface {
    GetCheckName() string
    GetTimeout() time.Duration
    GetDescription() string
}

// Simple strategy implementations
type VulnerabilityCheckStrategy struct{}

func (v *VulnerabilityCheckStrategy) GetCheckName() string {
    return "Vulnerability Scan Check"
}

func (v *VulnerabilityCheckStrategy) GetTimeout() time.Duration {
    return 10 * time.Minute
}

type LicenseCheckStrategy struct{}

// Enhanced CheckService
type CheckService struct {
    githubClient *clients.GitHubClient
    strategies   map[CheckRunType]CheckRunStrategy
}
```

#### Benefits
- Type-specific check run customization
- Better organization of check run logic
- Easy addition of new check types
- Consistent behavior patterns

## Low-Priority Opportunities

### 6. State Storage Organization (LOW PRIORITY)

**Status**: Identified
**Location**: `internal/services/state.go`
**Pattern**: Mixed responsibilities in state management

#### Current Issues
- Different data types handled inconsistently
- Cache and state operations coupled
- No type-specific serialization strategies

#### Proposed Strategy Implementation
```go
type StateStorageStrategy interface {
    StoreData(ctx context.Context, key string, value interface{}, ttl time.Duration) error
    GetData(ctx context.Context, key string, dest interface{}) error
    GetDataType() string
}

// Strategy implementations
type PolicyCacheStorageStrategy struct {
    store storage.Store
}

type CheckRunStorageStrategy struct {
    store storage.Store
}

type PRContextStorageStrategy struct {
    store storage.Store
}
```

#### Benefits
- Clear separation of data type responsibilities
- Consistent data handling patterns
- Better cache management
- Type-specific serialization/deserialization

### 7. Policy Evaluation Organization (MEDIUM PRIORITY)

**Current Issues:**
- Hardcoded methods for each policy type (`CheckVulnerabilityPolicy`, `CheckSBOMPolicy`)
- Difficult to add new policy types without modifying `PolicyService`
- Tight coupling between policy types and evaluation logic

**Pattern Applied:** **Factory/Registry Pattern** (not Strategy - no algorithm differences)

#### Proposed Solution
```go
// Simple policy evaluation interface
type PolicyEvaluator interface {
    GetPolicyType() string
    GetPolicyPath() string
    Evaluate(ctx context.Context, payload any) (any, error)
}

// Concrete implementations
type VulnerabilityPolicyEvaluator struct {
    service *PolicyService
}

func (v *VulnerabilityPolicyEvaluator) GetPolicyType() string {
    return "vulnerability"
}

func (v *VulnerabilityPolicyEvaluator) GetPolicyPath() string {
    return "vulnerability/main"
}

func (v *VulnerabilityPolicyEvaluator) Evaluate(ctx context.Context, payload any) (any, error) {
    vulnPayload, ok := payload.(*VulnerabilityPayload)
    if !ok {
        return nil, fmt.Errorf("expected *VulnerabilityPayload, got %T", payload)
    }
    return v.service.CheckVulnerabilityPolicy(ctx, vulnPayload)
}

// Enhanced PolicyService with simple registry
type PolicyService struct {
    opaClient    *clients.OPAClient
    evaluators   map[string]PolicyEvaluator
}

func (s *PolicyService) EvaluatePolicy(ctx context.Context, policyType string, payload any) (any, error) {
    evaluator, exists := s.evaluators[policyType]
    if !exists {
        return nil, fmt.Errorf("unknown policy type: %s", policyType)
    }
    return evaluator.Evaluate(ctx, payload)
}
```

#### Benefits
- Easy addition of new policy types (compliance, security, custom policies)
- Better testability (can test each evaluator independently)
- Follows single responsibility principle
- Consistent with existing webhook handler strategy pattern

## Implementation Priority Recommendations

### Phase 1: High Impact (Immediate)
1. **Check Run Result Building Functions** - Most immediate benefit, clear duplication
2. **Artifact Processing Functions** - High extensibility value for future artifact types

### Phase 2: Medium Impact (Next Sprint)
3. **Security Content Detection** - Improves extensibility for new report formats
4. **Comment Building Functions** - Improves consistency and maintainability

### Phase 3: Future Consideration
5. **Check Run Configuration** - Only when adding new check types with different behaviors
6. **Policy Evaluation Factory** - When adding multiple new policy types
7. **State Storage Strategy** - Only when adding new storage types or serialization needs

## Type Safety Philosophy

### Pragmatic Approach to Type Safety

The enhancement patterns are designed to **improve organization and extensibility** without over-engineering:

#### 1. **Policy Evaluation Factory - Simple and Type-Safe**
- ✅ **Concrete Types**: Each evaluator works with specific, known types
- ✅ **No Generic Complexity**: Direct methods like `EvaluateVulnerabilityPolicy(payload *VulnerabilityPayload)`
- ✅ **Clear Contracts**: Simple interfaces with obvious purposes
- ✅ **Easy Testing**: Straightforward mocking and testing

**Type Safety Level: EXCELLENT** - Simple, direct, and safe

#### 2. **Security Content Detection Strategy - Minimal Complexity**
- ✅ **Filename-Based Detection**: Simple pattern matching, no content parsing complexity
- ✅ **Clear Responsibilities**: Each detector knows what files it handles
- ✅ **No Type Erasure**: Existing payload building methods unchanged
- ✅ **Easy Extension**: Adding new detectors is trivial

**Type Safety Level: EXCELLENT** - No type safety compromises

#### 3. **Check Run Strategy - Configuration Pattern**
- ✅ **Simple Configuration**: Just names and timeouts, no complex behavior
- ✅ **No Over-Abstraction**: Existing check creation methods unchanged
- ✅ **Clear Value**: Easy to add new check types with different configurations
- ✅ **Minimal Interface**: Only what's actually needed

**Type Safety Level: EXCELLENT** - No complexity, all benefits

### Why This Approach Works Better

1. **Solve Actual Problems**: Focus on real extensibility needs, not theoretical flexibility
2. **Keep It Simple**: Use the simplest solution that provides the benefits
3. **Avoid Over-Engineering**: No generics where concrete types work fine
4. **Pragmatic Benefits**: Better organization without complexity costs

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

## Handler Strategy Pattern Compliance

### Existing Handler Pattern Analysis

The current webhook handlers (`internal/handlers/policy_processing.go`) already implement a strategy pattern:

```go
// Existing handler strategy interface
type PolicyProcessor interface {
    ProcessPayloads(ctx context.Context, logger *slog.Logger,
        policyService PolicyServiceInterface,
        payloads interface{},
        owner, repo, sha string,
    ) PolicyProcessingResult
    GetPolicyType() string
}

// Existing implementations
type VulnerabilityPolicyProcessor struct{}
type LicensePolicyProcessor struct{}
```

### Current Handler Success

The handlers demonstrate that the strategy pattern works well in this codebase:
- **Type Safety**: While using `interface{}` for payloads, immediate casting ensures type safety
- **Extensibility**: Easy to add new policy processors
- **Maintainability**: Common processing logic abstracted into generic functions
- **Testing**: Each processor can be tested independently

## Conclusion

The strategy pattern offers significant opportunities for code quality improvement in the polly codebase. The successful implementation of policy processing functions demonstrates the pattern's effectiveness in this context. The recommended phased approach ensures maximum benefit while minimizing risk and maintaining system stability.

**Total Impact Estimate**:
- **Code Reduction**: 100-150 lines of duplicate code eliminated
- **Maintainability**: Single point of change for common algorithms
- **Extensibility**: Foundation for adding new types without code duplication
- **Testing**: Improved unit test coverage and isolation
- **Type Safety**: Maintained through pragmatic design choices
