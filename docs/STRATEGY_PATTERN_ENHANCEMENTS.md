# Service Layer Enhancement Opportunities

## Overview

This document outlines opportunities to improve the `internal/services` package organization through better separation of concerns and extensibility patterns. While not all enhancements use the Strategy pattern, they all improve code maintainability and make it easier to add new functionality.

## Current State Analysis

### Services Package Structure
- `policy.go` - Policy evaluation with hardcoded methods for different policy types
- `security.go` - Security content detection with if-else chains for different formats
- `checks.go` - Check run management with type-specific logic
- `state.go` - State management with mixed responsibilities
- `policy_cache.go` - Policy caching with conversion utilities

## Enhancement Opportunities

### 1. Policy Evaluation Organization (HIGH PRIORITY) - **Factory Pattern**

**Current Issues:**
- Hardcoded methods for each policy type (`CheckVulnerabilityPolicy`, `CheckSBOMPolicy`)
- Difficult to add new policy types without modifying `PolicyService`
- Tight coupling between policy types and evaluation logic

**Pattern Applied:** **Factory/Registry Pattern** (not Strategy - no algorithm differences)

**Proposed Solution:**
```go
// Simple policy evaluation strategy interface - no over-engineering
type PolicyEvaluator interface {
    GetPolicyType() string
    GetPolicyPath() string
}

// Concrete implementations - simple and clear
type VulnerabilityPolicyEvaluator struct {
    service *PolicyService
}

func (v *VulnerabilityPolicyEvaluator) GetPolicyType() string {
    return "vulnerability"
}

func (v *VulnerabilityPolicyEvaluator) GetPolicyPath() string {
    return "vulnerability/main"
}

func (v *VulnerabilityPolicyEvaluator) Evaluate(ctx context.Context, payload *VulnerabilityPayload) (VulnerabilityPolicyResult, error) {
    // Direct, simple implementation
    return v.service.CheckVulnerabilityPolicy(ctx, payload)
}

type SBOMPolicyEvaluator struct {
    service *PolicyService
}

func (s *SBOMPolicyEvaluator) GetPolicyType() string {
    return "sbom"
}

func (s *SBOMPolicyEvaluator) GetPolicyPath() string {
    return "license/main"
}

func (s *SBOMPolicyEvaluator) Evaluate(ctx context.Context, payload *SBOMPayload) (SBOMPolicyResult, error) {
    // Direct, simple implementation
    return s.service.CheckSBOMPolicy(ctx, payload)
}

// Enhanced PolicyService with simple strategy registry
type PolicyService struct {
    opaClient    *clients.OPAClient
    logger       *slog.Logger
    vulnEvaluator *VulnerabilityPolicyEvaluator
    sbomEvaluator *SBOMPolicyEvaluator
}

func NewPolicyService(opaClient *clients.OPAClient, logger *slog.Logger) *PolicyService {
    service := &PolicyService{
        opaClient: opaClient,
        logger:    logger,
    }

    // Simple initialization - no complex generics
    service.vulnEvaluator = &VulnerabilityPolicyEvaluator{service: service}
    service.sbomEvaluator = &SBOMPolicyEvaluator{service: service}

    return service
}

// Simple, direct methods - no over-engineering
func (s *PolicyService) EvaluateVulnerabilityPolicy(ctx context.Context, payload *VulnerabilityPayload) (VulnerabilityPolicyResult, error) {
    return s.vulnEvaluator.Evaluate(ctx, payload)
}

func (s *PolicyService) EvaluateSBOMPolicy(ctx context.Context, payload *SBOMPayload) (SBOMPolicyResult, error) {
    return s.sbomEvaluator.Evaluate(ctx, payload)
}
```

**Benefits:**
- Easy addition of new policy types (compliance, security, custom policies)
- Better testability (can test each evaluator independently)
- Follows single responsibility principle
- Consistent with existing webhook handler strategy pattern

**Implementation Steps:**
1. Create `PolicyEvaluator` interface
2. Implement strategy classes for existing policy types
3. Update `PolicyService` to use strategy registry
4. Add factory method for strategy registration
5. Update `PolicyCacheService` to work with new interface
6. Create comprehensive tests for each strategy

### 2. Security Content Detection (MEDIUM PRIORITY) - **Strategy Pattern**

**Current Issues:**
- If-else chains in content detection logic
- Hardcoded content type checks
- Difficult to add new security report formats

**Pattern Applied:** **Strategy Pattern** (different algorithms for detecting content types)

**Proposed Solution:**
```go
// Simple content detection interface - no unnecessary complexity
type ContentDetector interface {
    CanHandle(filename string) bool
    GetContentType() string
}

// Simple, focused implementations
type TrivyJSONDetector struct{}

func (t *TrivyJSONDetector) CanHandle(filename string) bool {
    return strings.Contains(filename, "trivy") && strings.HasSuffix(filename, ".json")
}

func (t *TrivyJSONDetector) GetContentType() string {
    return "vulnerability"
}

type SPDXDetector struct{}

func (s *SPDXDetector) CanHandle(filename string) bool {
    return strings.Contains(filename, "spdx") || strings.Contains(filename, "sbom")
}

func (s *SPDXDetector) GetContentType() string {
    return "sbom"
}

// Enhanced SecurityService - simple and clear
type SecurityService struct {
    githubClient *clients.GitHubClient
    logger       *slog.Logger
    detectors    []ContentDetector
}

func (s *SecurityService) DetectContentType(filename string) (string, error) {
    for _, detector := range s.detectors {
        if detector.CanHandle(filename) {
            return detector.GetContentType(), nil
        }
    }
    return "", fmt.Errorf("unsupported file type: %s", filename)
}

// Keep existing methods simple - no over-engineering
func (s *SecurityService) BuildVulnerabilityPayload(ctx context.Context, artifact *SecurityArtifact, owner, repo, sha string, prNumber int, workflowID int64) (*VulnerabilityPayload, error) {
    // Existing logic - just check content type first
    contentType, err := s.DetectContentType(artifact.FileName)
    if err != nil || contentType != "vulnerability" {
        return nil, fmt.Errorf("not a vulnerability report: %s", artifact.FileName)
    }

    return s.BuildVulnerabilityPayloadFromTrivy(ctx, artifact, owner, repo, sha, prNumber, workflowID)
}

func (s *SecurityService) BuildSBOMPayload(ctx context.Context, artifact *SecurityArtifact, owner, repo, sha string, prNumber int, workflowID int64) (*SBOMPayload, error) {
    // Existing logic - just check content type first
    contentType, err := s.DetectContentType(artifact.FileName)
    if err != nil || contentType != "sbom" {
        return nil, fmt.Errorf("not an SBOM report: %s", artifact.FileName)
    }

    return s.BuildSBOMPayloadFromSPDX(ctx, artifact, owner, repo, sha, prNumber, workflowID)
}
```

**Benefits:**
- Easy addition of new security report formats
- Priority-based detection order
- Better separation of format-specific logic
- Improved testability

**Implementation Steps:**
1. Create `ContentDetector` interface
2. Implement detectors for existing formats (Trivy, SPDX, SARIF)
3. Add priority-based detection ordering
4. Update `SecurityService` to use detector registry
5. Add support for new formats (CycloneDX, custom formats)
6. Create comprehensive tests for each detector

### 3. Check Run Configuration (MEDIUM PRIORITY) - **Configuration Pattern**

**Current Issues:**
- Type-specific logic scattered throughout `CheckService`
- Hardcoded check run types and behaviors
- Difficult to customize check run behavior per type

**Pattern Applied:** **Configuration Pattern** (not Strategy - just different settings)

**Proposed Solution:**
```go
// Simple check run strategy - no unnecessary complexity
type CheckRunStrategy interface {
    GetCheckName() string
    GetTimeout() time.Duration
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

func (l *LicenseCheckStrategy) GetCheckName() string {
    return "License Check"
}

func (l *LicenseCheckStrategy) GetTimeout() time.Duration {
    return 5 * time.Minute
}

// Enhanced CheckService - keep it simple
type CheckService struct {
    githubClient *clients.GitHubClient
    logger       *slog.Logger
    strategies   map[CheckRunType]CheckRunStrategy
}

func NewCheckService(githubClient *clients.GitHubClient, logger *slog.Logger) *CheckService {
    service := &CheckService{
        githubClient: githubClient,
        logger:       logger,
        strategies:   make(map[CheckRunType]CheckRunStrategy),
    }

    // Simple registration
    service.strategies[CheckRunTypeVulnerability] = &VulnerabilityCheckStrategy{}
    service.strategies[CheckRunTypeLicense] = &LicenseCheckStrategy{}

    return service
}

func (s *CheckService) GetCheckName(checkType CheckRunType) string {
    if strategy, exists := s.strategies[checkType]; exists {
        return strategy.GetCheckName()
    }
    return "Unknown Check"
}

func (s *CheckService) GetTimeout(checkType CheckRunType) time.Duration {
    if strategy, exists := s.strategies[checkType]; exists {
        return strategy.GetTimeout()
    }
    return 5 * time.Minute // default
}
```

**Benefits:**
- Type-specific check run customization
- Better organization of check run logic
- Easy addition of new check types
- Consistent behavior patterns

**Implementation Steps:**
1. Create `CheckRunStrategy` interface
2. Implement strategies for existing check types
3. Update `CheckService` to use strategy registry
4. Add configuration for check run timeouts and behavior
5. Create tests for each strategy

### 4. State Storage Organization (LOW PRIORITY) - **Strategy Pattern**

**Current Issues:**
- Mixed responsibilities in state management
- Different data types handled inconsistently
- Cache and state operations coupled

**Pattern Applied:** **Strategy Pattern** (different storage/serialization algorithms per data type)

**Proposed Solution:**
```go
// State storage strategy interface
type StateStorageStrategy interface {
    StoreData(ctx context.Context, key string, value interface{}, ttl time.Duration) error
    GetData(ctx context.Context, key string) (interface{}, bool, error)
    DeleteData(ctx context.Context, key string) error
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

// Enhanced StateService
type StateService struct {
    store      storage.Store
    logger     *slog.Logger
    strategies map[string]StateStorageStrategy
}
```

**Benefits:**
- Clear separation of data type responsibilities
- Consistent data handling patterns
- Better cache management
- Type-specific serialization/deserialization

## Pattern Analysis

### True Strategy Patterns (Different Algorithms):

#### ✅ **Security Content Detection**
- **Why it's Strategy**: Each detector uses **different logic** to identify file types
- **Algorithm Variety**: Pattern matching, content analysis, filename rules
- **Benefit**: Easy to add new detection algorithms

#### ✅ **State Storage** (if implemented with different serialization)
- **Why it's Strategy**: Different **serialization/caching algorithms** per data type
- **Algorithm Variety**: JSON, binary, compressed, TTL strategies
- **Benefit**: Optimized storage per data type

### Not Strategy Patterns (Just Organization):

#### ❌ **Policy Evaluation** → **Factory Pattern**
- **Why NOT Strategy**: No algorithm differences - just delegation to existing methods
- **What it IS**: Factory pattern for creating policy evaluators
- **Benefit**: Better organization, easier registration

#### ❌ **Check Run Configuration** → **Configuration Pattern**
- **Why NOT Strategy**: No algorithm differences - just different settings
- **What it IS**: Configuration holder pattern
- **Benefit**: Centralized configuration, easier customization

## Type Safety Considerations

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

## Handler Strategy Pattern Compliance

### Existing Handler Pattern Analysis

The current webhook handlers (`internal/handlers/policy_processing.go`) already implement a strategy pattern:

```go
// Existing handler strategy interface
type PolicyProcessor interface {
    ProcessPayloads(ctx context.Context, logger *slog.Logger,
                    policyCacheService PolicyCacheServiceInterface,
                    payloads interface{}, owner, repo, sha string) PolicyProcessingResult
    GetPolicyType() string
}

// Existing implementations
type VulnerabilityPolicyProcessor struct{}
type LicensePolicyProcessor struct{}
```

### Critical Analysis: Why Not Use Generics in Handlers Too?

**Current Handler Issues:**
```go
func (p *VulnerabilityPolicyProcessor) ProcessPayloads(..., payloads interface{}, ...) {
    vulnPayloads, ok := payloads.([]*services.VulnerabilityPayload) // ❌ Runtime type assertion
    if !ok {
        // ❌ Runtime error instead of compile-time safety
        return PolicyProcessingResult{AllPassed: false, FailureDetails: []string{"Invalid payload type"}}
    }
}
```

**The handlers already KNOW their specific types** - they immediately cast `interface{}` to concrete types!

### Improved Handler Strategy - Keep It Simple

**Current Handler Issues:**
```go
func (p *VulnerabilityPolicyProcessor) ProcessPayloads(..., payloads interface{}, ...) {
    vulnPayloads, ok := payloads.([]*services.VulnerabilityPayload) // ❌ Runtime type assertion
    if !ok {
        // ❌ Runtime error instead of compile-time safety
        return PolicyProcessingResult{AllPassed: false, FailureDetails: []string{"Invalid payload type"}}
    }
}
```

**Simple Fix - Use Concrete Types:**

```go
// Simple interface with concrete methods
type PolicyProcessor interface {
    GetPolicyType() string
}

// Separate interfaces for each type - simple and clear
type VulnerabilityProcessor interface {
    PolicyProcessor
    ProcessVulnerabilities(ctx context.Context, logger *slog.Logger,
                          policyCacheService PolicyCacheServiceInterface,
                          payloads []*services.VulnerabilityPayload,
                          owner, repo, sha string) PolicyProcessingResult
}

type LicenseProcessor interface {
    PolicyProcessor
    ProcessSBOM(ctx context.Context, logger *slog.Logger,
               policyCacheService PolicyCacheServiceInterface,
               payloads []*services.SBOMPayload,
               owner, repo, sha string) PolicyProcessingResult
}

// Simple implementations - no generics needed
type VulnerabilityPolicyProcessor struct{}

func (p *VulnerabilityPolicyProcessor) GetPolicyType() string {
    return "vulnerability"
}

func (p *VulnerabilityPolicyProcessor) ProcessVulnerabilities(
    ctx context.Context,
    logger *slog.Logger,
    policyCacheService PolicyCacheServiceInterface,
    payloads []*services.VulnerabilityPayload, // ✅ Concrete type - no casting needed
    owner, repo, sha string,
) PolicyProcessingResult {
    // ✅ Direct usage - no type assertions
    result := PolicyProcessingResult{AllPassed: true}

    for _, payload := range payloads {
        policyResult, err := policyCacheService.CheckVulnerabilityPolicyWithCache(ctx, payload, owner, repo, sha)
        // ... rest of logic
    }
    return result
}
```

**Why This is Better:**
1. **No Runtime Type Assertions**: Concrete types eliminate the need
2. **Clear Interfaces**: Each processor has methods for its specific types
3. **Simple to Understand**: No complex generics or registries
4. **Easy to Test**: Mock with concrete types
5. **Type Safe**: Compiler catches type mismatches
```

### Why This is Better - Consistent Type Safety

#### **Benefits of Generic Handlers:**

1. **Compile-Time Safety**: No runtime type assertions in handlers
2. **Better Error Messages**: Type mismatches caught at compile time
3. **Consistent Pattern**: Same generic approach across handlers and services
4. **Performance**: No runtime type checking overhead
5. **Cleaner Code**: No defensive type assertion code

#### **Addressing Layer Concerns:**

**"But handlers deal with external data!"**
- ✅ **Parsing Layer Separation**: JSON/webhook parsing happens BEFORE strategy selection
- ✅ **Type Validation**: Input validation occurs at the parsing boundary, not strategy boundary
- ✅ **Strategy Selection**: By the time we reach strategies, we know the payload type

### Revised Architecture - Full Generic Strategy Pattern

```go
// Webhook handler flow with type safety
func (h *SecurityWebhookHandler) ProcessSecurityWorkflow(...) {
    // 1. Parse and validate external input (type assertions happen here)
    vulnPayloads, err := h.parseVulnerabilityArtifacts(artifacts)
    if err != nil {
        // Handle parsing errors
    }

    sbomPayloads, err := h.parseSBOMArtifacts(artifacts)
    if err != nil {
        // Handle parsing errors
    }

    // 2. Process with type-safe strategies (no type assertions needed)
    vulnResult := processVulnerabilityPolicies(ctx, logger, policyCacheService, vulnPayloads, owner, repo, sha)
    sbomResult := processLicensePolicies(ctx, logger, policyCacheService, sbomPayloads, owner, repo, sha)
}
```

### Migration Strategy

1. **Maintain Current Interface**: Keep existing `interface{}` methods for backward compatibility
2. **Add Generic Methods**: Introduce new generic strategy interfaces alongside existing ones
3. **Gradual Migration**: Convert callers to use generic versions
4. **Deprecate Old Interface**: Remove `interface{}` versions in future release

### Compliance Alignment - Improved Approach

The **revised** strategy patterns provide **consistent type safety** across both handlers and services:

#### ✅ **1. Consistent Type Safety**
- **Handler Pattern**: Generic `PolicyProcessor[TPayload]` eliminates runtime type assertions
- **Services Pattern**: Generic `PolicyEvaluator[TInput, TResult]` provides compile-time safety
- **Alignment**: Consistent generic approach across all layers

#### ✅ **2. Clear Responsibility Separation**
- **Parsing Layer**: Handles external input validation and type conversion (JSON → Go structs)
- **Strategy Layer**: Operates on validated, typed data structures
- **Business Logic**: Type-safe operations without defensive programming

#### ✅ **3. Performance Benefits**
- **Handler Pattern**: No runtime type assertions in hot paths
- **Services Pattern**: No type checking overhead in business logic
- **Alignment**: Optimal performance across the stack

#### ✅ **4. Error Handling Improvement**
- **Compile-Time Errors**: Type mismatches caught during development
- **Runtime Errors**: Only for actual business logic failures, not type issues
- **Alignment**: Better error semantics throughout

### Why Generics Make Sense Everywhere

**Original Concern**: "Handlers deal with external data, need flexibility"

**Reality Check**:
```go
// Current handler code IMMEDIATELY does type assertion:
vulnPayloads, ok := payloads.([]*services.VulnerabilityPayload)
if !ok {
    return PolicyProcessingResult{AllPassed: false, FailureDetails: []string{"Invalid payload type"}}
}
```

**The handlers already know their types!** Using `interface{}` just delays the inevitable type checking and makes it a runtime failure instead of compile-time safety.

**Better Architecture**:
1. **Webhook Parsing Layer** → Converts JSON to typed structs
2. **Strategy Selection Layer** → Routes to appropriate generic strategy
3. **Strategy Execution Layer** → Type-safe processing

## Architectural Recommendation: Full Type Safety

**Your insight is spot-on**: Using generics in services but `interface{}` in handlers creates an inconsistent architecture where type safety is artificially delayed.

### The Better Path Forward

**Phase 1**: Implement type-safe handlers alongside enhanced services
**Phase 2**: Migrate existing webhook handlers to use generic strategy pattern
**Phase 3**: Remove legacy `interface{}` patterns

### Benefits of Consistent Generics

1. **Type Safety Throughout**: Compile-time guarantees from parsing to persistence
2. **Performance**: No runtime type assertions in hot paths
3. **Developer Experience**: Better IDE support, refactoring safety
4. **Architecture Clarity**: Consistent patterns across all layers

### Implementation Strategy

Start with the services enhancements (they're isolated), then demonstrate the improved handler pattern as a proof-of-concept for broader adoption.

**Result**: A fully type-safe policy processing pipeline where types are validated once at the boundary and flow safely through the entire system.

---

**Remember**: External data flexibility is achieved at the **parsing boundary**, not by sacrificing type safety in business logic. The webhook handlers already know their exact types - we should embrace that knowledge, not fight it!

### Integration Strategy

The services strategy patterns integrate seamlessly with existing handlers:

```go
// Existing handler usage (unchanged)
processor := &VulnerabilityPolicyProcessor{}
result := processor.ProcessPayloads(ctx, logger, policyCacheService, payloads, owner, repo, sha)

// Enhanced services usage (new capability)
result, err := EvaluatePolicy[*VulnerabilityPayload, VulnerabilityPolicyResult](
    ctx, policyService, "vulnerability", payload,
)

// Backward-compatible services usage
result, err := policyService.ProcessPolicy(ctx, "vulnerability", payload)
```

### Migration Path

1. **Phase 1**: Implement services strategy patterns with backward compatibility
2. **Phase 2**: Enhance handlers to optionally use new type-safe APIs
3. **Phase 3**: Gradually migrate handler internals to use services strategies
4. **Phase 4**: Deprecate duplicate logic while maintaining handler interface contracts

### Benefits of Alignment

1. **Consistent Patterns**: Same strategy concepts across handlers and services
2. **Gradual Migration**: No breaking changes to existing handler APIs
3. **Enhanced Type Safety**: Improved safety without losing flexibility
4. **Code Reuse**: Services strategies can be used by both handlers and direct callers
5. **Testing**: Consistent testing patterns across all strategy implementations

## Implementation Plan

### Phase 1: Policy Evaluation Strategy
**Timeline:** 1-2 weeks
**Files to modify:**
- `internal/services/policy.go`
- `internal/services/policy_cache.go`
- `internal/services/policy_test.go`
- `internal/services/policy_cache_test.go`

**Deliverables:**
- `PolicyEvaluator` interface
- Strategy implementations for vulnerability and SBOM policies
- Updated `PolicyService` with strategy registry
- Comprehensive tests

### Phase 2: Security Content Detection Strategy
**Timeline:** 1 week
**Files to modify:**
- `internal/services/security.go`
- `internal/services/security_test.go`

**Deliverables:**
- `ContentDetector` interface
- Detector implementations for existing formats
- Priority-based detection system
- Tests for each detector

### Phase 3: Check Run Type Strategy
**Timeline:** 1 week
**Files to modify:**
- `internal/services/checks.go`
- `internal/services/checks_test.go`

**Deliverables:**
- `CheckRunStrategy` interface
- Strategy implementations for existing check types
- Enhanced `CheckService` with strategy registry
- Type-specific behavior customization

### Phase 4: State Storage Strategy Enhancement
**Timeline:** 1 week
**Files to modify:**
- `internal/services/state.go`
- `internal/services/state_test.go`

**Deliverables:**
- `StateStorageStrategy` interface
- Strategy implementations for different data types
- Enhanced state management
- Improved caching patterns

## Testing Strategy

### Unit Tests
- Test each strategy implementation independently
- Mock dependencies for isolated testing
- Verify strategy registration and selection
- Test error handling and edge cases

### Integration Tests
- Test strategy interactions with real backends
- Verify end-to-end functionality
- Test strategy switching and configuration
- Performance testing for strategy overhead

### Testcontainers
- Use existing testcontainer setup for integration tests
- Test with real OPA and Valkey containers
- Verify strategy behavior with actual data

## Benefits Summary

1. **Extensibility:** Easy addition of new policy types, content formats, and check types
2. **Maintainability:** Clear separation of concerns and single responsibility
3. **Testability:** Isolated testing of individual strategies
4. **Consistency:** Uniform patterns across the services package
5. **Performance:** Strategy caching and optimized selection
6. **Configuration:** Runtime strategy selection and configuration

## Migration Considerations

1. **Backward Compatibility:** Maintain existing API while adding strategy support
2. **Gradual Migration:** Implement strategies incrementally without breaking changes
3. **Configuration:** Add strategy configuration to existing config system
4. **Documentation:** Update ADRs and development guides
5. **Performance:** Ensure strategy overhead is minimal

## Related Documents

- [ADR-008: Policy Processing Strategy Pattern](ADR-008-policy-processing-strategy-pattern.md)
- [STRATEGY_PATTERN_OPPORTUNITIES.md](STRATEGY_PATTERN_OPPORTUNITIES.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [TESTING.md](TESTING.md)

## Next Steps

1. Create new branch: `feat/strategy-pattern-enhancements`
2. Start with Phase 1 (Policy Evaluation Strategy)
3. Create ADR for strategy pattern implementation
4. Update copilot instructions with strategy pattern guidelines
5. Begin implementation with comprehensive tests

---

**Note:** This enhancement aligns with existing project patterns and the strategy pattern already implemented in the webhook handlers (`internal/handlers/`). The implementation should follow established coding guidelines and maintain consistency with the existing codebase architecture.
