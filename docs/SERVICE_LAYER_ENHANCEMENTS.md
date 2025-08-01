# Service Layer Enhancement Opportunities

## Overview

This document outlines opportunities to improve the `internal/services` package organization through better separation of concerns and extensibility patterns. The enhancements use **multiple design patterns** (Strategy, Factory, Configuration) based on what fits best for each specific use case.

## Current State Analysis

### Services Package Structure
- `policy.go` - Policy evaluation with hardcoded methods for different policy types
- `security.go` - Security content detection with if-else chains for different formats
- `checks.go` - Check run management with type-specific logic
- `state.go` - State management with mixed responsibilities
- `policy_cache.go` - Policy caching with conversion utilities
- **Cross-cutting concerns**: Tracing boilerplate duplicated across all service methods

## Enhancement Opportunities

### 0. Centralized Tracing Helper (HIGH PRIORITY) - **Utility Pattern**

**Current Issues:**
- Every service method duplicates `tracer := otel.Tracer("polly/services")`
- Inconsistent tracing patterns across services
- Boilerplate code scattered throughout the codebase
- Handler tracing logic duplicated in handlers package

**Pattern Applied:** **Centralized Utility Pattern** (shared tracing infrastructure)

**Proposed Solution:**
```go
// In internal/otel/otel.go - Centralized tracing helper
type TracingHelper struct {
    tracer oteltrace.Tracer
}

func NewTracingHelper(componentName string) *TracingHelper {
    return &TracingHelper{
        tracer: otel.Tracer(componentName),
    }
}

func (t *TracingHelper) StartSpan(ctx context.Context, name string) (context.Context, oteltrace.Span) {
    return t.tracer.Start(ctx, name)
}

// In internal/services/ - Constructor injection pattern
func NewPolicyService(opaClient *clients.OPAClient, logger *slog.Logger, tracer *otel.TracingHelper) *PolicyService {
    return &PolicyService{
        opaClient: opaClient,
        logger:    logger,
        tracer:    tracer,
    }
}

// In internal/handlers/ - Constructor injection pattern
func NewSecurityWebhookHandler(deps *Dependencies, tracer *otel.TracingHelper) *SecurityWebhookHandler {
    return &SecurityWebhookHandler{
        BaseWebhookHandler: NewBaseWebhookHandler(deps, tracer),
        // ... other fields
    }
}
```

**Usage Example:**
```go
// Before: Boilerplate in every method
func (s *PolicyService) CheckVulnerabilityPolicy(ctx context.Context, payload *VulnerabilityPayload) (VulnerabilityPolicyResult, error) {
    tracer := otel.Tracer("polly/services")  // ❌ Duplicated
    ctx, span := tracer.Start(ctx, "policy.vulnerability.check")
    defer span.End()
    // ... rest of method
}

// After: Clean, constructor-injected tracing
func (s *PolicyService) CheckVulnerabilityPolicy(ctx context.Context, payload *VulnerabilityPayload) (VulnerabilityPolicyResult, error) {
    ctx, span := s.tracer.StartSpan(ctx, "policy.vulnerability.check")  // ✅ Injected dependency
    defer span.End()
    // ... rest of method
}
```

**Benefits:**
- **Eliminates Boilerplate**: No more `tracer := otel.Tracer("...")` in every method
- **Constructor Injection**: Clean dependency injection pattern for testing and configuration
- **Easier Maintenance**: Changes to tracing logic only need to happen in one place
- **Cross-Package Reuse**: Same helper works for handlers, services, and future packages
- **Testable**: Easy to inject no-op tracers in tests

**Implementation Steps:**
1. ✅ Create centralized `TracingHelper` in `internal/otel/otel.go`
2. Update service constructors to accept `*otel.TracingHelper` parameter
3. Update handler constructors to accept tracer via dependency injection
4. ✅ Add tests for the tracing helper
5. Update all service methods to use injected tracer
6. Update all handler methods to use injected tracer
7. Update `internal/app/container.go` to wire tracer dependencies

**Current Status:** Infrastructure complete, ready for constructor injection migration

### 1. Policy Evaluation Organization (HIGH PRIORITY) - **Factory Pattern**

**Current Issues:**
- Hardcoded methods for each policy type (`CheckVulnerabilityPolicy`, `CheckSBOMPolicy`)
- Difficult to add new policy types without modifying `PolicyService`
- Tight coupling between policy types and evaluation logic

**Pattern Applied:** **Factory/Registry Pattern** with **Constructor Injection**

**Proposed Solution:**
```go
// Minimal interface following Go naming conventions
type Evaluator interface {
    PolicyType() string
    PolicyPath() string
}

// Custom error types for better error handling
var (
    ErrUnknownPolicyType = errors.New("unknown policy type")
    ErrPolicyEvaluation  = errors.New("policy evaluation failed")
)

// Concrete implementations with package-relative naming
type VulnerabilityEvaluator struct {
    service *PolicyService
}

func (v *VulnerabilityEvaluator) PolicyType() string {
    return "vulnerability"
}

func (v *VulnerabilityEvaluator) PolicyPath() string {
    return "vulnerability/main"
}

func (v *VulnerabilityEvaluator) Evaluate(ctx context.Context, payload *VulnerabilityPayload) (VulnerabilityPolicyResult, error) {
    return v.service.CheckVulnerabilityPolicy(ctx, payload)
}

type SBOMEvaluator struct {
    service *PolicyService
}

func (s *SBOMEvaluator) PolicyType() string {
    return "sbom"
}

func (s *SBOMEvaluator) PolicyPath() string {
    return "license/main"
}

func (s *SBOMEvaluator) Evaluate(ctx context.Context, payload *SBOMPayload) (SBOMPolicyResult, error) {
    return s.service.CheckSBOMPolicy(ctx, payload)
}

// Enhanced PolicyService with constructor injection
type PolicyService struct {
    opaClient   *clients.OPAClient
    logger      *slog.Logger
    tracer      *otel.TracingHelper
    evaluators  map[string]Evaluator
}

// Constructor injection - evaluators provided by caller
func NewPolicyService(
    opaClient *clients.OPAClient, 
    logger *slog.Logger,
    tracer *otel.TracingHelper,
    evaluators []Evaluator,
) *PolicyService {
    service := &PolicyService{
        opaClient:  opaClient,
        logger:     logger,
        tracer:     tracer,
        evaluators: make(map[string]Evaluator),
    }

    // Register evaluators
    for _, evaluator := range evaluators {
        service.evaluators[evaluator.PolicyType()] = evaluator
    }

    return service
}

// Factory function for standard evaluators
func NewStandardEvaluators(service *PolicyService) []Evaluator {
    return []Evaluator{
        &VulnerabilityEvaluator{service: service},
        &SBOMEvaluator{service: service},
    }
}

// Type-safe evaluation with clear error handling
func (s *PolicyService) EvaluateVulnerabilityPolicy(ctx context.Context, payload *VulnerabilityPayload) (VulnerabilityPolicyResult, error) {
    evaluator, exists := s.evaluators["vulnerability"]
    if !exists {
        return VulnerabilityPolicyResult{}, fmt.Errorf("%w: vulnerability", ErrUnknownPolicyType)
    }
    
    vulnEvaluator, ok := evaluator.(*VulnerabilityEvaluator)
    if !ok {
        return VulnerabilityPolicyResult{}, fmt.Errorf("%w: invalid evaluator type", ErrPolicyEvaluation)
    }
    
    return vulnEvaluator.Evaluate(ctx, payload)
}

func (s *PolicyService) EvaluateSBOMPolicy(ctx context.Context, payload *SBOMPayload) (SBOMPolicyResult, error) {
    evaluator, exists := s.evaluators["sbom"]
    if !exists {
        return SBOMPolicyResult{}, fmt.Errorf("%w: sbom", ErrUnknownPolicyType)
    }
    
    sbomEvaluator, ok := evaluator.(*SBOMEvaluator)
    if !ok {
        return SBOMPolicyResult{}, fmt.Errorf("%w: invalid evaluator type", ErrPolicyEvaluation)
    }
    
    return sbomEvaluator.Evaluate(ctx, payload)
}
```

**Benefits:**
- **Constructor Injection**: Evaluators provided by caller, not created internally
- **Minimal Interfaces**: Single responsibility interfaces with clear contracts
- **Type Safety**: Clear error types that can be checked with `errors.Is()`
- **No Package Stuttering**: `policy.Evaluator` not `policy.PolicyEvaluator`
- **Explicit Wiring**: No magic registration, all dependencies visible
- **Easy Testing**: Mock evaluators can be injected during construction
- **Clear Error Handling**: Typed errors for better error flow control

**Implementation Steps:**
1. Create minimal `Evaluator` interface with focused methods
2. Implement evaluator types with clear naming (no package stuttering)
3. Update `PolicyService` constructor to accept evaluator slice
4. Add factory function for standard evaluators
5. Define custom error types for better error handling
6. Update `PolicyCacheService` to work with new interface
7. Update `internal/app/container.go` to wire evaluator dependencies
8. Create comprehensive tests for each evaluator

### 2. Security Content Detection (MEDIUM PRIORITY) - **Strategy Pattern**

**Current Issues:**
- If-else chains in content detection logic
- Hardcoded content type checks
- Difficult to add new security report formats

**Pattern Applied:** **Strategy Pattern** with **Constructor Injection**

**Proposed Solution:**
```go
// Minimal interface with Go naming conventions
type Detector interface {
    CanHandle(filename string) bool
    ContentType() string
}

// Custom error types
var (
    ErrUnsupportedFileType = errors.New("unsupported file type")
    ErrContentDetection    = errors.New("content detection failed")
)

// Simple, focused implementations
type TrivyJSONDetector struct{}

func (t *TrivyJSONDetector) CanHandle(filename string) bool {
    return strings.Contains(filename, "trivy") && strings.HasSuffix(filename, ".json")
}

func (t *TrivyJSONDetector) ContentType() string {
    return "vulnerability"
}

type SPDXDetector struct{}

func (s *SPDXDetector) CanHandle(filename string) bool {
    return strings.Contains(filename, "spdx") || strings.Contains(filename, "sbom")
}

func (s *SPDXDetector) ContentType() string {
    return "sbom"
}

// Enhanced SecurityService with constructor injection
type SecurityService struct {
    githubClient *clients.GitHubClient
    logger       *slog.Logger
    tracer       *otel.TracingHelper
    detectors    []Detector
}

// Constructor injection - detectors provided by caller
func NewSecurityService(
    githubClient *clients.GitHubClient,
    logger *slog.Logger,
    tracer *otel.TracingHelper,
    detectors []Detector,
) *SecurityService {
    return &SecurityService{
        githubClient: githubClient,
        logger:       logger,
        tracer:       tracer,
        detectors:    detectors,
    }
}

// Factory function for standard detectors
func NewStandardDetectors() []Detector {
    return []Detector{
        &TrivyJSONDetector{},
        &SPDXDetector{},
    }
}

func (s *SecurityService) DetectContentType(filename string) (string, error) {
    for _, detector := range s.detectors {
        if detector.CanHandle(filename) {
            return detector.ContentType(), nil
        }
    }
    return "", fmt.Errorf("%w: %s", ErrUnsupportedFileType, filename)
}

// Keep existing methods simple with clear error handling
func (s *SecurityService) BuildVulnerabilityPayload(ctx context.Context, artifact *SecurityArtifact, owner, repo, sha string, prNumber int, workflowID int64) (*VulnerabilityPayload, error) {
    contentType, err := s.DetectContentType(artifact.FileName)
    if err != nil {
        return nil, fmt.Errorf("%w: %s", ErrContentDetection, err)
    }
    if contentType != "vulnerability" {
        return nil, fmt.Errorf("%w: expected vulnerability, got %s", ErrUnsupportedFileType, contentType)
    }
    return s.BuildVulnerabilityPayloadFromTrivy(ctx, artifact, owner, repo, sha, prNumber, workflowID)
}

func (s *SecurityService) BuildSBOMPayload(ctx context.Context, artifact *SecurityArtifact, owner, repo, sha string, prNumber int, workflowID int64) (*SBOMPayload, error) {
    contentType, err := s.DetectContentType(artifact.FileName)
    if err != nil {
        return nil, fmt.Errorf("%w: %s", ErrContentDetection, err)
    }
    if contentType != "sbom" {
        return nil, fmt.Errorf("%w: expected sbom, got %s", ErrUnsupportedFileType, contentType)
    }
    return s.BuildSBOMPayloadFromSPDX(ctx, artifact, owner, repo, sha, prNumber, workflowID)
}
```

**Benefits:**
- **Constructor Injection**: Detectors provided by caller for maximum testability
- **Minimal Interface**: Only methods clients actually need
- **Typed Errors**: Clear error types that can be checked with `errors.Is()`
- **No Package Stuttering**: `security.Detector` not `security.ContentDetector`
- **Priority Ordering**: Detector order matters, easy to customize
- **Clear Separation**: Detection logic separate from payload building

**Implementation Steps:**
1. Create minimal `Detector` interface with focused methods
2. Implement detector types for existing formats (Trivy, SPDX, SARIF)
3. Update `SecurityService` constructor to accept detector slice
4. Add factory function for standard detectors
5. Define custom error types for better error handling
6. Add support for new formats (CycloneDX, custom formats)
7. Update `internal/app/container.go` to wire detector dependencies
8. Create comprehensive tests for each detector

### 3. Check Run Configuration (MEDIUM PRIORITY) - **Configuration Pattern**

**Current Issues:**
- Type-specific logic scattered throughout `CheckService`
- Hardcoded check run types and behaviors
- Difficult to customize check run behavior per type

**Pattern Applied:** **Configuration Pattern** with **Constructor Injection**

**Proposed Solution:**
```go
// Minimal configuration interface
type CheckConfig interface {
    Name() string
    Timeout() time.Duration
}

// Custom error types
var (
    ErrUnknownCheckType = errors.New("unknown check type")
)

// Simple configuration implementations
type VulnerabilityCheckConfig struct{}

func (v *VulnerabilityCheckConfig) Name() string {
    return "Vulnerability Scan Check"
}

func (v *VulnerabilityCheckConfig) Timeout() time.Duration {
    return 10 * time.Minute
}

type LicenseCheckConfig struct{}

func (l *LicenseCheckConfig) Name() string {
    return "License Check"
}

func (l *LicenseCheckConfig) Timeout() time.Duration {
    return 5 * time.Minute
}

// Enhanced CheckService with constructor injection
type CheckService struct {
    githubClient *clients.GitHubClient
    logger       *slog.Logger
    tracer       *otel.TracingHelper
    configs      map[CheckRunType]CheckConfig
}

// Constructor injection - configs provided by caller
func NewCheckService(
    githubClient *clients.GitHubClient,
    logger *slog.Logger,
    tracer *otel.TracingHelper,
    configs map[CheckRunType]CheckConfig,
) *CheckService {
    return &CheckService{
        githubClient: githubClient,
        logger:       logger,
        tracer:       tracer,
        configs:      configs,
    }
}

// Factory function for standard configurations
func NewStandardCheckConfigs() map[CheckRunType]CheckConfig {
    return map[CheckRunType]CheckConfig{
        CheckRunTypeVulnerability: &VulnerabilityCheckConfig{},
        CheckRunTypeLicense:       &LicenseCheckConfig{},
    }
}

func (s *CheckService) GetCheckName(checkType CheckRunType) (string, error) {
    if config, exists := s.configs[checkType]; exists {
        return config.Name(), nil
    }
    return "", fmt.Errorf("%w: %v", ErrUnknownCheckType, checkType)
}

func (s *CheckService) GetTimeout(checkType CheckRunType) (time.Duration, error) {
    if config, exists := s.configs[checkType]; exists {
        return config.Timeout(), nil
    }
    return 0, fmt.Errorf("%w: %v", ErrUnknownCheckType, checkType)
}
```

**Benefits:**
- **Constructor Injection**: Configurations provided by caller, no hidden dependencies
- **Minimal Interface**: Only configuration methods clients need
- **Typed Errors**: Clear error handling with `errors.Is()` support
- **No Package Stuttering**: `checks.CheckConfig` not `checks.CheckRunConfig`
- **Type-specific Customization**: Easy to customize per check type
- **Clear Error Flow**: No silent defaults, explicit error handling

**Implementation Steps:**
1. Create minimal `CheckConfig` interface
2. Implement configuration types for existing check types
3. Update `CheckService` constructor to accept config map
4. Add factory function for standard configurations
5. Define custom error types for missing configurations
6. Update error handling to return errors instead of defaults
7. Update `internal/app/container.go` to wire configuration dependencies
8. Create tests for each configuration type

### 4. State Storage Organization (LOW PRIORITY) - **Strategy Pattern**

**Current Issues:**
- Mixed responsibilities in state management
- Different data types handled inconsistently
- Cache and state operations coupled

**Pattern Applied:** **Strategy Pattern** with **Constructor Injection**

**Proposed Solution:**
```go
// Minimal storage strategy interface
type StorageStrategy interface {
    Store(ctx context.Context, key string, value interface{}, ttl time.Duration) error
    Get(ctx context.Context, key string) (interface{}, bool, error)
    Delete(ctx context.Context, key string) error
    DataType() string
}

// Custom error types
var (
    ErrInvalidDataType    = errors.New("invalid data type for storage strategy")
    ErrStorageOperation   = errors.New("storage operation failed")
)

// Strategy implementations with clear responsibilities
type PolicyCacheStorage struct {
    store storage.Store
}

func (p *PolicyCacheStorage) DataType() string {
    return "policy_cache"
}

func (p *PolicyCacheStorage) Store(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
    // Type-specific serialization logic
    return p.store.Set(ctx, key, value, ttl)
}

type CheckRunStorage struct {
    store storage.Store
}

func (c *CheckRunStorage) DataType() string {
    return "check_run"
}

func (c *CheckRunStorage) Store(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
    // Type-specific serialization logic  
    return c.store.Set(ctx, key, value, ttl)
}

// Enhanced StateService with constructor injection
type StateService struct {
    store      storage.Store
    logger     *slog.Logger
    tracer     *otel.TracingHelper
    strategies map[string]StorageStrategy
}

// Constructor injection - strategies provided by caller
func NewStateService(
    store storage.Store,
    logger *slog.Logger,
    tracer *otel.TracingHelper,
    strategies []StorageStrategy,
) *StateService {
    service := &StateService{
        store:      store,
        logger:     logger,
        tracer:     tracer,
        strategies: make(map[string]StorageStrategy),
    }

    for _, strategy := range strategies {
        service.strategies[strategy.DataType()] = strategy
    }

    return service
}

// Factory function for standard storage strategies
func NewStandardStorageStrategies(store storage.Store) []StorageStrategy {
    return []StorageStrategy{
        &PolicyCacheStorage{store: store},
        &CheckRunStorage{store: store},
    }
}
```

**Benefits:**
- **Constructor Injection**: Storage strategies provided explicitly, no hidden state
- **Minimal Interface**: Only methods actually needed for storage operations
- **Clear Separation**: Different serialization strategies per data type
- **Type Safety**: Better cache management with typed operations
- **No Package Stuttering**: `state.StorageStrategy` not `state.StateStorageStrategy`
- **Explicit Dependencies**: All strategy dependencies visible at construction time

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

#### ❌ **Policy Evaluation** → **Factory Pattern with Constructor Injection**
- **Why NOT Strategy**: No algorithm differences - just delegation to existing methods
- **What it IS**: Factory pattern with explicit dependency injection
- **Benefit**: Better organization, easier testing, no hidden dependencies

#### ❌ **Check Run Configuration** → **Configuration Pattern with Constructor Injection**
- **Why NOT Strategy**: No algorithm differences - just different settings
- **What it IS**: Configuration holder pattern with explicit injection
- **Benefit**: Centralized configuration, easier customization, clear dependencies

## Type Safety Considerations

### Pragmatic Approach to Type Safety

The enhancement patterns are designed to **improve organization and extensibility** with **explicit dependency management**:

#### 1. **Policy Evaluation Factory - Simple, Injected, and Type-Safe**
- ✅ **Concrete Types**: Each evaluator works with specific, known types
- ✅ **Constructor Injection**: Dependencies provided by caller, not created internally
- ✅ **Clear Contracts**: Minimal interfaces with obvious purposes
- ✅ **Easy Testing**: Straightforward mocking and dependency injection
- ✅ **Typed Errors**: `ErrUnknownPolicyType` can be checked with `errors.Is()`

**Type Safety Level: EXCELLENT** - Simple, explicit, and safe

#### 2. **Security Content Detection Strategy - Minimal Complexity, Maximum Clarity**
- ✅ **Filename-Based Detection**: Simple pattern matching, no content parsing complexity
- ✅ **Constructor Injection**: Detectors provided by caller for easy testing
- ✅ **No Type Erasure**: Existing payload building methods unchanged
- ✅ **Easy Extension**: Adding new detectors is trivial and explicit
- ✅ **Clear Error Types**: Specific errors for different failure modes

**Type Safety Level: EXCELLENT** - No type safety compromises, clear dependencies

#### 3. **Check Run Configuration - Configuration Pattern with Injection**
- ✅ **Constructor Injection**: Configurations provided explicitly, no surprises
- ✅ **Minimal Interface**: Only what's actually needed
- ✅ **Clear Value**: Easy to add new check types with different configurations
- ✅ **Typed Errors**: No silent defaults, explicit error handling
- ✅ **No Hidden State**: All dependencies visible at construction time

**Type Safety Level: EXCELLENT** - No complexity, all benefits, explicit dependencies

### Why This Approach Works Better

1. **Solve Actual Problems**: Focus on real extensibility needs, not theoretical flexibility
2. **Constructor Injection**: Explicit dependencies make testing and configuration easier
3. **Avoid Over-Engineering**: Use the simplest solution that provides the benefits
4. **Minimal Interfaces**: Small, focused interfaces with only needed methods
5. **Typed Errors**: Clear error types that can be checked with `errors.Is()`
6. **No Package Stuttering**: Follow Go naming conventions (`policy.Evaluator`, not `policy.PolicyEvaluator`)
7. **Explicit Wiring**: No magic registration or hidden side effects

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
// Minimal interfaces with concrete methods - no generics needed
type VulnerabilityProcessor interface {
    ProcessVulnerabilities(ctx context.Context, logger *slog.Logger,
                          policyCacheService PolicyCacheServiceInterface,
                          payloads []*services.VulnerabilityPayload,
                          owner, repo, sha string) PolicyProcessingResult
    PolicyType() string
}

type LicenseProcessor interface {
    ProcessSBOM(ctx context.Context, logger *slog.Logger,
               policyCacheService PolicyCacheServiceInterface,
               payloads []*services.SBOMPayload,
               owner, repo, sha string) PolicyProcessingResult
    PolicyType() string
}

// Simple implementations with constructor injection
type VulnerabilityPolicyProcessor struct {
    tracer *otel.TracingHelper
}

func NewVulnerabilityPolicyProcessor(tracer *otel.TracingHelper) *VulnerabilityPolicyProcessor {
    return &VulnerabilityPolicyProcessor{tracer: tracer}
}

func (p *VulnerabilityPolicyProcessor) PolicyType() string {
    return "vulnerability"
}

func (p *VulnerabilityPolicyProcessor) ProcessVulnerabilities(
    ctx context.Context,
    logger *slog.Logger,
    policyCacheService PolicyCacheServiceInterface,
    payloads []*services.VulnerabilityPayload, // ✅ Concrete type - no casting needed
    owner, repo, sha string,
) PolicyProcessingResult {
    ctx, span := p.tracer.StartSpan(ctx, "process.vulnerabilities")
    defer span.End()
    
    // ✅ Direct usage - no type assertions
    result := PolicyProcessingResult{AllPassed: true}
    for _, payload := range payloads {
        policyResult, err := policyCacheService.CheckVulnerabilityPolicyWithCache(ctx, payload, owner, repo, sha)
        if err != nil {
            logger.ErrorContext(ctx, "Policy evaluation failed", "error", err)
            result.AllPassed = false
            result.FailureDetails = append(result.FailureDetails, err.Error())
            continue
        }
        // ... rest of logic
    }
    return result
}
```

**Why This is Better:**
1. **No Runtime Type Assertions**: Concrete types eliminate the need
2. **Constructor Injection**: Clean dependency injection for tracers and other dependencies
3. **Minimal Interfaces**: Each processor has methods for its specific types only
4. **Easy to Test**: Mock with concrete types and injected dependencies
5. **Type Safe**: Compiler catches type mismatches
6. **Clear Dependencies**: All dependencies explicit in constructor
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

### Implementation Steps - Updated for Go Best Practices

1. **Maintain Current Interface**: Keep existing `interface{}` methods for backward compatibility
2. **Add Concrete Interfaces**: Introduce new concrete processor interfaces alongside existing ones
3. **Constructor Injection**: Update all constructors to accept dependencies explicitly
4. **Minimal Package State**: Eliminate package-level variables where possible
5. **Typed Errors**: Define custom error types that can be checked with `errors.Is()`
6. **Gradual Migration**: Convert callers to use concrete versions
7. **Update Container**: Modify `internal/app/container.go` for explicit dependency wiring
8. **Deprecate Old Interface**: Remove `interface{}` versions in future release

### Compliance Alignment - Go Best Practices Approach

The **revised** patterns provide **consistent type safety and explicit dependencies** across both handlers and services:

#### ✅ **1. Consistent Type Safety with Constructor Injection**
- **Handler Pattern**: Concrete processor interfaces eliminate runtime type assertions
- **Services Pattern**: Explicit evaluator/detector injection provides compile-time safety
- **Alignment**: Consistent explicit dependency approach across all layers

#### ✅ **2. Clear Responsibility Separation with Minimal Interfaces**
- **Parsing Layer**: Handles external input validation and type conversion (JSON → Go structs)
- **Strategy Layer**: Operates on validated, typed data structures with minimal interfaces
- **Business Logic**: Type-safe operations with explicit dependencies

#### ✅ **3. Performance Benefits with Zero Magic**
- **Handler Pattern**: No runtime type assertions in hot paths
- **Services Pattern**: No type checking overhead in business logic
- **Alignment**: Optimal performance with explicit wiring, no reflection or hidden registration

#### ✅ **4. Error Handling Improvement with Typed Errors**
- **Compile-Time Errors**: Type mismatches caught during development
- **Runtime Errors**: Custom error types that can be checked with `errors.Is()`
- **Alignment**: Better error semantics with clear error classification throughout

### Why Constructor Injection Makes Sense Everywhere

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

**Better Architecture with Constructor Injection**:
1. **Webhook Parsing Layer** → Converts JSON to typed structs
2. **Strategy Selection Layer** → Routes to appropriate concrete processor (injected at construction)
3. **Strategy Execution Layer** → Type-safe processing with explicit dependencies

## Architectural Recommendation: Full Type Safety with Explicit Dependencies

**Your insight is spot-on**: Using concrete types in services but `interface{}` in handlers creates an inconsistent architecture where type safety is artificially delayed and dependencies are hidden.

### The Better Path Forward

**Phase 1**: Implement type-safe services with constructor injection alongside enhanced handlers
**Phase 2**: Migrate existing webhook handlers to use concrete processor interfaces
**Phase 3**: Update container to wire all dependencies explicitly
**Phase 4**: Remove legacy `interface{}` patterns and package-level state

### Benefits of Consistent Constructor Injection

1. **Type Safety Throughout**: Compile-time guarantees from parsing to persistence
2. **Performance**: No runtime type assertions in hot paths
3. **Testability**: Easy dependency injection for testing
4. **Architecture Clarity**: Consistent patterns with explicit dependencies across all layers
5. **No Hidden Magic**: All dependencies visible and controllable

### Implementation Strategy

Start with the services enhancements (they're isolated), then demonstrate the improved handler pattern as a proof-of-concept for broader adoption.

**Result**: A fully type-safe policy processing pipeline with explicit dependencies where types are validated once at the boundary and flow safely through the entire system.

---

**Remember**: External data flexibility is achieved at the **parsing boundary**, not by sacrificing type safety in business logic. Dependencies should be **explicit and injected**, not hidden in package-level variables or magic registration systems!

### Integration Strategy

The services strategy patterns integrate seamlessly with existing handlers:

```go
// Existing handler usage (unchanged)
processor := NewVulnerabilityPolicyProcessor(tracer)
result := processor.ProcessVulnerabilities(ctx, logger, policyCacheService, payloads, owner, repo, sha)

// Enhanced services usage with explicit dependencies
evaluators := policy.NewStandardEvaluators(policyService)
policyService := policy.NewPolicyService(opaClient, logger, tracer, evaluators)
result, err := policyService.EvaluateVulnerabilityPolicy(ctx, payload)

// All dependencies explicit and injected at construction time
```

### Migration Path

1. **Phase 1**: Implement services patterns with constructor injection and backward compatibility
2. **Phase 2**: Enhance handlers to use concrete interfaces with injected dependencies
3. **Phase 3**: Update `internal/app/container.go` to wire all dependencies explicitly
4. **Phase 4**: Gradually migrate handler internals to use services patterns
5. **Phase 5**: Deprecate duplicate logic while maintaining handler interface contracts

### Benefits of Alignment

1. **Consistent Patterns**: Same explicit dependency concepts across handlers and services
2. **Gradual Migration**: No breaking changes to existing handler APIs
3. **Enhanced Type Safety**: Improved safety with explicit dependencies
4. **Code Reuse**: Services patterns can be used by both handlers and direct callers
5. **Testing**: Consistent testing patterns with easy dependency injection across all implementations
6. **No Hidden State**: All dependencies visible and controllable at construction time

## Implementation Plan

### Phase 0: Centralized Tracing Helper ✅ COMPLETED
**Files modified:**
- ✅ `internal/otel/otel.go` - Added centralized `TracingHelper`
- ✅ `internal/otel/otel_test.go` - Added tests for tracing helper

**Deliverables:**
- ✅ Centralized `TracingHelper` with consistent API
- ✅ Test coverage for tracing functionality

**Migration Remaining:**
- Update service constructors to accept `*otel.TracingHelper` parameter
- Update handler constructors to accept tracer via dependency injection
- Update `internal/app/container.go` to wire tracer dependencies
- Remove package-level tracer variables

### Phase 1: Policy Evaluation Factory with Constructor Injection
**Files to modify:**
- `internal/services/policy.go`
- `internal/services/policy_cache.go`
- `internal/services/policy_test.go`
- `internal/services/policy_cache_test.go`
- `internal/app/container.go`

**Deliverables:**
- Minimal `Evaluator` interface (no package stuttering)
- Factory implementations for vulnerability and SBOM policies
- Updated `PolicyService` with constructor injection for evaluators and tracer
- Custom error types (`ErrUnknownPolicyType`, `ErrPolicyEvaluation`)
- Updated container to wire policy service dependencies
- Comprehensive tests with dependency injection

### Phase 2: Security Content Detection Strategy with Constructor Injection
**Files to modify:**
- `internal/services/security.go`
- `internal/services/security_test.go`
- `internal/app/container.go`

**Deliverables:**
- Minimal `Detector` interface (no package stuttering)
- Detector implementations for existing formats with constructor injection
- Custom error types (`ErrUnsupportedFileType`, `ErrContentDetection`)
- Priority-based detection system with explicit ordering
- Updated container to wire security service dependencies
- Tests for each detector with dependency injection

### Phase 3: Check Run Configuration with Constructor Injection
**Timeline:** 1 week
**Files to modify:**
- `internal/services/checks.go`
- `internal/services/checks_test.go`
- `internal/app/container.go`

**Deliverables:**
- Minimal `CheckConfig` interface (no package stuttering)
- Configuration implementations for existing check types
- Enhanced `CheckService` with constructor injection for configurations and tracer
- Custom error types (`ErrUnknownCheckType`)
- Type-specific behavior customization with explicit error handling
- Updated container to wire check service dependencies

### Phase 4: State Storage Strategy with Constructor Injection
**Files to modify:**
- `internal/services/state.go`
- `internal/services/state_test.go`
- `internal/app/container.go`

**Deliverables:**
- Minimal `StorageStrategy` interface (no package stuttering)
- Strategy implementations for different data types with constructor injection
- Enhanced state management with explicit dependencies
- Custom error types for storage operations
- Improved caching patterns with type-specific strategies
- Updated container to wire state service dependencies

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

1. **Extensibility:** Easy addition of new policy types, content formats, and check types through explicit injection
2. **Maintainability:** Clear separation of concerns and single responsibility with minimal interfaces
3. **Testability:** Isolated testing of individual strategies with easy dependency injection
4. **Consistency:** Uniform patterns with constructor injection across the services package
5. **Performance:** Strategy caching and optimized selection with no runtime type assertions
6. **Configuration:** Explicit dependency injection and configuration without hidden state
7. **Type Safety:** Custom error types that can be checked with `errors.Is()`
8. **Go Idioms:** Follows Go best practices for interfaces, naming, and dependency management

## Migration Considerations

1. **Backward Compatibility:** Maintain existing API while adding constructor injection support
2. **Gradual Migration:** Implement patterns incrementally without breaking changes
3. **Explicit Dependencies:** Update container to wire all dependencies explicitly, eliminating package-level state
4. **Documentation:** Update ADRs and development guides with Go best practices
5. **Performance:** Ensure dependency injection overhead is minimal
6. **Error Handling:** Migrate to typed errors that can be checked with `errors.Is()`

## Related Documents

- [ADR-008: Policy Processing Strategy Pattern](ADR-008-policy-processing-strategy-pattern.md)
- [SERVICE_LAYER_ENHANCEMENTS.md](SERVICE_LAYER_ENHANCEMENTS.md) (this document)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [TESTING.md](TESTING.md)

## Next Steps

1. Create new branch: `feat/service-layer-enhancements`
2. Start with Phase 1 (Policy Evaluation Factory)
3. Create ADR for service layer pattern implementation
4. Update copilot instructions with service organization guidelines
5. Begin implementation with comprehensive tests

---

**Note:** This enhancement uses appropriate design patterns for each use case and aligns with Go best practices for dependency injection, minimal interfaces, and explicit error handling. The implementation follows established coding guidelines and maintains consistency with the existing codebase architecture while eliminating package-level state and magic registration patterns.
