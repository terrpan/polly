# ADR-007: Webhook Handler Refactoring and Consolidation

## Status
**Accepted** - Implemented July 2025

## Context

The webhook handler codebase suffered from significant code quality issues that were impacting maintainability and development velocity:

### Problems Identified
1. **Function Length Violations**: 4 functions violated the 80-line `funlen` limit (97-132 lines)
2. **Extensive Code Duplication**: ~300+ lines of duplicate code across webhook handlers
3. **Architectural Redundancy**: Separate `webhook_utils.go` and `helpers.go` files serving similar purposes
4. **Inconsistent Patterns**: Different handlers implemented similar logic in varying ways

### Business Impact
- Increased maintenance burden due to duplicate logic updates
- Higher risk of bugs from inconsistent implementations
- Slower development velocity from navigating complex, lengthy functions
- Linting failures blocking CI/CD pipeline

## Decision

**Consolidate webhook handler infrastructure into a single, well-structured helpers file with shared processing functions.**

### Key Decisions Made

1. **Extract Shared Helper Functions**: Break down lengthy functions (>80 lines) into focused, reusable helpers
2. **Eliminate Code Duplication**: Create generic processing functions to handle common patterns
3. **Consolidate File Structure**: Merge `webhook_utils.go` into `helpers.go` for unified architecture
4. **Standardize Data Types**: Introduce shared types for consistent parameter passing

### Alternatives Considered

1. **Individual Function Fixes**: Fix each violation separately without broader refactoring
   - **Rejected**: Would not address systemic duplication and architectural issues

2. **Separate Utility Packages**: Create dedicated packages for shared functionality
   - **Rejected**: Over-engineering for current scale; adds unnecessary complexity

3. **Template-Based Code Generation**: Generate handlers from templates
   - **Rejected**: Adds build complexity without addressing core architectural problems

## Implementation

### 1. Shared Types in `helpers.go`

#### PolicyProcessingResult
```go
type PolicyProcessingResult struct {
    AllPassed             bool
    Violations            []VulnerabilityPolicyVuln  // For vulnerability checks
    ConditionalComponents []SBOMPolicyComponent       // For license checks
    Summary               string
    Details               string
}
```
**Benefits**:
- Standardizes policy evaluation results across vulnerability and license checks
- Eliminates duplicate result handling code
- Provides consistent error checking patterns

#### WebhookProcessingConfig
```go
type WebhookProcessingConfig struct {
    Owner    string
    Repo     string
    SHA      string
    PRNumber int64
}
```
**Benefits**:
- Reduces parameter lists from 5+ individual parameters to single config object
- Standardizes webhook context across different handlers
- Simplifies function signatures and improves readability

### 2. Shared Processing Functions

#### Policy Processing
- `processVulnerabilityPolicies()`: Centralizes vulnerability policy evaluation logic
- `processLicensePolicies()`: Centralizes license policy evaluation logic

**Before**: Each handler had 30-40 lines of duplicate policy processing code
**After**: Single implementation reused across workflow and check run handlers

#### Comment Management
- `postVulnerabilityComments()`: Standardized vulnerability comment posting
- `postLicenseComments()`: Standardized license comment posting

**Benefits**: Consistent PR comment formatting and error handling

#### Check Result Building
- `buildVulnerabilityCheckResult()`: Creates standardized GitHub check run results for vulnerabilities
- `buildLicenseCheckResult()`: Creates standardized GitHub check run results for licenses

**Benefits**: Consistent check run titles, summaries, and conclusions

### 3. Handler-Specific Improvements

#### webhook_checkrun.go
**Extracted Methods**:
- `handleCheckRunRerun()`: Main rerun processing logic (was 120+ lines, now <80)
- `storePRNumberFromCheckRun()`: PR number extraction and storage
- `routeSecurityCheckRerun()`: Check run type routing logic
- `restartSecurityCheck()`: Generic security check restart with `SecurityCheckRestartFunc` type

**Benefits**: Clear separation of concerns, easier testing, reusable restart logic

#### webhook_router.go
**Extracted Methods**:
- `parseWebhook()`: Webhook payload parsing
- `routeWebhookEvent()`: Event routing logic
- `handleWebhookError()`: Consistent error response handling
- `handleWebhookSuccess()`: Consistent success response handling

**Benefits**: Simplified main `HandleWebhook` function from 41+ statements to <30

#### webhook_workflow.go
**Simplified Methods**:
- `handleWorkflowCompleted()`: Streamlined using shared `WebhookProcessingConfig`
- `processSecurityPayloads()`: Uses shared processing functions

**Benefits**: Eliminated duplicate payload processing code

#### webhook_utils.go
**New Processing Methods**:
- `processWorkflowSecurityArtifacts()`: Centralized artifact processing coordination
- `processVulnerabilityArtifacts()`: Vulnerability-specific artifact handling
- `processLicenseArtifacts()`: License-specific artifact handling

**Benefits**: Consistent error handling and state management across artifact types

## Testing Improvements

### New Test Coverage
- `TestBuildVulnerabilityCheckResult`: Validates vulnerability check result building
- Enhanced test coverage for new shared helper functions
- All existing tests continue to pass with no regressions

### Testing Benefits
- Shared functions are easier to unit test in isolation
- Consistent behavior across different handler implementations
- Reduced testing complexity through shared logic

## Code Quality Metrics

### Function Length Compliance
```bash
# Before refactoring
golangci-lint run --enable=funlen internal/handlers/
# Multiple violations: 97-132 lines > 80 line limit

# After refactoring
golangci-lint run --enable=funlen internal/handlers/
# Result: 0 function length violations in handlers
```

### Duplication Reduction
- **Vulnerability Processing**: Reduced from 3+ implementations to 1 shared function
- **License Processing**: Reduced from 3+ implementations to 1 shared function
- **Comment Posting**: Eliminated duplicate comment formatting across handlers
- **Check Result Building**: Centralized result creation logic

### Maintainability Improvements
- **Single Point of Change**: Policy processing changes only need updates in `helpers.go`
- **Consistent Behavior**: All handlers use identical processing logic
- **Type Safety**: Shared types prevent parameter mismatches
- **Error Handling**: Standardized error patterns across all handlers

## Migration Impact

### Backward Compatibility
- ✅ All existing tests pass without modification
- ✅ External API contracts remain unchanged
- ✅ No breaking changes to webhook event handling
- ✅ Existing functionality preserved completely

### Performance Impact
- ✅ No performance degradation (same underlying logic)
- ✅ Reduced memory allocations through shared processing
- ✅ Eliminated duplicate code execution paths

## Best Practices Established

### Function Design
1. **Length Limit**: All functions under 80 lines for funlen compliance
2. **Single Responsibility**: Each function has a clear, focused purpose
3. **Shared Logic**: Common patterns extracted to reusable functions
4. **Type Safety**: Standardized types for consistent data handling

### Code Organization
1. **Logical Grouping**: Related functions grouped in appropriate files
2. **Clear Naming**: Function names clearly indicate purpose and scope
3. **Documentation**: Comprehensive comments for shared functions
4. **Testing**: All new shared functions have corresponding test coverage

### Maintenance Guidelines
1. **Shared First**: Consider shared helpers before duplicating logic
2. **Type Consistency**: Use standardized types for common data structures
3. **Function Length**: Extract helpers when approaching 80-line limit
4. **Test Coverage**: Maintain test coverage for all shared functionality

## Future Benefits

### Extensibility
- New event types can easily reuse existing shared processing functions
- Additional security check types can follow established patterns
- Policy evaluation can be extended without duplicating processing logic

### Maintainability
- Bug fixes in shared logic automatically benefit all handlers
- Feature enhancements require changes in fewer locations
- Code reviews focus on business logic rather than boilerplate

### Code Quality
- Linting violations significantly reduced
- Consistent patterns improve code readability
- Shared types prevent runtime errors from parameter mismatches

## Consequences

### Positive Outcomes
- ✅ **Zero Code Quality Violations**: 0 `funlen` and 0 `dupl` violations
- ✅ **Reduced Codebase Size**: ~300+ lines eliminated through consolidation
- ✅ **Improved Maintainability**: Single point of change for shared functionality
- ✅ **Enhanced Testability**: Shared functions easier to unit test in isolation
- ✅ **Consistent Behavior**: All handlers use identical processing logic
- ✅ **Better Architecture**: Unified webhook infrastructure in single file

### Potential Risks
- **Learning Curve**: Developers need to understand new shared patterns
- **Abstraction Overhead**: Generic functions may be less obvious than specific implementations
- **Single Point of Failure**: Bugs in shared functions affect multiple handlers

### Migration Impact
- **Backward Compatibility**: ✅ All existing tests pass without modification
- **API Contracts**: ✅ No changes to external webhook interfaces
- **Performance**: ✅ No degradation, potentially improved through reduced duplication

## Monitoring and Success Metrics

### Code Quality Metrics
```bash
# Function Length Compliance
golangci-lint run --enable=funlen internal/handlers/
# Result: 0 violations (target: 0)

# Code Duplication
golangci-lint run --enable=dupl internal/handlers/
# Result: 0 violations (target: 0)
```

### Maintainability Indicators
- Time to implement new webhook handlers
- Lines of code required for similar functionality
- Number of files requiring changes for shared logic updates

## Future Considerations

This ADR establishes patterns that should be followed for future webhook handler development:

1. **Function Length**: Extract helpers when approaching 80-line limit
2. **Shared Logic**: Prefer shared functions over duplication
3. **Type Consistency**: Use standardized types for common data structures
4. **Test Coverage**: Maintain comprehensive test coverage for shared functionality

## Related Documents
- [ARCHITECTURE.md](./ARCHITECTURE.md) - Overall system architecture
- [WEBHOOK_DEVELOPMENT_GUIDE.md](./WEBHOOK_DEVELOPMENT_GUIDE.md) - Development patterns and guidelines
