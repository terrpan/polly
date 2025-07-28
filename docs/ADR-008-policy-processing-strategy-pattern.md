# ADR-008: Policy Processing Strategy Pattern Implementation

## Status
Accepted

## Context
The webhook handlers in the polly application were evaluating both vulnerability and license policies using nearly identical logic patterns. The `processVulnerabilityPolicies` and `processLicensePolicies` functions contained substantial code duplication with only minor differences in:

1. **Policy service method calls**: `CheckVulnerabilityPolicy` vs `CheckSBOMPolicy`
2. **Input payload types**: `VulnerabilityPayload` vs `SBOMPayload`
3. **Return result types**: `VulnerabilityPolicyResult` vs `SBOMPolicyResult`
4. **Error handling specifics**: Different failure condition checks and error messages
5. **Result processing**: Different ways of handling non-compliant items

This duplication made the code harder to maintain and extend, especially when considering future policy types (e.g., GitHub Actions policies, Docker image policies).

The original functions shared the following structure:
- Initialize result with `AllPassed: true`
- Iterate through payloads
- Log payload processing details
- Call appropriate policy service method
- Handle policy evaluation errors with fallback logic
- Process policy results and update failure details
- Accumulate non-compliant items

## Decision
We will implement the **Strategy Pattern** to eliminate code duplication in policy processing while maintaining type safety and extensibility.

### Strategy Pattern Components

1. **PolicyProcessor Interface**: Defines the contract for policy processing strategies
   ```go
   type PolicyProcessor[T any] interface {
       ProcessPayloads(ctx context.Context, logger *slog.Logger, policyService PolicyServiceInterface, payloads []T, owner, repo, sha string) PolicyProcessingResult
       GetPolicyType() string
   }
   ```

2. **Concrete Strategy Implementations**:
   - `VulnerabilityPolicyProcessor`: Handles vulnerability policy evaluation
   - `LicensePolicyProcessor`: Handles license/SBOM policy evaluation

3. **Strategy Execution Function**: `processPoliciesWithStrategy` provides the common algorithm flow

### Key Benefits

- **DRY Principle**: Eliminates ~80 lines of duplicated code
- **Single Responsibility**: Each processor focuses on one policy type
- **Open/Closed Principle**: Easy to add new policy types without modifying existing code
- **Type Safety**: Maintains compile-time type checking through generics
- **Consistent Error Handling**: Standardized approach across all policy types
- **Testability**: Each strategy can be tested independently

## Implementation Details

### Interface Definition
```go
type PolicyProcessor[T any] interface {
    ProcessPayloads(ctx context.Context, logger *slog.Logger, policyService PolicyServiceInterface, payloads []T, owner, repo, sha string) PolicyProcessingResult
    GetPolicyType() string
}
```

### Concrete Implementations

**VulnerabilityPolicyProcessor**:
- Processes `[]*services.VulnerabilityPayload`
- Calls `policyService.CheckVulnerabilityPolicy()`
- Handles critical/high severity fallback on errors
- Maps results to `PolicyProcessingResult.NonCompliantVulns`

**LicensePolicyProcessor**:
- Processes `[]*services.SBOMPayload`
- Calls `policyService.CheckSBOMPolicy()`
- Handles packages without license fallback on errors
- Maps results to both `NonCompliantComponents` and `ConditionalComponents`

### Strategy Execution
```go
func processPoliciesWithStrategy[T any](
    ctx context.Context,
    logger *slog.Logger,
    policyService PolicyServiceInterface,
    processor PolicyProcessor[T],
    payloads []T,
    owner, repo, sha string,
) PolicyProcessingResult
```

### Updated Public Functions
The existing `processVulnerabilityPolicies` and `processLicensePolicies` functions are now lightweight wrappers that:
1. Create the appropriate strategy instance
2. Delegate to `processPoliciesWithStrategy`
3. Maintain the same public API for backward compatibility

## Consequences

### Positive
- **Reduced Duplication**: ~80 lines of duplicated code eliminated
- **Enhanced Maintainability**: Changes to policy processing algorithm only need to be made in one place
- **Improved Extensibility**: Adding new policy types requires only implementing the interface
- **Better Testing**: Each strategy can be unit tested independently
- **Consistent Behavior**: All policy types follow the same processing patterns
- **Type Safety**: Compile-time guarantees through generic interface

### Negative
- **Slight Complexity Increase**: Introduction of interface and strategy pattern
- **Learning Curve**: Team members need to understand the strategy pattern
- **Indirection**: One additional level of abstraction in the call chain

### Neutral
- **Performance**: No measurable impact on runtime performance
- **Memory Usage**: Minimal additional memory overhead from strategy instances

## Future Extensions

This pattern enables easy addition of new policy types:

### Potential Future Strategies
1. **GitHub Actions Policy Processor**: For workflow security policies
2. **Docker Image Policy Processor**: For container security policies
3. **Infrastructure Policy Processor**: For Terraform/CloudFormation policies
4. **API Security Policy Processor**: For REST/GraphQL endpoint policies

### Extension Example
```go
type GitHubActionsPolicyProcessor struct{}

func (p *GitHubActionsPolicyProcessor) ProcessPayloads(
    ctx context.Context,
    logger *slog.Logger,
    policyService PolicyServiceInterface,
    payloads []*services.GitHubActionsPayload,
    owner, repo, sha string,
) PolicyProcessingResult {
    // Implementation for GitHub Actions policy processing
}

func (p *GitHubActionsPolicyProcessor) GetPolicyType() string {
    return "github-actions"
}
```

## Testing Strategy

### Unit Tests
- **Interface Compliance**: Each processor implements the interface correctly
- **Policy Type Identification**: `GetPolicyType()` returns correct values
- **Success Scenarios**: Compliant policies return `AllPassed: true`
- **Violation Scenarios**: Non-compliant policies populate failure details correctly
- **Error Scenarios**: Policy service errors trigger appropriate fallback logic
- **Strategy Execution**: `processPoliciesWithStrategy` works with different processor types

### Integration Tests
- **End-to-End**: Webhook handlers use strategy pattern correctly
- **Backward Compatibility**: Existing API contracts maintained
- **Cross-Strategy**: Multiple policy types can be processed in same request

## Migration Notes

### Backward Compatibility
- All existing public APIs remain unchanged
- No breaking changes to webhook handler interfaces
- Existing tests continue to pass without modification

### Rollback Plan
If issues arise, the strategy pattern can be rolled back by:
1. Reverting the `processVulnerabilityPolicies` and `processLicensePolicies` functions to their original implementations
2. Removing the strategy pattern components (`PolicyProcessor` interface and concrete implementations)
3. Removing the `processPoliciesWithStrategy` function

## Related ADRs
- [ADR-007: Webhook Handler Refactoring and Consolidation](./ADR-007-webhook-handler-refactoring-consolidation.md) - Established the foundation for this refactoring

## References
- [Strategy Pattern - Gang of Four Design Patterns](https://en.wikipedia.org/wiki/Strategy_pattern)
- [Go Generics - Type Parameters](https://go.dev/doc/tutorial/generics)
- [Clean Code: Functions](https://blog.cleancoder.com/uncle-bob/2016/05/01/TypeWars.html)
