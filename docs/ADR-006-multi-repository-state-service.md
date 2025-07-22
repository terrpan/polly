# ADR-006: Multi-Repository State Service Enhancement

## Status
Accepted

## Context

The Polly webhook service was originally designed to handle GitHub webhooks from a single repository environment. However, in production webhook environments, a single Polly instance may need to process webhooks from multiple repositories and organizations. The original state service design used SHA-based keys which could lead to collisions and cross-repository state contamination when multiple repositories have commits with the same SHA.

### Original Design Issues
1. **Key Collision Risk**: Different repositories could have commits with identical SHAs
2. **State Contamination**: PR context from one repository could affect another repository's processing
3. **Debugging Complexity**: Difficult to trace state to specific repositories in multi-tenant environments
4. **Webhook Environment Limitations**: Cannot reliably serve multiple repositories from a single instance

### Previous Key Format
```
polly:pr_number:{sha}
polly:vuln_check_run_id:{sha}
polly:license_check_run_id:{sha}
polly:workflow_run_id:{sha}
```

## Decision

We have enhanced the StateService to support multi-repository environments by:

1. **Repository Context Integration**: All state operations now require owner, repo, and SHA parameters
2. **Enhanced Key Format**: Keys now include repository context for complete isolation
3. **StateMap Structure**: Organized state retrieval with boolean flags and consolidated access
4. **GetAllState Method**: Comprehensive state access for repository context

### New Key Format
```
{owner}:{repo}:pr_number:{sha}
{owner}:{repo}:vuln_check_run_id:{sha}
{owner}:{repo}:license_check_run_id:{sha}
{owner}:{repo}:workflow_run_id:{sha}
```

### API Changes

#### Before (Single Repository)
```go
// Store operations
func (s *StateService) StorePRNumber(ctx context.Context, sha string, prNumber int64) error

// Get operations
func (s *StateService) GetPRNumber(ctx context.Context, sha string) (int64, error)
```

#### After (Multi-Repository)
```go
// Store operations
func (s *StateService) StorePRNumber(ctx context.Context, owner, repo, sha string, prNumber int64) error

// Get operations with existence check
func (s *StateService) GetPRNumber(ctx context.Context, owner, repo, sha string) (int64, bool, error)

// Comprehensive state access
func (s *StateService) GetAllState(ctx context.Context, owner, repo, sha string) (*StateMap, error)
```

#### New StateMap Structure
```go
type StateMap struct {
    // Boolean flags indicating presence of each state type
    HasPRNumber           bool
    HasVulnCheckRunID     bool
    HasLicenseCheckRunID  bool
    HasWorkflowRunID      bool

    // Actual state values
    PRNumber              int64
    VulnCheckRunID        int64
    LicenseCheckRunID     int64
    WorkflowRunID         int64
}
```

## Consequences

### Positive
1. **Repository Isolation**: Complete separation of state between repositories
2. **Collision Prevention**: Identical SHAs from different repositories cannot interfere
3. **Multi-Tenant Support**: Single Polly instance can safely serve multiple repositories
4. **Enhanced Debugging**: Repository context in keys aids troubleshooting
5. **Organized Access**: StateMap provides structured view of all repository state
6. **Existence Checking**: Boolean return values eliminate ambiguity between zero values and missing data

### Negative
1. **Breaking API Change**: All existing StateService consumers require updates
2. **Increased Complexity**: Additional parameters required for all operations
3. **Key Length**: Longer keys consume more storage space
4. **Migration Required**: Existing single-repository deployments need code updates

### Migration Path
1. **Immediate**: All StateService calls updated with owner/repo parameters
2. **Webhook Handler**: Updated to extract and pass repository context
3. **Test Suite**: Comprehensive test updates with repository context
4. **Documentation**: Updated STORAGE.md and ARCHITECTURE.md

## Implementation Details

### Repository Context Extraction
The webhook handler extracts repository context from GitHub webhook payloads:
```go
owner := payload.Repository.Owner.Login
repo := payload.Repository.Name
sha := payload.PullRequest.Head.SHA
```

### Backward Compatibility
This is a breaking change with no backward compatibility. All consumers must update to the new API simultaneously.

### Error Handling
- `Get` operations return `(value, exists, error)` tuples
- Missing state returns `(0, false, nil)` rather than errors
- Storage errors are properly wrapped and logged

### Testing Strategy
- Updated all existing unit tests with repository context
- Added multi-repository isolation tests
- Verified key format correctness
- Validated StateMap functionality

## Examples

### Basic Operations
```go
// Store PR context
err := stateService.StorePRNumber(ctx, "github-org", "my-repo", "abc123", 42)

// Check if PR context exists
prNumber, exists, err := stateService.GetPRNumber(ctx, "github-org", "my-repo", "abc123")
if exists {
    log.Info("Found PR context", "prNumber", prNumber)
}
```

### Comprehensive State Access
```go
// Get all state for repository context
stateMap, err := stateService.GetAllState(ctx, "github-org", "my-repo", "abc123")
if err != nil {
    return err
}

if stateMap.HasPRNumber {
    log.Info("PR context available", "prNumber", stateMap.PRNumber)
}
if stateMap.HasVulnCheckRunID {
    log.Info("Vulnerability check exists", "checkRunID", stateMap.VulnCheckRunID)
}
```

### Repository Isolation Example
```go
// Different repositories with same SHA are isolated
err1 := stateService.StorePRNumber(ctx, "org1", "repo1", "abc123", 42)
err2 := stateService.StorePRNumber(ctx, "org2", "repo2", "abc123", 84)

// Each repository maintains separate state
pr1, exists1, _ := stateService.GetPRNumber(ctx, "org1", "repo1", "abc123") // Returns 42
pr2, exists2, _ := stateService.GetPRNumber(ctx, "org2", "repo2", "abc123") // Returns 84
```

## Alternatives Considered

### 1. Namespace Prefixes
Using configurable namespace prefixes like `{namespace}:pr_number:{sha}`:
- **Rejected**: Still requires configuration management and doesn't solve the multi-repository problem within a namespace

### 2. Separate State Service Instances
Running separate StateService instances per repository:
- **Rejected**: Increases deployment complexity and resource usage without providing clear benefits

### 3. Repository Hash in Keys
Using a hash of owner/repo instead of full names:
- **Rejected**: Reduces debuggability and makes troubleshooting more difficult

## Future Considerations

### Performance Optimizations
- Key compression for very long repository names
- Batch operations for multiple repositories
- Caching frequently accessed repository contexts

### Enhanced Features
- Repository-level state cleanup operations
- Cross-repository state queries for administrative purposes
- Metrics and monitoring per repository

### Storage Efficiency
- Consider key compression for storage space optimization
- Evaluate impact of longer keys on different storage backends
- Monitor key length distribution in production

## References
- [STORAGE.md](./STORAGE.md) - Updated storage documentation
- [ARCHITECTURE.md](./ARCHITECTURE.md) - Updated architecture flows
- [internal/services/state.go](../internal/services/state.go) - Implementation
- [internal/services/state_test.go](../internal/services/state_test.go) - Test coverage
- [internal/handlers/webhook.go](../internal/handlers/webhook.go) - Consumer updates
