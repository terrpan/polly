# ADR-005: PR Context Storage for Security Check Runs

## Status
Implemented

## Context
Polly processes security artifacts from GitHub Actions workflow runs to evaluate vulnerabilities and create check runs on pull requests. However, there's a timing and context challenge:

1. **Pull Request Events** occur when PRs are opened/reopened and contain PR metadata (PR number, branch info)
2. **Workflow Run Events** occur when CI workflows complete and contain security artifacts (SPDX, Trivy JSON, SARIF)
3. **GitHub Check Runs** need to be associated with specific PRs for proper integration

The challenge is connecting these two event streams to create meaningful security check runs on the correct PRs.

### Problem Statement
- Workflow run events contain security artifacts but lack direct PR context
- Pull request events have PR context but no security artifacts
- Check runs need both PR context AND security evaluation results
- GitHub's webhook events don't provide a direct mapping between workflow runs and PRs

### Alternative Approaches Considered
1. **GitHub API Lookup**: Query GitHub API to find PR by SHA during workflow processing
2. **Single Event Processing**: Try to process everything during PR events (artifacts not available yet)
3. **Event Queuing with NATS**: Use message queues to coordinate between events
4. **Context Storage**: Store PR context during PR events, retrieve during workflow events

## Decision
We will implement **Option 1: Store PR context and create check runs from workflow events** using an in-memory map for initial implementation, with future migration to ValKey for persistence.

### Architecture
1. **PR Event Handler**: Store SHA → PR number mapping when PR is opened/reopened
2. **Workflow Event Handler**: Retrieve PR context, process security artifacts, create check runs
3. **Context Storage**: Thread-safe in-memory map with plans for ValKey migration

### Implementation Details

#### PR Context Storage
```go
type WebhookHandler struct {
    // In-memory cache for PR context store
    prContextStore map[string]int64 // sha -> pr_number
    prContextMutex sync.RWMutex     // RWMutex to protect the context store
}
```

#### Event Flow
1. **Pull Request Opened/Reopened**:
   - Extract SHA and PR number
   - Store mapping: `prContextStore[sha] = prNumber`
   - Create and start policy check run (existing behavior)

2. **Workflow Run Completed**:
   - Process security artifacts into normalized payloads
   - Lookup PR number: `prNumber := prContextStore[sha]`
   - If PR context exists, create security check run
   - Evaluate payloads with OPA and complete check run

#### Thread Safety
- Use `sync.RWMutex` for concurrent access protection
- Write operations (storing context) use `Lock()`
- Read operations (retrieving context) use `RLock()`
- Immediate unlock pattern for simple operations (no defer needed)

## Implementation Status (2025)

The storage abstraction has been fully implemented with the following components:

### Storage Interface (`internal/storage/interface.go`)
```go
type Store interface {
    Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
    Get(ctx context.Context, key string, dest interface{}) error
    Delete(ctx context.Context, key string) error
    Exists(ctx context.Context, key string) (bool, error)
    Close() error
}
```

### StateService (`internal/services/state.go`)
Replaces the original WebhookHandler maps with a dedicated service:
```go
type StateService struct {
    store storage.Store
}

// PR context management
func (s *StateService) StorePRNumber(ctx context.Context, sha string, prNumber int64) error
func (s *StateService) GetPRNumber(ctx context.Context, sha string) (int64, error)

// Check run state management
func (s *StateService) StoreVulnCheckRunID(ctx context.Context, sha string, checkRunID int64) error
func (s *StateService) GetVulnCheckRunID(ctx context.Context, sha string) (int64, error)
func (s *StateService) StoreLicenseCheckRunID(ctx context.Context, sha string, checkRunID int64) error
func (s *StateService) GetLicenseCheckRunID(ctx context.Context, sha string) (int64, error)

// Workflow state management
func (s *StateService) StoreWorkflowRunID(ctx context.Context, sha string, workflowRunID int64) error
func (s *StateService) GetWorkflowRunID(ctx context.Context, sha string) (int64, error)
```

### Storage Backends
- **Memory Store** (`internal/storage/memory.go`): Thread-safe in-memory implementation with expiration
- **Valkey Store** (`internal/storage/valkey.go`): Production-ready distributed storage with JSON serialization
- **Factory** (`internal/storage/factory.go`): Configuration-driven store creation

### Configuration Integration
Environment variable support for flexible storage selection:
```bash
POLLY_STORAGE_TYPE=memory          # or "valkey"
POLLY_VALKEY_ADDRESS=localhost:6379
POLLY_VALKEY_USERNAME=
POLLY_VALKEY_PASSWORD=
POLLY_VALKEY_DB=0
```

The WebhookHandler has been refactored to use StateService instead of direct map access, providing clean separation of concerns and enabling seamless backend switching.

## Valkey Integration (Implemented)

### Production Storage Features
- **Persistence**: Survive application restarts and deployments
- **Scalability**: Support multiple Polly instances
- **TTL Support**: Automatic cleanup of old PR contexts
- **Performance**: Dedicated storage layer optimized for key-value operations

### Migration Plan
```go
package storage

type PRContextStore interface {
    StorePRContext(ctx context.Context, sha string, prNumber int64) error
    GetPRNumber(ctx context.Context, sha string) (int64, error)
}

// In-memory implementation (current)
type InMemoryPRContextStore struct {
    store map[string]int64
    mutex sync.RWMutex
}

// ValKey implementation (future)
type ValKeyPRContextStore struct {
    client *valkey.Client
    ttl    time.Duration
}

func (s *ValKeyPRContextStore) StorePRContext(ctx context.Context, sha string, prNumber int64) error {
    key := fmt.Sprintf("polly:pr_context:%s", sha)
    return s.client.Set(ctx, key, prNumber, s.ttl).Err()
}

func (s *ValKeyPRContextStore) GetPRNumber(ctx context.Context, sha string) (int64, error) {
    key := fmt.Sprintf("polly:pr_context:%s", sha)
    val, err := s.client.Get(ctx, key).Result()
    if err == valkey.Nil {
        return 0, nil // Not found
    }
    if err != nil {
        return 0, err
    }
    return strconv.ParseInt(val, 10, 64)
}
```

### ValKey Configuration
- **Key Pattern**: `polly:pr_context:{sha}`
- **TTL**: 24-48 hours (longer than typical CI workflows)
- **Cleanup**: Automatic expiration prevents storage bloat
- **Monitoring**: Track hit/miss rates and cleanup metrics

## Rationale

### Why This Approach
1. **Separation of Concerns**: Each event handler focuses on its specific responsibilities
2. **Reliable Timing**: Workflow events guarantee security artifacts are available
3. **Simple Implementation**: Straightforward key-value mapping
4. **Future-Proof**: Clear migration path to persistent storage

### Why Not Alternatives
- **GitHub API Lookup**: Additional API calls, rate limiting concerns, complexity
- **Single Event Processing**: Timing issues, artifacts not ready during PR events
- **NATS Queuing**: Over-engineering for this use case, adds complexity without clear benefits

## Consequences

### Positive
- **Clean Event Separation**: Each event type handles what it does best
- **Reliable Security Checks**: Guaranteed artifact availability during processing
- **Scalable Architecture**: Ready for multi-instance deployment with ValKey
- **Simple Implementation**: Easy to understand and maintain
- **Flexible Storage**: Can switch backends without changing business logic

### Negative
- **Memory Usage**: In-memory storage scales with active PRs
- **Data Loss Risk**: Current implementation loses context on restart
- **Cleanup Complexity**: Need to manage stale entries in memory
- **Additional Dependency**: Future ValKey requirement

### Mitigation Strategies
- **Memory Management**: Implement periodic cleanup of old entries
- **Graceful Degradation**: Handle missing context gracefully (skip check run creation)
- **Monitoring**: Track context store size and hit rates
- **Migration Planning**: Implement interface early for seamless ValKey transition

## Implementation Status
- ✅ In-memory PR context storage
- ✅ Thread-safe access with RWMutex
- ✅ PR event context storage
- ✅ Workflow event context retrieval
- ✅ Security check run creation
- 🔄 Security payload evaluation (placeholder implementation)
- ⏳ ValKey storage interface design
- ⏳ ValKey implementation
- ⏳ Memory cleanup mechanisms
- ⏳ Monitoring and metrics

## Future Considerations

### Performance Optimization
- **Batch Operations**: Group multiple PR contexts in single ValKey operations
- **Caching Strategy**: Local cache with ValKey as authoritative source
- **Connection Pooling**: Optimize ValKey connection management

### Observability
- **Metrics**: Context store hit/miss rates, storage size, cleanup frequency
- **Logging**: Context storage/retrieval operations, cleanup events
- **Alerts**: High memory usage, ValKey connection issues, context misses

### Security
- **Access Control**: ValKey authentication and authorization
- **Data Encryption**: Encrypt sensitive PR context data
- **Audit Logging**: Track context access patterns

## Related ADRs
- ADR-004: Structured Security Payloads and OPA Validation
- ADR-003: GitHub Checks Integration (if exists)
