# Storage Architecture

Polly uses a flexible storage abstraction to maintain application state across GitHub webhook events. The storage layer provides a clean interface for persisting PR context, check run state, and workflow information needed for proper GitHub integration.

## Overview

The storage system consists of:
- **Interface**: Common contract for all storage backends
- **Backends**: Pluggable implementations (Memory, Valkey)
- **StateService**: Business logic layer for managing application state
- **Factory**: Configuration-driven backend creation

## Storage Interface

All storage backends implement a common interface:

```go
type Store interface {
    // Basic storage operations
    Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
    Get(ctx context.Context, key string) (interface{}, error)
    Delete(ctx context.Context, key string) error
    Exists(ctx context.Context, key string) (bool, error)
    Ping(ctx context.Context) (string, error)
    Close() error

    // Policy cache operations (optimized for large security artifacts)
    StoreCachedPolicyResults(ctx context.Context, key string, result interface{}, ttl time.Duration, maxSize int64) error
    GetCachedPolicyResults(ctx context.Context, key string) (*PolicyCacheEntry, error)
}
```

### Key Features
- **Context Support**: All operations accept context for cancellation and tracing
- **Generic Values**: Automatic JSON serialization for complex data types
- **Expiration**: Built-in TTL support for automatic cleanup
- **Policy Caching**: Specialized methods for caching policy evaluation results with size validation
- **Error Handling**: Consistent error patterns across backends

## Storage Backends

### Memory Store

**Purpose**: Development and testing
**Location**: `internal/storage/memory.go`

**Features**:
- Thread-safe concurrent access using `sync.RWMutex`
- Built-in expiration with background cleanup
- Zero external dependencies
- Fast access for local development

**Limitations**:
- Data lost on application restart
- Single instance only (no shared state)
- Memory usage scales with stored data

**Configuration**:
```bash
POLLY_STORAGE_TYPE=memory
```

### Valkey Store

**Purpose**: Production deployments
**Location**: `internal/storage/valkey.go`

**Features**:
- Persistent storage across restarts
- Multi-instance support for horizontal scaling
- Automatic key expiration
- JSON serialization for complex data types
- Connection pooling and retry logic
- **OpenTelemetry Integration**: Optional distributed tracing support
- **Sentinel Support**: High availability with Valkey Sentinel
- **Compression**: Optional zlib compression for improved performance

**Requirements**:
- Valkey or Redis server
- Network connectivity to storage server
- Optional: Sentinel cluster for high availability

**Basic Configuration**:
```bash
POLLY_STORAGE_TYPE=valkey
POLLY_VALKEY_ADDRESS=localhost:6379
POLLY_VALKEY_USERNAME=your_username
POLLY_VALKEY_PASSWORD=your_password
POLLY_VALKEY_DB=0
```

**Advanced Configuration**:
```bash
# Sentinel Configuration (for high availability)
POLLY_VALKEY_ENABLE_SENTINEL=true
POLLY_VALKEY_SENTINEL_ADDRS=sentinel1:26379,sentinel2:26379,sentinel3:26379
POLLY_VALKEY_SENTINEL_MASTER=mymaster
POLLY_VALKEY_SENTINEL_USERNAME=sentinel_user
POLLY_VALKEY_SENTINEL_PASSWORD=sentinel_pass

# Performance Configuration
POLLY_VALKEY_ENABLE_COMPRESSION=true

# OpenTelemetry Integration (requires OTLP to be enabled)
POLLY_VALKEY_ENABLE_OTEL=true
```

## StateService

The StateService provides a business logic layer on top of the storage interface, managing application-specific state with type safety and key formatting. It supports multi-repository environments by including repository context in all operations.

**Location**: `internal/services/state.go`

### Repository Context

All state operations require repository context to ensure proper isolation between different repositories:

```go
type RepoContext struct {
    Owner string // GitHub repository owner
    Repo  string // GitHub repository name
    SHA   string // Git commit SHA
}
```

### Managed State Types

#### PR Context
Maps commit SHAs to PR numbers for connecting workflow events to pull requests:
```go
func (s *StateService) StorePRNumber(ctx context.Context, owner, repo, sha string, prNumber int64) error
func (s *StateService) GetPRNumber(ctx context.Context, owner, repo, sha string) (int64, bool, error)
```

#### Check Run State
Tracks GitHub check run IDs for security validations:
```go
// Vulnerability check runs
func (s *StateService) StoreVulnCheckRunID(ctx context.Context, owner, repo, sha string, checkRunID int64) error
func (s *StateService) GetVulnCheckRunID(ctx context.Context, owner, repo, sha string) (int64, bool, error)

// License check runs
func (s *StateService) StoreLicenseCheckRunID(ctx context.Context, owner, repo, sha string, checkRunID int64) error
func (s *StateService) GetLicenseCheckRunID(ctx context.Context, owner, repo, sha string) (int64, bool, error)
```

#### Workflow State
Manages workflow run IDs for handling re-runs and concurrent processing:
```go
func (s *StateService) StoreWorkflowRunID(ctx context.Context, owner, repo, sha string, workflowRunID int64) error
func (s *StateService) GetWorkflowRunID(ctx context.Context, owner, repo, sha string) (int64, bool, error)
```

#### Policy Result Caching
Caches policy evaluation results to optimize performance during check run re-runs, especially for large SBOM files that can contain tens of thousands of lines.

```go
type PolicyCacheEntry struct {
    Result    interface{} `json:"result"`
    CachedAt  time.Time   `json:"cached_at"`
    ExpiresAt time.Time   `json:"expires_at"`
    Size      int64       `json:"size"` // Size in bytes for monitoring
}

// Storage interface methods
func StoreCachedPolicyResults(ctx context.Context, key string, result interface{}, ttl time.Duration, maxSize int64) error
func GetCachedPolicyResults(ctx context.Context, key string) (*PolicyCacheEntry, error)
```

**Implementation Details**:

*Memory Store*:
- Size validation using simple object estimation
- Direct object storage (no serialization overhead)
- Automatic cleanup of expired entries using existing TTL mechanism
- Thread-safe access with `sync.RWMutex`

*Valkey Store*:
- JSON serialization/deserialization for persistence
- Integration with existing zlib compression for large entries
- Size validation before storage to prevent memory issues
- Background cleanup of expired entries
- Compression ratio tracking for performance monitoring

**Key Features**:
- **Size Validation**: Prevents caching of extremely large entries (configurable via `max_size`)
- **TTL Support**: Automatic expiration of cached results (configurable via `ttl`)
- **Error Handling**: Returns `ErrEntrySizeExceeded` for oversized entries, `ErrPolicyCacheDisabled` when disabled
- **Observability**: Full OpenTelemetry tracing with cache hit/miss metrics and compression ratios
- **Compression**: Automatic compression for Valkey backend to reduce storage footprint
- **Safety**: Size limits prevent memory exhaustion from large SBOM files

**Configuration Examples**:

*Basic Configuration*:
```yaml
storage:
  type: "memory"
  policy_cache:
    enabled: true
    ttl: "30m"           # Cache TTL (e.g., "30m", "1h", "24h")
    max_size: 10485760   # 10MB max size per cache entry
```

*Production Configuration with Valkey*:
```yaml
storage:
  type: "valkey"
  valkey:
    address: "localhost:6379"
    enable_compression: true
    enable_otel: true
  policy_cache:
    enabled: true
    ttl: "1h"
    max_size: 52428800  # 50MB for large SBOMs
```

*Environment Variables*:
```bash
export POLLY_STORAGE_POLICY_CACHE_ENABLED=true
export POLLY_STORAGE_POLICY_CACHE_TTL=30m
export POLLY_STORAGE_POLICY_CACHE_MAX_SIZE=10485760
```

**Usage Pattern**:
```go
// Generate cache key for policy result
cacheKey := fmt.Sprintf("policy:%s:%s:%s:%s", policyName, owner, repo, sha)

// Try to get cached result first
if config.AppConfig.Storage.PolicyCache.Enabled {
    if entry, err := store.GetCachedPolicyResults(ctx, cacheKey); err == nil {
        // Cache hit - return cached result
        return entry.Result, nil
    }
}

// Cache miss - evaluate policy
result, err := evaluatePolicy(ctx, input)
if err != nil {
    return nil, err
}

// Cache the result for future re-runs
if config.AppConfig.Storage.PolicyCache.Enabled {
    ttl, _ := time.ParseDuration(config.AppConfig.Storage.PolicyCache.TTL)
    store.StoreCachedPolicyResults(ctx, cacheKey, result, ttl, config.AppConfig.Storage.PolicyCache.MaxSize)
}

return result, nil
```

**Use Cases**:
- Check run re-runs avoid re-processing identical SBOM files
- Large security artifacts (10k+ lines) benefit from caching
- Reduces OPA evaluation overhead for repeated policy checks
- Improves response times for GitHub webhooks during re-runs
- Handles enterprise-scale repositories with massive dependency graphs

### PolicyCacheService Integration

While the raw storage interface exposes low-level caching primitives (`StoreCachedPolicyResults`, `GetCachedPolicyResults`), application code never calls them directly. Instead it uses the dedicated `PolicyCacheService` (`internal/services/policy_cache.go`) which:

1. Wraps the pure `PolicyService` to preserve single-responsibility (policy evaluation vs caching concern)
2. Applies configuration guards (`config.AppConfig.Storage.PolicyCache.Enabled`) so callers do not duplicate enablement checks
3. Generates consistent cache keys (`<policyType>:<owner>:<repo>:<sha>`) ensuring repository isolation matches other state keys
4. Adds OpenTelemetry spans/attributes for hit vs miss and size metrics
5. Handles TTL + max size parsing, falling back safely when misconfigured

Recommended usage pattern (handlers / processors):

```go
// In a policy processor or handler
result, err := h.policyCacheService.CheckVulnerabilityPolicyWithCache(ctx, payload, owner, repo, sha)
// Fallback to non-cached path is automatic when disabled
```

Do NOT bypass the service to call storage directly—this centralizes future enhancements (eviction strategies, metrics, versioned cache keys) without changing call sites.

Additional rationale and extension points are documented in [Policy Development Guide](./POLICY_DEVELOPMENT_GUIDE.md) and architectural motivations in [Architecture Patterns](./ARCHITECTURE_PATTERNS.md).

### Comprehensive State Access

#### StateMap Structure
The StateMap provides organized access to all state for a repository context:
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

#### Get All State
Retrieve complete state for a repository context in a single operation:
```go
func (s *StateService) GetAllState(ctx context.Context, owner, repo, sha string) (*StateMap, error)
```

### Key Features
- **Multi-Repository Support**: Repository isolation prevents cross-contamination
- **Type Safety**: Generic helpers ensure correct data types
- **Key Formatting**: Consistent key patterns with repository context
- **Error Handling**: Proper error wrapping and context
- **Deletion Support**: Cleanup methods for all state types
- **Comprehensive Access**: StateMap for organized state retrieval

## Configuration

Storage backend selection is controlled by environment variables:

```bash
# Storage type (required)
POLLY_STORAGE_TYPE=memory|valkey

# Basic Valkey configuration (required when POLLY_STORAGE_TYPE=valkey)
POLLY_VALKEY_ADDRESS=host:port
POLLY_VALKEY_USERNAME=username     # optional
POLLY_VALKEY_PASSWORD=password     # optional
POLLY_VALKEY_DB=0                  # optional, default: 0

# Advanced Valkey features (optional)
POLLY_VALKEY_ENABLE_SENTINEL=false              # Enable Sentinel mode
POLLY_VALKEY_SENTINEL_ADDRS=host1:port1,host2:port2  # Sentinel addresses
POLLY_VALKEY_SENTINEL_MASTER=mymaster           # Sentinel master name
POLLY_VALKEY_SENTINEL_USERNAME=sentinel_user    # Sentinel username
POLLY_VALKEY_SENTINEL_PASSWORD=sentinel_pass    # Sentinel password
POLLY_VALKEY_ENABLE_COMPRESSION=false           # Enable zlib compression
POLLY_VALKEY_ENABLE_OTEL=false                  # Enable OpenTelemetry (requires OTLP)
```

## Advanced Valkey Features

### Sentinel Support

Valkey Sentinel provides high availability and automatic failover for production deployments.

**Benefits**:
- Automatic master discovery and failover
- Multiple sentinel nodes for redundancy
- Health monitoring and notifications
- Split-brain protection

**Configuration Example**:
```bash
POLLY_VALKEY_ENABLE_SENTINEL=true
POLLY_VALKEY_SENTINEL_ADDRS=sentinel1:26379,sentinel2:26379,sentinel3:26379
POLLY_VALKEY_SENTINEL_MASTER=mymaster
```

**Deployment Considerations**:
- Deploy at least 3 sentinel instances for quorum
- Sentinel instances should be on separate nodes
- Monitor sentinel logs for failover events
- Test failover scenarios in staging

### Compression

Zlib compression reduces memory usage and network traffic for large payloads.

**Benefits**:
- Reduced memory footprint in Valkey
- Lower network bandwidth usage
- Improved performance for large state objects
- Transparent to application logic

**When to Enable**:
- Large PR numbers or complex state objects
- Network bandwidth constraints
- Memory-constrained Valkey instances
- High-frequency state operations

**Performance Impact**:
- CPU overhead for compression/decompression
- Reduced network I/O
- Lower memory usage in Valkey
- Best for payloads > 1KB

### OpenTelemetry Integration

Distributed tracing for Valkey operations provides visibility into storage performance.

**Features**:
- Automatic span creation for all operations
- Performance metrics and latency tracking
- Integration with existing OTLP infrastructure
- Error and timeout visibility

**Prerequisites**:
- OTLP must be enabled in main configuration
- OpenTelemetry collector or compatible endpoint
- Tracing infrastructure setup

**Metrics Captured**:
- Operation latency (Get, Set, Delete, Exists)
- Error rates and types
- Connection health and timeouts
- Compression ratios (when enabled)

### Factory Pattern
The storage factory creates backends based on configuration:
```go
store, err := storage.NewStore(config.Storage)
```

## Data Patterns

### Key Naming Convention
All keys follow a consistent multi-repository pattern:
- Format: `{owner}:{repo}:{keyType}:{sha}`
- PR Numbers: `{owner}:{repo}:pr_number:{sha}`
- Vulnerability Check Runs: `{owner}:{repo}:vuln_check_run_id:{sha}`
- License Check Runs: `{owner}:{repo}:license_check_run_id:{sha}`
- Workflow Runs: `{owner}:{repo}:workflow_run_id:{sha}`

**Example Keys:**
```
github-org:my-repo:pr_number:abc123...
github-org:my-repo:vuln_check_run_id:abc123...
another-org:different-repo:pr_number:def456...
```

### Repository Isolation
The multi-repository key format ensures complete isolation between repositories:
- Different repositories with the same SHA will have separate state
- Prevents accidental cross-repository state contamination
- Supports webhook environments serving multiple repositories

### Expiration Strategy
- **Default TTL**: 24 hours (configurable)
- **Rationale**: Longer than typical CI workflows but prevents indefinite accumulation
- **Automatic Cleanup**: Backend-specific expiration mechanisms

### Error Handling
- **Not Found**: Returns zero values (0, empty string) without error
- **Connection Errors**: Wrapped and logged for debugging
- **Serialization Errors**: Detailed error messages with context

## Usage Examples

### Storing PR Context
```go
// During pull request event
owner := "github-org"
repo := "my-repo"
sha := "abc123def456..."
prNumber := int64(42)

err := stateService.StorePRNumber(ctx, owner, repo, sha, prNumber)
if err != nil {
    log.Error("Failed to store PR context", "error", err, "owner", owner, "repo", repo)
    return err
}
```

### Retrieving PR Context
```go
// During workflow event
owner := "github-org"
repo := "my-repo"
sha := "abc123def456..."

prNumber, exists, err := stateService.GetPRNumber(ctx, owner, repo, sha)
if err != nil {
    log.Error("Failed to get PR number", "error", err, "owner", owner, "repo", repo)
    return err
}
if !exists {
    log.Warn("No PR context found for SHA", "sha", sha, "owner", owner, "repo", repo)
    return nil // Skip processing
}
```

### Managing Check Run State
```go
// Store check run ID after creation
owner := "github-org"
repo := "my-repo"
sha := "abc123def456..."

checkRunID := createCheckRun(...)
err := stateService.StoreVulnCheckRunID(ctx, owner, repo, sha, checkRunID)

// Retrieve for updates
checkRunID, exists, err := stateService.GetVulnCheckRunID(ctx, owner, repo, sha)
if err != nil {
    log.Error("Failed to get check run ID", "error", err)
    return err
}
if exists && checkRunID != 0 {
    updateCheckRun(checkRunID, result)
}
```

### Comprehensive State Retrieval
```go
// Get all state for a repository context
owner := "github-org"
repo := "my-repo"
sha := "abc123def456..."

stateMap, err := stateService.GetAllState(ctx, owner, repo, sha)
if err != nil {
    log.Error("Failed to get all state", "error", err)
    return err
}

// Check what state exists
if stateMap.HasPRNumber {
    log.Info("PR context available", "prNumber", stateMap.PRNumber)
}
if stateMap.HasVulnCheckRunID {
    log.Info("Vulnerability check run exists", "checkRunID", stateMap.VulnCheckRunID)
}
```

## Advanced Configuration Examples

### Production Deployment with Sentinel
```bash
# High-availability production setup
POLLY_STORAGE_TYPE=valkey
POLLY_VALKEY_ENABLE_SENTINEL=true
POLLY_VALKEY_SENTINEL_ADDRS=sentinel-1.prod:26379,sentinel-2.prod:26379,sentinel-3.prod:26379
POLLY_VALKEY_SENTINEL_MASTER=polly-master
POLLY_VALKEY_SENTINEL_USERNAME=polly-sentinel
POLLY_VALKEY_SENTINEL_PASSWORD=secure-sentinel-password
POLLY_VALKEY_USERNAME=polly-app
POLLY_VALKEY_PASSWORD=secure-app-password
POLLY_VALKEY_DB=0
POLLY_VALKEY_ENABLE_COMPRESSION=true
POLLY_VALKEY_ENABLE_OTEL=true
```

### Development Environment
```bash
# Simple development setup
POLLY_STORAGE_TYPE=valkey
POLLY_VALKEY_ADDRESS=localhost:6379
POLLY_VALKEY_ENABLE_COMPRESSION=false
POLLY_VALKEY_ENABLE_OTEL=false
```

### Performance-Optimized Setup
```bash
# Optimized for large payloads and high throughput
POLLY_STORAGE_TYPE=valkey
POLLY_VALKEY_ADDRESS=valkey-cluster.internal:6379
POLLY_VALKEY_ENABLE_COMPRESSION=true
POLLY_VALKEY_ENABLE_OTEL=true
POLLY_VALKEY_DB=1
```

## Testing

The storage layer includes comprehensive unit tests:
- **Memory Store**: `internal/storage/memory_test.go`
- **Valkey Store**: `internal/storage/valkey_test.go` (interface compliance and advanced features)
- **StateService**: `internal/services/state_test.go`
- **Factory**: `internal/storage/factory_test.go`

Tests cover:
- Basic CRUD operations
- Expiration behavior
- Concurrent access patterns
- Error handling scenarios
- Type conversion validation
- **Sentinel Configuration**: Connection and failover scenarios
- **Compression**: Compression/decompression functionality
- **OpenTelemetry**: Tracing integration and configuration

## Monitoring and Observability

### Metrics to Track
- Storage operation latency
- Hit/miss ratios for state lookups
- Storage backend connection health
- Key expiration rates
- Memory usage (for memory backend)

### Logging
All storage operations include structured logging with:
- Operation type (Get, Set, Delete)
- Key patterns (without sensitive data)
- Execution time
- Error details

### Tracing
Storage operations participate in OpenTelemetry tracing:
- Span creation for storage operations
- Error recording and status codes
- Operation attributes (backend type, key pattern)

## Migration Strategies

### From Memory to Valkey
1. Update configuration to use Valkey backend
2. Deploy with new configuration
3. Existing memory state will be lost (acceptable for transient PR context)
4. New events will use persistent storage

### Backend Switching
The storage interface allows seamless backend switching without code changes:
- Update `POLLY_STORAGE_TYPE` environment variable
- Restart application
- All business logic remains unchanged

## Troubleshooting

### Common Issues

#### Memory Backend
- **High Memory Usage**: Check for key expiration configuration
- **State Loss**: Expected behavior on restart, consider Valkey for persistence

#### Valkey Backend
- **Connection Failures**: Verify network connectivity and credentials
- **Serialization Errors**: Check data types being stored
- **Performance Issues**: Monitor Valkey server health and network latency

#### Sentinel Issues
- **Master Discovery Failed**: Verify sentinel addresses and master name
- **Frequent Failovers**: Check network stability and sentinel configuration
- **Split-Brain Scenarios**: Ensure minimum 3 sentinels and proper quorum
- **Authentication Errors**: Verify sentinel and master credentials separately

#### Compression Issues
- **High CPU Usage**: Monitor compression overhead, consider disabling for small payloads
- **Decompression Errors**: Check for data corruption or mixed compression states
- **Performance Degradation**: Profile compression vs. network benefits

#### OpenTelemetry Issues
- **Missing Traces**: Verify OTLP is enabled and collector is reachable
- **High Trace Volume**: Consider sampling configuration
- **Performance Impact**: Monitor tracing overhead in high-throughput scenarios

### Debug Commands
```bash
# Check storage configuration
grep POLLY_STORAGE_TYPE /path/to/config
grep POLLY_VALKEY /path/to/config

# Monitor Valkey operations (if using Valkey)
valkey-cli monitor

# Check sentinel status
valkey-cli -h sentinel-host -p 26379 sentinel masters
valkey-cli -h sentinel-host -p 26379 sentinel sentinels mymaster

# Test compression manually
echo "test data" | valkey-cli -x set test:key
valkey-cli get test:key

# Check application logs for storage operations
grep "valkey_store" /path/to/logs
grep "storage" /path/to/logs
```

## Future Enhancements

### Potential Improvements
- **Encryption**: Encrypt sensitive data at rest
- **Clustering**: Support for Valkey cluster deployments
- **Metrics**: Built-in Prometheus metrics export
- **Backup**: Automated backup strategies for critical state
- **Connection Pooling**: Advanced connection pool configuration
- **Circuit Breaker**: Resilience patterns for storage failures

### Interface Evolution
The storage interface is designed to be extensible:
- Additional backends (DynamoDB, PostgreSQL, etc.)
- Batch operations for performance
- Transaction support for complex operations
- Advanced querying capabilities

### Recently Implemented ✅
- **Compression**: ✅ Zlib compression for reduced storage footprint
- **Sentinel Support**: ✅ High availability with automatic failover
- **OpenTelemetry**: ✅ Distributed tracing integration
