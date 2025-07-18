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
    Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
    Get(ctx context.Context, key string, dest interface{}) error
    Delete(ctx context.Context, key string) error
    Exists(ctx context.Context, key string) (bool, error)
    Close() error
}
```

### Key Features
- **Context Support**: All operations accept context for cancellation and tracing
- **Generic Values**: Automatic JSON serialization for complex data types
- **Expiration**: Built-in TTL support for automatic cleanup
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

**Requirements**:
- Valkey or Redis server
- Network connectivity to storage server

**Configuration**:
```bash
POLLY_STORAGE_TYPE=valkey
POLLY_VALKEY_ADDRESS=localhost:6379
POLLY_VALKEY_USERNAME=your_username
POLLY_VALKEY_PASSWORD=your_password
POLLY_VALKEY_DB=0
```

## StateService

The StateService provides a business logic layer on top of the storage interface, managing application-specific state with type safety and key formatting.

**Location**: `internal/services/state.go`

### Managed State Types

#### PR Context
Maps commit SHAs to PR numbers for connecting workflow events to pull requests:
```go
func (s *StateService) StorePRNumber(ctx context.Context, sha string, prNumber int64) error
func (s *StateService) GetPRNumber(ctx context.Context, sha string) (int64, error)
```

#### Check Run State
Tracks GitHub check run IDs for security validations:
```go
// Vulnerability check runs
func (s *StateService) StoreVulnCheckRunID(ctx context.Context, sha string, checkRunID int64) error
func (s *StateService) GetVulnCheckRunID(ctx context.Context, sha string) (int64, error)

// License check runs
func (s *StateService) StoreLicenseCheckRunID(ctx context.Context, sha string, checkRunID int64) error
func (s *StateService) GetLicenseCheckRunID(ctx context.Context, sha string) (int64, error)
```

#### Workflow State
Manages workflow run IDs for handling re-runs and concurrent processing:
```go
func (s *StateService) StoreWorkflowRunID(ctx context.Context, sha string, workflowRunID int64) error
func (s *StateService) GetWorkflowRunID(ctx context.Context, sha string) (int64, error)
```

### Key Features
- **Type Safety**: Generic helpers ensure correct data types
- **Key Formatting**: Consistent key patterns across different state types
- **Error Handling**: Proper error wrapping and context
- **Deletion Support**: Cleanup methods for all state types

## Configuration

Storage backend selection is controlled by environment variables:

```bash
# Storage type (required)
POLLY_STORAGE_TYPE=memory|valkey

# Valkey configuration (required when POLLY_STORAGE_TYPE=valkey)
POLLY_VALKEY_ADDRESS=host:port
POLLY_VALKEY_USERNAME=username     # optional
POLLY_VALKEY_PASSWORD=password     # optional
POLLY_VALKEY_DB=0                  # optional, default: 0
```

### Factory Pattern
The storage factory creates backends based on configuration:
```go
store, err := storage.NewStore(config.Storage)
```

## Data Patterns

### Key Naming Convention
All keys follow a consistent pattern:
- PR Numbers: `polly:pr_number:{sha}`
- Vulnerability Check Runs: `polly:vuln_check_run_id:{sha}`
- License Check Runs: `polly:license_check_run_id:{sha}`
- Workflow Runs: `polly:workflow_run_id:{sha}`

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
err := stateService.StorePRNumber(ctx, commitSHA, prNumber)
if err != nil {
    log.Error("Failed to store PR context", "error", err)
    return err
}
```

### Retrieving PR Context
```go
// During workflow event
prNumber, err := stateService.GetPRNumber(ctx, commitSHA)
if err != nil {
    log.Error("Failed to get PR number", "error", err)
    return err
}
if prNumber == 0 {
    log.Warn("No PR context found for SHA", "sha", commitSHA)
    return nil // Skip processing
}
```

### Managing Check Run State
```go
// Store check run ID after creation
checkRunID := createCheckRun(...)
err := stateService.StoreVulnCheckRunID(ctx, commitSHA, checkRunID)

// Retrieve for updates
checkRunID, err := stateService.GetVulnCheckRunID(ctx, commitSHA)
if checkRunID != 0 {
    updateCheckRun(checkRunID, result)
}
```

## Testing

The storage layer includes comprehensive unit tests:
- **Memory Store**: `internal/storage/memory_test.go`
- **Valkey Store**: `internal/storage/valkey_test.go` (interface compliance)
- **StateService**: `internal/services/state_test.go`
- **Factory**: `internal/storage/factory_test.go`

Tests cover:
- Basic CRUD operations
- Expiration behavior
- Concurrent access patterns
- Error handling scenarios
- Type conversion validation

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

### Debug Commands
```bash
# Check storage configuration
grep POLLY_STORAGE_TYPE /path/to/config

# Monitor Valkey operations (if using Valkey)
valkey-cli monitor

# Check application logs for storage operations
grep "storage" /path/to/logs
```

## Future Enhancements

### Potential Improvements
- **Compression**: Reduce storage footprint for large payloads
- **Encryption**: Encrypt sensitive data at rest
- **Clustering**: Support for Valkey cluster deployments
- **Metrics**: Built-in Prometheus metrics export
- **Backup**: Automated backup strategies for critical state

### Interface Evolution
The storage interface is designed to be extensible:
- Additional backends (DynamoDB, PostgreSQL, etc.)
- Batch operations for performance
- Transaction support for complex operations
- Advanced querying capabilities
