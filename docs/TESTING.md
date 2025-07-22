# Testing Strategy

This project uses a comprehensive testing strategy with both unit tests and integration tests.

## Test Structure

The project uses `testing.Short()` to distinguish between unit tests and integration tests, replacing the previous build tag approach.

### Unit Tests
- Fast, isolated tests that don't require external dependencies
- Run by default with `go test ./...`
- Run explicitly with `go test -short ./...`
- Mock external dependencies where needed

### Integration Tests
- Test real integrations with external services using testcontainers
- Skipped when running with `-short` flag
- Require Docker to be available
- Use real Valkey instances for storage tests

## Running Tests

### Unit Tests Only (Fast)
```bash
go test -short ./...
```

### All Tests (Unit + Integration)
```bash
go test ./...
```

### Integration Tests Only
```bash
go test ./... -run Integration
```

### Specific Package Tests
```bash
# All storage tests
go test ./internal/storage/

# Only storage unit tests
go test -short ./internal/storage/

# Only storage integration tests
go test ./internal/storage/ -run Integration
```

## Test Implementation Guidelines

### Unit Tests
- Use `t.Short()` check to skip integration tests:
  ```go
  func TestSomething_Unit(t *testing.T) {
      // This is a unit test - no skip needed
      // Test implementation...
  }
  ```

### Integration Tests
- Always include `t.Skip()` for short mode:
  ```go
  func TestSomething_Integration(t *testing.T) {
      if testing.Short() {
          t.Skip("Skipping integration test in short mode")
      }

      // Integration test implementation with testcontainers...
  }
  ```

## Testcontainers Usage

Integration tests use [testcontainers](https://github.com/testcontainers/testcontainers-go) to spin up real dependencies:

```go
// Start Valkey container
redisContainer, err := redis.Run(ctx, "valkey/valkey:8-alpine")
require.NoError(t, err)

t.Cleanup(func() {
    if err := testcontainers.TerminateContainer(redisContainer); err != nil {
        t.Logf("failed to terminate container: %s", err)
    }
})

// Get connection details
host, err := redisContainer.Host(ctx)
require.NoError(t, err)

port, err := redisContainer.MappedPort(ctx, "6379")
require.NoError(t, err)

// Use in your tests...
```

## CI/CD Integration

The GitHub Actions workflow runs both unit and integration tests:

1. **Unit Tests**: `go test -v -race -short -coverprofile=coverage.out ./...`
2. **Integration Tests**: `go test -v -race -coverprofile=coverage_integration.out ./...`

## Storage Package Tests

The storage package includes comprehensive tests for:

### Factory Tests (`factory_test.go`)
- Store creation and configuration
- Type validation
- Integration tests with real Valkey connections

### Memory Store Tests (`memory_test.go`)
- Basic operations (set, get, delete, exists)
- Expiration handling
- Concurrent access
- Large-scale operations (integration)
- Complex data structures (integration)

### Valkey Store Tests (`valkey_test.go`)
- Interface compliance
- Constructor validation
- Sentinel configuration
- Compression configuration
- OpenTelemetry configuration
- Integration tests with real Valkey containers
- Concurrency testing with real connections
- Compression validation with real data

## Dependencies

### Test Dependencies
- `github.com/stretchr/testify` - Assertions and test utilities
- `github.com/testcontainers/testcontainers-go` - Container orchestration
- `github.com/testcontainers/testcontainers-go/modules/redis` - Valkey/Redis container support

### Runtime Requirements for Integration Tests
- Docker (for testcontainers)
- Available ports for container binding

## Best Practices

1. **Keep unit tests fast** - Mock external dependencies
2. **Use descriptive test names** - Include what's being tested and expected outcome
3. **Use subtests** - Group related test cases with `t.Run()`
4. **Clean up resources** - Use `t.Cleanup()` for proper resource management
5. **Test error cases** - Don't just test the happy path
6. **Use appropriate assertions** - `require` for failures that should stop the test, `assert` for failures that can continue
