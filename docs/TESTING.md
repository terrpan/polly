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

### Test Suite Usage
For complex components with shared setup/teardown and state management, use `testify/suite`:
```go
type ComponentTestSuite struct {
    suite.Suite
    ctx             context.Context
    mockService     *mocks.MockService
    handler         *ComponentHandler
}

func (suite *ComponentTestSuite) SetupSuite() {
    suite.ctx = context.Background()
    // Shared setup for all tests
}

func (suite *ComponentTestSuite) SetupTest() {
    // Setup before each test
    suite.mockService = &mocks.MockService{}
    suite.handler = NewComponentHandler(suite.mockService)
}

func (suite *ComponentTestSuite) TestSomething() {
    // Test implementation
}

func TestComponentTestSuite(t *testing.T) {
    suite.Run(t, new(ComponentTestSuite))
}
```

### Simple Unit Tests
For simple functions without complex setup, use standard Go testing:
```go
func TestSomething_Unit(t *testing.T) {
    t.Run("success case", func(t *testing.T) {
        // Test implementation...
    })
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

- For complex integration tests with shared resources, use test suites:
  ```go
  type IntegrationTestSuite struct {
      suite.Suite
      container testcontainers.Container
      storage   storage.Store
  }

  func (suite *IntegrationTestSuite) SetupSuite() {
      if testing.Short() {
          suite.T().Skip("Skipping integration test suite in short mode")
      }

      // Setup testcontainers once for all tests
      var err error
      suite.container, err = redis.Run(suite.ctx, "valkey/valkey:8-alpine")
      suite.Require().NoError(err)
  }

  func (suite *IntegrationTestSuite) TearDownSuite() {
      if suite.container != nil {
          _ = testcontainers.TerminateContainer(suite.container)
      }
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

## Policy Cache Testing

The `PolicyCacheService` adds a caching layer around pure policy evaluation. Tests should verify:

1. Cache miss path: first call evaluates via OPA client mock
2. Cache hit path: second call for same (policyType, owner, repo, sha) avoids OPA evaluation
3. Disabled configuration: with `PolicyCache.Enabled=false` every call evaluates (no cache interaction)
4. Size limit enforcement: oversized result returns `ErrEntrySizeExceeded` (ensure no panic and evaluation still returns)
5. TTL expiry (optional, can be integration): simulate expiration by using short TTL and sleeping or injecting a clock if refactored

Example pattern (unit):
```go
opaMock := &mocks.OPAClient{}
opaMock.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return(mockResult, nil)

svc := services.NewPolicyService(opaMock, logger, telemetry, nil)
cache := services.NewPolicyCacheService(svc, stateSvc, logger, telemetry)

// 1st call → miss
res1, _ := cache.CheckVulnerabilityPolicyWithCache(ctx, payload, owner, repo, sha)
// 2nd call → hit (OPA Evaluate should still have been called only once)
res2, _ := cache.CheckVulnerabilityPolicyWithCache(ctx, payload, owner, repo, sha)
opaMock.AssertNumberOfCalls(t, "Evaluate", 1)
assert.Equal(t, res1, res2)
```

Integration tests (optional) can assert persistence across handler invocations using the Valkey backend.

## Service Registry (Container) Tests

The DI container (`internal/app/container.go`) uses a registry to construct services. Testing focuses on:
1. Construction success with minimal configuration (memory store)
2. Policy evaluators registered (expected keys present)
3. Cache service wraps policy service without altering evaluator map
4. Shared singletons (same pointer reused for services that should be unique)
5. Failure path: invalid storage type returns an error

Example assertions:
```go
c, err := app.NewContainer(cfg, logger)
require.NoError(t, err)
require.NotNil(t, c.Services.PolicyService)
require.NotNil(t, c.Services.PolicyCacheService)
assert.Same(t, c.Services.PolicyService, c.Services.PolicyCacheService.Underlying())
```

Keep container tests fast—avoid external dependencies except where specifically testing Valkey integration via testcontainers (then mark as integration and skip in short mode).

## Cross-File Consistency Tests (Optional)

Lightweight tests can enforce that documentation/code stay aligned, for example ensuring each evaluator registered in `policy.go` has a corresponding description in `POLICY_DEVELOPMENT_GUIDE.md`. These help detect drift after refactors.
