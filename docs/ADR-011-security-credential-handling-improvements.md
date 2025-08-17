# ADR-011: Security and Credential Handling Improvements

## Status
Accepted

## Context

The application handles sensitive credentials including GitHub App private keys, Valkey passwords, and GitHub tokens. Analysis of the current codebase revealed several security concerns:

### Current Security Issues

1. **Direct Credential Exposure Risk**: Found `fmt.Printf` statements in client code that could inadvertently log sensitive configuration errors
2. **No Configuration Sanitization**: Credentials stored as plain strings in config structs without protection against accidental logging or JSON marshaling
3. **Missing Request Correlation**: No systematic way to correlate logs and traces across request lifecycles for debugging production issues
4. **Lack of Credential Leak Prevention**: No tests or patterns to prevent accidental credential exposure in logs, error messages, or debug output

### Architectural Constraints

- Must maintain existing service architecture patterns
- Cannot break backward compatibility with current configuration
- Must work independently of OpenTelemetry tracing state
- Should follow existing logging patterns using `slog.Logger`

## Decision

We will implement a comprehensive security and credential handling system with four key components:

### 1. Secure Configuration Types

Implement `SecureString` type for credential fields:

```go
// internal/config/secure_types.go
type SecureString struct {
    value string
}

func (s SecureString) String() string {
    if s.value == "" { return "" }
    return "[REDACTED]"
}

func (s SecureString) MarshalJSON() ([]byte, error) {
    return json.Marshal("[REDACTED]")
}
```

**Configuration Updates:**
- `GitHubAppConfig.PrivateKey` → `SecureString`
- `ValkeyConfig.Password` → `SecureString`
- `ValkeyConfig.SentinelPassword` → `SecureString`
- `Config.GitHubToken` → `SecureString`

### 2. Request ID Middleware for Correlation

Independent request correlation system that works with or without tracing:

```go
// internal/app/middleware.go
func requestIDMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // 1. Honor external request IDs (X-Request-Id, X-Trace-Id)
        requestID := r.Header.Get("X-Request-Id")
        if requestID == "" {
            requestID = r.Header.Get("X-Trace-Id")
        }
        
        // 2. Generate UUID if no external ID (independent of tracing)
        if requestID == "" {
            requestID = uuid.New().String()
        }
        
        // 3. Store in context and return in response
        ctx := context.WithValue(r.Context(), "request_id", requestID)
        w.Header().Set("X-Request-Id", requestID)
        
        next.ServeHTTP(w, r.WithContext(ctx))
    }
}
```

### 3. Enhanced Logging with Request Correlation

```go
// internal/config/logger.go
func NewLoggerWithRequestID(ctx context.Context) *slog.Logger {
    logger := NewLogger()
    if requestID := ctx.Value("request_id"); requestID != nil {
        logger = logger.With("request_id", requestID)
    }
    return logger
}
```

### 4. Client Error Handling Without Logging

Remove direct logging from clients, delegate to service layer:

```go
// Before: Client logs directly (problematic)
fmt.Printf("failed to configure GitHub Enterprise URLs: %v\n", err)

// After: Client returns error, service handles logging
return nil, fmt.Errorf("failed to configure GitHub Enterprise URLs: %w", err)
```

## Implementation Strategy

### Phase 1: Configuration Sanitization (Foundation)
- Create `SecureString` type with backward-compatible getters
- Update config structs incrementally
- Implement configuration sanitization utilities

### Phase 2: Request ID Middleware (Correlation)
- Add UUID dependency
- Implement request ID middleware 
- Update route registration to apply middleware
- Enhance telemetry helper for optional trace correlation

### Phase 3: Audit and Fix Credential Exposure
- Remove problematic `fmt.Printf` from clients
- Implement error sanitization utilities
- Update service layer error handling patterns
- Apply request-aware logging throughout services

### Phase 4: Security Testing Framework
- Create credential leak detection tests
- Add configuration sanitization tests
- Implement integration tests for end-to-end security
- Add static analysis helpers for sensitive patterns

## Benefits

### Security Benefits
- **Zero Credential Exposure**: Automatic redaction in logs, JSON output, and string representations
- **Error Message Sanitization**: Sensitive data scrubbed from error messages
- **Test Coverage**: Automated detection of credential leaks

### Operational Benefits  
- **Request Correlation**: Single ID traces request from load balancer through all services
- **Tool Independence**: Works with or without tracing enabled
- **Debug Efficiency**: Cross-system correlation for production troubleshooting

### Architecture Benefits
- **Separation of Concerns**: Clients focus on API interactions, services handle logging
- **Backward Compatibility**: No breaking changes to existing functionality
- **Type Safety**: Compile-time prevention of credential misuse

## Correlation Example

```
Load Balancer: X-Request-Id: 12345, Status: 500
Application Logs: request_id="12345", error="Policy evaluation timeout"  
Jaeger Traces: request.id="12345" (if tracing enabled)
External Services: X-Request-Id: 12345 (propagated downstream)
```

## Testing Strategy

- **Unit Tests**: Each security component tested in isolation
- **Integration Tests**: End-to-end credential leak detection  
- **Security Tests**: Dedicated suite for credential handling patterns
- **Regression Tests**: Ensure no functional impact from security changes

## Risks and Mitigations

**Risk**: Breaking changes to configuration access patterns
**Mitigation**: Provide backward-compatible getter methods on `SecureString`

**Risk**: Performance impact from UUID generation
**Mitigation**: UUID generation is fast (< 1μs) with no external dependencies

**Risk**: Request ID middleware affecting non-HTTP contexts
**Mitigation**: Middleware only applies to HTTP handlers, internal service calls unaffected

## Success Criteria

- ✅ Zero credentials appear in log output (automated scanning)
- ✅ All HTTP requests have correlated request/trace IDs
- ✅ 100% test coverage for credential handling paths
- ✅ Static analysis passes for sensitive data patterns
- ✅ All existing functionality preserved without breaking changes

This approach provides comprehensive security improvements while maintaining clean architecture and ensuring production debugging capabilities remain robust.
