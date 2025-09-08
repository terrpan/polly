<!-- Moved from docs/DEPENDENCY_ANALYSIS.md -->
<!-- Analysis of dependencies needed for Polly 2.0 plugin system implementation. -->
# Dependency Analysis for Polly 2.0

This document analyzes all suggested dependencies for Polly 2.0 to ensure we only add packages that provide real value.

## Summary

✅ **KEEP**: `github.com/hashicorp/go-plugin` - Essential for plugin system  
❌ **REMOVE**: `github.com/gorilla/mux` - Standard `http.ServeMux` is sufficient  
❌ **REMOVE**: `github.com/google/go-github/v57` - Already using v72 in current codebase  

## Detailed Analysis

### 1. `github.com/hashicorp/go-plugin` - ✅ ESSENTIAL

**Status**: **KEEP** - Core dependency for plugin architecture

**Why We Need It**:
- Plugin system is impossible without this library
- Provides RPC communication between Polly core and plugins
- Handles plugin lifecycle (start, stop, health checks)
- Enables process isolation and hot reloading
- Battle-tested (used by Terraform, Vault, Consul, Nomad)

**Usage in Polly 2.0**:
```go
// Plugin interface implementation
type PolicyPluginGRPC struct {
    plugin.Plugin
    Impl PolicyPlugin
}

// Plugin serving
plugin.Serve(&plugin.ServeConfig{
    HandshakeConfig: plugin.HandshakeConfig{
        ProtocolVersion:  1,
        MagicCookieKey:   "POLLY_PLUGIN",
        MagicCookieValue: "polly-plugin",
    },
    Plugins: map[string]plugin.Plugin{
        "policy": &VulnerabilityPlugin{},
    },
})
```

### 2. `github.com/gorilla/mux` - ❌ UNNECESSARY

**Status**: **REMOVE** - Current routing is sufficient

**Why We Don't Need It**:
- Polly has simple routing needs: `/webhook` and `/health`
- Standard `http.ServeMux` handles current requirements perfectly
- No need for path parameters, route groups, or advanced middleware
- Adding dependencies without clear benefit violates minimalism principle

**Current Routing (Works Fine)**:
```go
// internal/app/server.go
mux := http.NewServeMux()
mux.HandleFunc("/webhook", withMiddleware(...))
mux.HandleFunc("/health", withMiddleware(...))
```

**Would Only Be Needed If**:
- Complex API endpoints like `/api/plugins/{id}/config`
- Advanced middleware chaining requirements
- Route parameter extraction needs
- REST API with multiple HTTP methods per endpoint

### 3. `github.com/google/go-github/v57` - ❌ VERSION CONFLICT

**Status**: **REMOVE** - Already using newer version

**Why We Don't Need v57**:
- **Current version**: Already using `v72.0.0` in production
- **Version conflict**: Would create dependency hell
- **No benefits**: v57 doesn't provide anything v72 doesn't have
- **Backwards compatibility**: v72 is compatible with v57 usage patterns

**Current Usage (v72)**:
```go
// go.mod
github.com/google/go-github/v72 v72.0.0

// internal/clients/github.go
import "github.com/google/go-github/v72/github"
```

**For Polly 2.0**:
- Continue using v72 for consistency
- Leverage existing GitHub client infrastructure
- No need to duplicate GitHub API handling

## Additional Dependencies to Consider

### Dependencies We DON'T Need

**❌ `github.com/gin-gonic/gin`**
- Overkill for simple webhook + health endpoints
- Adds unnecessary complexity and dependencies

**❌ `github.com/gorilla/websocket`**
- No real-time communication requirements
- Plugin communication is RPC-based, not WebSocket

**❌ `github.com/sirupsen/logrus`**
- Already using Go's standard `slog` package
- `slog` is more performant and structured

**❌ Database ORMs** (GORM, etc.)
- Using Valkey for state storage
- No complex relational data requirements

### Dependencies We MIGHT Need Later

**🤔 `go.opentelemetry.io/otel`** (Observability)
- Already partially integrated in current codebase
- Plugin tracing could be valuable
- **Decision**: Evaluate during Phase 2

**🤔 `github.com/spf13/cobra`** (CLI)
- Could be useful for plugin management CLI
- Not needed for MVP
- **Decision**: Future enhancement

**🤔 `github.com/prometheus/client_golang`** (Metrics)  
- Plugin metrics could be valuable
- Not needed for MVP core functionality
- **Decision**: Phase 4+ enhancement

## Dependency Addition Guidelines

### Before Adding Any New Dependency, Ask:

1. **Is it essential for core functionality?**
   - Plugin system: YES → `go-plugin`
   - Enhanced routing: NO → stick with stdlib

2. **Does stdlib provide this capability?**
   - HTTP routing: YES → use `http.ServeMux`
   - JSON marshaling: YES → use `encoding/json`
   - Logging: YES → use `slog`

3. **Are we already using something similar?**
   - GitHub API: YES → use existing `go-github/v72`
   - Configuration: YES → use existing `viper`

4. **Does it solve a real problem or just look nice?**
   - Plugin communication: REAL PROBLEM → `go-plugin`
   - Pretty HTTP framework: NICE TO HAVE → skip

5. **What's the maintenance burden?**
   - Well-maintained HashiCorp library: LOW RISK
   - Abandoned or single-maintainer projects: HIGH RISK

### Approved Dependencies for Polly 2.0

**Phase 1 (MVP)**:
- `github.com/hashicorp/go-plugin` - Plugin system core

**Phase 2+ (Enhancements)**:
- TBD based on actual requirements, not speculation

### Implementation Steps Updated

The implementation steps have been updated to remove unnecessary dependencies:

```bash
# ✅ Only add what we actually need
go get github.com/hashicorp/go-plugin@latest
go mod tidy

# ❌ Removed unnecessary packages:
# go get github.com/gorilla/mux@latest          # Standard http.ServeMux sufficient
# go get github.com/google/go-github/v57@latest # Already using v72
```

## Benefits of This Approach

✅ **Minimal Attack Surface**: Fewer dependencies = fewer security vulnerabilities  
✅ **Faster Builds**: Less code to compile and link  
✅ **Simpler Maintenance**: Fewer packages to keep updated  
✅ **Reduced Complexity**: Standard library is well-understood  
✅ **Better Performance**: No unnecessary abstraction layers  
✅ **Easier Debugging**: Fewer moving parts to troubleshoot  

## Conclusion

For Polly 2.0 MVP, we need exactly **ONE new dependency**: `github.com/hashicorp/go-plugin`.

This disciplined approach to dependencies ensures:
- Fast, reliable builds
- Minimal security exposure  
- Simple maintenance overhead
- Clear separation between essential and nice-to-have features

We can always add more dependencies later if we encounter **actual limitations** with the standard library, not theoretical ones.
