<!-- Moved from docs/PLUGIN_SYSTEM_IMPLEMENTATION_GUIDE.md -->
# Plugin System Implementation Guide

This guide provides detailed implementation steps for extracting Polly's embedded policy processors into a plugin-based architecture as outlined in [ADR-012: Plugin System for Policy Extraction](../adr/ADR-012-plugin-system-policy-extraction.md).

## Plugin Interface Design Analysis

Before diving into implementation details, we need to decide on the plugin interface approach. Here's a comprehensive analysis of the three main options:

### Option A: Low-Level Raw Bytes Interface

```go
type PolicyPlugin interface {
    ProcessPayloads(ctx context.Context, payloads []byte, owner, repo, sha string) ([]byte, error)
    Initialize(config []byte) error
    Name() string
    Version() string
    PolicyType() string
}
```

**Pros:**
- ✅ **Maximum Flexibility**: Plugins can handle any payload format or custom data structures
- ✅ **Performance**: Zero serialization overhead in the RPC layer
- ✅ **Version Independence**: Polly core doesn't need to know about plugin-specific types
- ✅ **Language Agnostic**: Easy to support non-Go plugins (Python, Rust, etc.)
- ✅ **Minimal Dependencies**: No shared type dependencies between core and plugins

**Cons:**
- ❌ **Error Prone**: Manual serialization/deserialization in every plugin
- ❌ **No Type Safety**: Runtime errors from malformed data
- ❌ **Code Duplication**: Each plugin reimplements similar parsing logic
- ❌ **Poor Developer Experience**: Complex boilerplate for simple plugins
- ❌ **Testing Complexity**: Hard to mock and unit test

### Option B: Strongly-Typed Structs

```go
type PolicyPlugin interface {
    ProcessVulnerabilities(ctx context.Context, payloads []*VulnerabilityPayload, context ProcessContext) (*PolicyResult, error)
    ProcessSBOM(ctx context.Context, payloads []*SBOMPayload, context ProcessContext) (*PolicyResult, error)
    Initialize(config *PluginConfig) error
    Metadata() PluginMetadata
}

type VulnerabilityPayload struct {
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
    Summary        VulnerabilitySummary `json:"summary"`
    Metadata       ScanMetadata `json:"metadata"`
}

type PolicyResult struct {
    Passed      bool              `json:"passed"`
    Message     string           `json:"message"`
    Details     []string         `json:"details"`
    Annotations []Annotation     `json:"annotations"`
}
```

**Pros:**
- ✅ **Type Safety**: Compile-time validation of data structures
- ✅ **Excellent Developer Experience**: Clear contracts and IDE support
- ✅ **Reduced Boilerplate**: No manual serialization in plugins
- ✅ **Better Testing**: Easy mocking with concrete types
- ✅ **Documentation**: Types serve as living documentation
- ✅ **Validation**: Built-in structure validation

**Cons:**
- ❌ **Version Coupling**: Plugin and core must agree on type versions
- ❌ **Go-Only**: Difficult to support other languages
- ❌ **Breaking Changes**: Struct changes require coordinated updates
- ❌ **RPC Overhead**: go-plugin must serialize/deserialize complex types
- ❌ **Less Flexible**: Hard to support custom payload formats

### Option C: Hybrid SDK Approach

```go
// Core RPC interface (minimal, stable)
type PolicyPlugin interface {
    ProcessPayloads(ctx context.Context, request *ProcessRequest) (*ProcessResponse, error)
    Initialize(config *PluginConfig) error
    Metadata() *PluginMetadata
}

// ProcessRequest/Response are minimal, stable types
type ProcessRequest struct {
    PayloadType string          `json:"payload_type"`
    Data        json.RawMessage `json:"data"`
    Context     ProcessContext  `json:"context"`
}

// SDK layer provides typed helpers (optional)
package sdk

func ParseVulnerabilityPayloads(data json.RawMessage) ([]*VulnerabilityPayload, error)
func ParseSBOMPayloads(data json.RawMessage) ([]*SBOMPayload, error)
func NewPolicyResult(passed bool, message string) *ProcessResponse

// Plugin implementation can choose level of typing
func (p *MyPlugin) ProcessPayloads(ctx context.Context, request *ProcessRequest) (*ProcessResponse, error) {
    switch request.PayloadType {
    case "vulnerability":
        payloads, err := sdk.ParseVulnerabilityPayloads(request.Data)
        if err != nil { return nil, err }
        return p.handleVulnerabilities(ctx, payloads, request.Context)
    }
}
```

**Pros:**
- ✅ **Best of Both Worlds**: Type safety with flexibility
- ✅ **Gradual Adoption**: Can start simple and add typing later
- ✅ **Version Resilience**: Core interface stays stable, SDK evolves separately
- ✅ **Language Support**: Core interface simple enough for other languages
- ✅ **Optional Complexity**: Simple plugins don't need SDK
- ✅ **Extensible**: Easy to add new payload types without breaking changes

**Cons:**
- ❌ **Additional Complexity**: Two-layer architecture
- ❌ **SDK Maintenance**: Need to maintain SDK alongside core
- ❌ **Learning Curve**: Developers need to understand both layers
- ❌ **Potential Confusion**: Unclear which layer to use when

### How Hybrid Approach Achieves Language Agnosticism

The key insight is that **language agnosticism happens at the RPC layer**, while **type safety happens in language-specific SDKs**:

#### 1. Language-Agnostic RPC Interface
The core plugin communication uses simple JSON over standard protocols:

```json
// RPC Request (works in any language)
{
  "method": "ProcessPayloads",
  "params": {
    "payload_type": "vulnerability",
    "data": { /* raw JSON payload */ },
    "context": {
      "owner": "myorg",
      "repo": "myapp",
      "sha": "abc123"
    }
  }
}

// RPC Response (universal JSON)
{
  "result": {
    "passed": true,
    "message": "All checks passed",
    "details": ["No critical vulnerabilities found"],
    "annotations": []
  }
}
```

#### 2. Language-Specific SDKs Provide Type Safety

**Go SDK** (Compile-time type safety):
```go
// Type-safe structs with validation
type VulnerabilityPayload struct {
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
    Summary        VulnerabilitySummary `json:"summary"`
}

func ParseVulnerabilityPayloads(data json.RawMessage) ([]*VulnerabilityPayload, error) {
    var payloads []*VulnerabilityPayload
    return payloads, json.Unmarshal(data, &payloads)
}
```

**Python SDK** (Runtime validation + duck typing):
```python
from dataclasses import dataclass
from typing import List

@dataclass
class Vulnerability:
    id: str
    severity: str
    score: float
    title: str

def parse_vulnerability_payloads(data: dict) -> List[VulnerabilityPayload]:
    # Runtime validation with typed objects
    payloads = []
    for item in data:
        vulns = [Vulnerability(**v) for v in item['vulnerabilities']]
        payloads.append(VulnerabilityPayload(vulnerabilities=vulns, summary=item['summary']))
    return payloads
```

**TypeScript/JavaScript SDK** (Compile-time + runtime safety):
```typescript
interface Vulnerability {
    id: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    score: number;
    title: string;
}

function parseVulnerabilityPayloads(data: any[]): VulnerabilityPayload[] {
    // Runtime validation with TypeScript types
    return data.map(item => ({
        vulnerabilities: item.vulnerabilities as Vulnerability[],
        summary: item.summary as VulnerabilitySummary
    }));
}
```

## Recommendation Analysis

Based on Polly's specific needs and the project's emphasis on type safety (from the coding guidelines), here's my analysis:

### For Polly, Option C (Hybrid SDK) is Optimal Because:

1. **Type Safety Philosophy**: Aligns with your "Prioritize Type Safety" principle while maintaining flexibility
2. **Migration Path**: Existing processors can be extracted with full type safety via SDK
3. **Community Growth**: Simple core interface lowers barriers for community plugins
4. **Future Proofing**: Can evolve types in SDK without breaking core RPC contract
5. **Developer Choice**: Teams can choose their preferred abstraction level

### Proposed Implementation Strategy:

```go
// Phase 1: Minimal stable core interface
type PolicyPlugin interface {
    ProcessPayloads(ctx context.Context, request *ProcessRequest) (*ProcessResponse, error)
    Initialize(config *PluginConfig) error
    Metadata() *PluginMetadata
}

// Phase 2: Rich SDK with extracted processor logic
package sdk
type VulnerabilityProcessor struct {
    // Contains extracted VulnerabilityPolicyProcessor logic
}
func (v *VulnerabilityProcessor) Process(payloads []*VulnerabilityPayload) (*PolicyResult, error)

// Phase 3: Plugin implementations choose their approach
// Simple: Direct JSON handling
// Advanced: Full SDK with types
```

This approach gives you type safety where you want it (extracted processors) while keeping the plugin system flexible for future expansion.

## How Plugin Wiring Works

The plugin system uses **HashiCorp's go-plugin** library (not Go's built-in plugin package) for several critical advantages:

### Why HashiCorp go-plugin over Go's built-in plugin?

| Feature | Go's Built-in `plugin` | HashiCorp `go-plugin` |
|---------|----------------------|---------------------|
| **Process Isolation** | ❌ Same process | ✅ Separate processes |
| **Platform Support** | ❌ Linux/macOS only | ✅ All platforms |
| **Crash Safety** | ❌ Plugin crash = host crash | ✅ Plugin crash isolated |
| **Versioning** | ❌ Complex symbol conflicts | ✅ Version-agnostic RPC |
| **Production Ready** | ❌ Experimental | ✅ Battle-tested (Terraform, Vault, etc.) |

### Plugin Communication Flow

```
┌─────────────────┐    RPC over     ┌──────────────────────┐
│                 │    Unix Socket  │                      │
│   Polly Core    ├────────────────►│  Plugin Process      │
│                 │    or TCP       │                      │
│  PluginManager  │                 │  PolicyPlugin Impl   │
└─────────────────┘                 └──────────────────────┘
```

### Wiring Architecture

#### 1. **Plugin Interface Definition** (Shared Contract)
```go
// This interface is implemented by plugin processes
type PolicyPlugin interface {
    ProcessPayloads(ctx context.Context, payloads []byte, owner, repo, sha string) (PolicyProcessingResult, error)
    Initialize(config PluginConfig) error
    Name() string
    Version() string
    PolicyType() string
}
```

#### 2. **RPC Serialization Layer**
```go
// go-plugin handles the RPC marshalling/unmarshalling
type PolicyPluginRPC struct {
    plugin.Plugin  // Embeds go-plugin interface
}

// Client-side RPC wrapper (runs in Polly core)
type PolicyPluginRPCClient struct {
    client *rpc.Client
}

// Server-side RPC wrapper (runs in plugin process)
type PolicyPluginRPCServer struct {
    Impl PolicyPlugin  // The actual plugin implementation
}
```

#### 3. **Process Management**
```go
// Polly core starts plugin as separate process
pluginConfig := &plugin.ClientConfig{
    HandshakeConfig: handshakeConfig,  // Security handshake
    Plugins:         pluginMap,        // Available plugin types
    Cmd:            exec.Command("./vulnerability-plugin"), // Plugin binary
}

client := plugin.NewClient(pluginConfig)
rpcClient, _ := client.Client()
policyPlugin := rpcClient.Dispense("policy_plugin").(PolicyPlugin)
```

### Complete Plugin Wiring Example

Here's how a vulnerability plugin would be wired:

#### Plugin Binary (`cmd/plugins/vulnerability/main.go`)
```go
package main

import (
    "github.com/hashicorp/go-plugin"
    "github.com/terrpan/polly/internal/plugins"
)

// VulnerabilityPlugin implements the PolicyPlugin interface
type VulnerabilityPlugin struct {
    // Contains the extracted VulnerabilityPolicyProcessor logic
}

func (p *VulnerabilityPlugin) ProcessPayloads(ctx context.Context, payloads []byte, owner, repo, sha string) (handlers.PolicyProcessingResult, error) {
    // Deserialize payloads
    var vulnPayloads []*services.VulnerabilityPayload
    json.Unmarshal(payloads, &vulnPayloads)

    // Process using existing logic (extracted from VulnerabilityPolicyProcessor)
    return p.processVulnerabilityPayloads(ctx, vulnPayloads, owner, repo, sha)
}

func main() {
    // Register this plugin with go-plugin
    plugin.Serve(&plugin.ServeConfig{
        HandshakeConfig: plugins.HandshakeConfig,
        Plugins: map[string]plugin.Plugin{
            "policy_plugin": &plugins.PolicyPluginRPC{Impl: &VulnerabilityPlugin{}},
        },
    })
}
```

#### Polly Core Usage (`internal/handlers/policy_processing.go`)
```go
// Enhanced processVulnerabilityPolicies with plugin support
func processVulnerabilityPolicies(
    ctx context.Context,
    logger *slog.Logger,
    policyCacheService *services.PolicyCacheService,
    payloads []*services.VulnerabilityPayload,
    owner, repo, sha string,
) PolicyProcessingResult {

    // Try plugin first
    if pluginManager := getPluginManager(); pluginManager.HasPlugin("vulnerability") {
        result, err := pluginManager.ProcessPayloads(ctx, "vulnerability", payloads, owner, repo, sha)
        if err == nil {
            return result
        }
        logger.WarnContext(ctx, "Plugin failed, falling back to embedded", "error", err)
    }

    // Fallback to existing embedded processor
    processor := &VulnerabilityPolicyProcessor{}
    return processPoliciesWithStrategy(ctx, logger, policyCacheService, processor, payloads, owner, repo, sha)
}
```

#### Security Handshake
```go
// Prevents arbitrary binaries from connecting as plugins
var handshakeConfig = plugin.HandshakeConfig{
    ProtocolVersion:  1,
    MagicCookieKey:   "POLLY_PLUGIN",
    MagicCookieValue: "polly-policy-plugin",
}
```

## Plugin Independence and Shareability

**Critical Requirement**: Plugins must be buildable outside the Polly codebase and shareable between users.

This comprehensive implementation guide provides a complete roadmap for transforming Polly into a plugin-based architecture while maintaining all current functionality and enabling community-driven policy development.
