<!-- Moved from docs/ADR-012-plugin-system-policy-extraction.md -->
<!-- This is the authoritative ADR location under Polly 2.0 documentation hub. -->
# ADR-012: Polly 2.0 - Event Bus Architecture with Plugin Ecosystem

## Status
Accepted (MVP scope)

Authoritative API surface is defined in `../api/PLUGIN_API_REFERENCE.md` (v0.1). This ADR captures the architectural intent; discrepancies should be resolved in favor of the reference file, then reconciled back here.

## Context

Polly 1.x currently has hardcoded policy processing logic embedded within the core application through `VulnerabilityPolicyProcessor` and `LicensePolicyProcessor` in `internal/handlers/policy_processing.go`. While this monolithic approach served well for initial development, the architectural analysis reveals that a **fundamental transformation** is needed to unlock Polly's full potential as a policy orchestration platform.

### Why Polly 2.0 is Necessary

The proposed changes represent such a significant architectural shift that they warrant a major version increment:

1. **Complete Interface Redesign**: Moving from targeted policy processors to event bus architecture
2. **Fundamental Data Flow Changes**: From monolithic processing to distributed plugin ecosystem  
3. **New Distribution Model**: ORAS-based plugin distribution replacing embedded code
4. **Breaking Configuration Changes**: New event-driven plugin configuration model
5. **Ecosystem Transformation**: From application to platform with external plugin development

This is not an incremental improvement but a **platform evolution** that transforms Polly from a security tool into a **GitHub workflow orchestration platform** with unlimited extensibility through plugins.

> Error Categorization: See `../api/PLUGIN_API_REFERENCE.md` (Error Taxonomy v0.1) for transient vs permanent vs contract failure semantics used by the plugin supervisor.

### Current Architecture Limitations

1. **Tight Coupling**: Policy logic is tightly coupled to the core Polly binary, requiring full application recompilation for policy changes
2. **Monolithic Deployment**: All policy types must be deployed together, even if only subset is needed
3. **Limited Extensibility**: Adding new policy types requires core code changes and application rebuild
4. **Version Lock**: Policy logic versions are tied to Polly releases, preventing independent evolution
5. **Resource Constraints**: All policy processing shares the same process resources and failure domains
6. **Customization Barriers**: Organizations cannot easily customize policy logic without forking the entire project

### Current Policy Processing Flow

```
webhook_workflow.go
  → processVulnerabilityChecks()
	→ processVulnerabilityPolicies()
	  → VulnerabilityPolicyProcessor.ProcessPayloads()
		→ policyCacheService.CheckVulnerabilityPolicyWithCache()
		  → OPA evaluation
```

The existing processors contain substantial business logic (~200+ lines each) that includes:
- Payload validation and transformation
- OPA policy evaluation with caching
- Error handling and fallback logic
- Result formatting and violation reporting
- System availability checks and graceful degradation

## Decision

We will implement **Polly 2.0** - a complete architectural transformation from a monolithic policy processor into an **event-driven plugin orchestration platform** that revolutionizes how organizations implement GitHub workflow automation.

### Polly 2.0 Core Architectural Principles

1. **Event Bus First**: All GitHub webhooks transformed into enriched events and broadcast to plugin ecosystem
2. **Plugin Autonomy**: Plugins decide independently which events to process and what actions to take
3. **Helper Service Architecture**: Polly provides centralized services (GitHub API, OPA, caching) that plugins consume
4. **ORAS Distribution**: Plugins distributed as OCI artifacts with cryptographic verification and hot-reload
5. **Ecosystem Platform**: Transform Polly from tool to platform enabling unlimited extensibility

### Polly 2.0 Type Safety Strategy

Following Polly's established type safety philosophy, the plugin system maintains **compile-time type safety** while enabling cross-process communication:

#### **Interface Usage: Only at RPC Boundaries**
```go
// ✅ Interface required for RPC communication across process boundaries
type PolicyPlugin interface {
	HandleEvent(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error)
}

// ✅ Concrete implementation provides full type safety
type VulnerabilityPlugin struct {
	config PluginConfig  // Concrete struct
	logger *slog.Logger  // Concrete type
}
```

#### **Data Structures: Always Concrete Types**
```go
// ✅ NO interface{} in business logic - all data is strongly typed
type EnrichedEvent struct {
	Type        string            `json:"type"`         // Known string values
	Repository  *RepositoryInfo   `json:"repository"`   // Concrete struct
	PullRequest *PullRequestInfo  `json:"pull_request"` // Concrete struct, optional
}

// ❌ AVOID: Generic data bags that lose type safety
type EnrichedEvent struct {
	Type string                 `json:"type"`
	Data map[string]interface{} `json:"data"` // ❌ Type unsafe
}
```

#### **Policy Evaluation: Type-Safe Methods**
```go
// ✅ Following Polly's evaluatePolicy[T, R] pattern - type-safe at compile time
func (h *pollyHelpersImpl) EvaluateVulnerabilityPolicy(ctx context.Context, policyPath string, input VulnerabilityPolicyInput) ([]PolicyViolation, error) {
	return h.evaluatePolicy[VulnerabilityPolicyInput, []PolicyViolation](ctx, policyPath, input)
}

// ❌ AVOID: Generic method that requires runtime type assertions
func (h *pollyHelpersImpl) EvaluatePolicy(ctx context.Context, policyPath string, input interface{}) (interface{}, error) {
	// ❌ Runtime type assertions, no compile-time safety
}
```

#### **Benefits of This Approach**
1. **Compile-Time Safety**: All plugin data structures validated at compile time
2. **IDE Support**: Full autocomplete and type checking in plugin development  
3. **No Runtime Casting**: Plugin developers never need `interface{}` type assertions
4. **Minimal Interface Usage**: Interfaces only where technically required (RPC boundaries)
5. **Follows Polly Patterns**: Consistent with existing `evaluatePolicy[T, R]` type safety approach

#### **Type Safety at Plugin Development**
```go
// Plugin developers work with concrete, type-safe code
func (p *VulnerabilityPlugin) processPullRequest(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error) {
	// ✅ Type-safe field access - IDE knows event.PullRequest is *PullRequestInfo
	prNumber := event.PullRequest.Number  // Compile-time validated
    
	// ✅ Type-safe helper calls - input/output types known at compile time
	sboms, err := helpers.GetSBOMFromArtifacts(ctx, event.Repository.Owner.Login, event.Repository.Name, prNumber)
    
	// ✅ Type-safe policy evaluation - no interface{} needed
	violations, err := helpers.EvaluateVulnerabilityPolicy(ctx, "vulnerability/check_sbom", VulnerabilityPolicyInput{
		SBOMs:       sboms,          // []SBOMDocument - concrete type
		Repository:  event.Repository, // RepositoryInfo - concrete type
		PullRequest: event.PullRequest, // *PullRequestInfo - concrete type
	})
    
	// ✅ Type-safe result construction
	return &PolicyResult{Violations: violations}, nil
}
```

This approach provides **maximum type safety** while enabling the plugin architecture's cross-process communication requirements.

## Simple Plugin Management for MVP

For the MVP, we'll implement a **simple, single-instance plugin system** that focuses on core functionality rather than high availability. This gets us working quickly with the ability to add HA features later.

### **MVP Plugin Manager Architecture**

#### **1. Basic Plugin Manager**
```go
// Simple plugin manager - single instance, no coordination needed
type PluginManager struct {
    plugins map[string]PolicyPlugin
    config  PluginConfig
    logger  *slog.Logger
    
    // Optional: Basic plugin update polling
    updateTicker *time.Ticker
}

func NewPluginManager(config PluginConfig) *PluginManager {
    return &PluginManager{
        plugins: make(map[string]PolicyPlugin),
        config:  config,
        logger:  slog.Default(),
    }
}
```

#### **2. Simple Plugin Loading**
```go
func (pm *PluginManager) Start(ctx context.Context) error {
    // Load all configured plugins on startup
    for _, processorConfig := range pm.config.Processors {
        if err := pm.loadPlugin(ctx, processorConfig); err != nil {
            return fmt.Errorf("failed to load plugin %s: %w", processorConfig.Name, err)
        }
    }
    
    // Optional: Start basic update polling (for later enhancement)
    if pm.config.EnableUpdates {
        go pm.startBasicUpdatePolling(ctx)
    }
    
    pm.logger.InfoContext(ctx, "Plugin manager started", "plugins", len(pm.plugins))
    return nil
}

func (pm *PluginManager) loadPlugin(ctx context.Context, config ProcessorConfig) error {
    // For MVP: Start with local binary plugins, add OCI later
    pluginPath := pm.resolvePluginPath(config.Name, config.Image)
    
    plugin, err := pm.startPluginProcess(ctx, pluginPath)
    if err != nil {
        return fmt.Errorf("failed to start plugin process: %w", err)
    }
    
    // Initialize plugin with configuration
    if err := plugin.Initialize(config.Config); err != nil {
        return fmt.Errorf("failed to initialize plugin: %w", err)
    }
    
    pm.plugins[config.Name] = plugin
    pm.logger.InfoContext(ctx, "Plugin loaded", "name", config.Name, "path", pluginPath)
    
    return nil
}
```

#### **3. Basic Event Processing**
```go
// Simple event processing - broadcast to all plugins
func (pm *PluginManager) ProcessEvent(ctx context.Context, event EnrichedEvent) ([]PolicyResult, error) {
    var results []PolicyResult
    var errors []error
    
    // Process event through all loaded plugins
    for pluginName, plugin := range pm.plugins {
        // Apply basic event filtering if configured
        if !pm.shouldProcessEvent(pluginName, event) {
            continue
        }
        
        result, err := plugin.HandleEvent(ctx, event, pm.createHelpers(ctx))
        if err != nil {
            pm.logger.ErrorContext(ctx, "Plugin processing error", 
                "plugin", pluginName, "error", err)
            errors = append(errors, fmt.Errorf("plugin %s failed: %w", pluginName, err))
            continue
        }
        
        if result != nil && result.Processed {
            results = append(results, *result)
            pm.logger.DebugContext(ctx, "Plugin processed event", 
                "plugin", pluginName, "violations", len(result.Violations))
        }
    }
    
    // For MVP: Log errors but don't fail the whole event
    if len(errors) > 0 {
        pm.logger.WarnContext(ctx, "Some plugins failed", "errors", len(errors), "successful", len(results))
    }
    
    return results, nil
}
```

### **MVP Configuration - Keep It Simple**

```yaml
plugins:
  enabled: true
  
  # Simple plugin loading - no complex features for MVP
  processors:
    - name: vulnerability-plugin
      # For MVP: Start with local binaries, add OCI registry later
      image: "./plugins/vulnerability-plugin"  # Local path
      
      # Basic event filtering
      event_filters:
        - "pull_request.opened"
        - "pull_request.synchronize"
        - "workflow_run.completed"
      
      # OPA endpoint routing
      opa_endpoint: "vulnerability"
      
      config:
        logLevel: "info"
        
    - name: license-plugin
      image: "./plugins/license-plugin"  # Local path
      
      event_filters:
        - "pull_request.opened"
        - "push"
        
      opa_endpoint: "license"
      
      config:
        logLevel: "info"

# Simple OPA configuration
opa:
  serverURL: "http://localhost:8181"  # Single OPA instance for MVP
```

### **MVP Development Strategy**

#### **Phase 1: Core Foundation (Week 1-2)**
```go
// 1. Basic plugin interface and RPC communication
type PolicyPlugin interface {
    Name() string
    HandleEvent(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error)
    Initialize(config map[string]interface{}) error
    Shutdown() error
}

// 2. Simple helper services
type PollyHelpers interface {
    GetFile(ctx context.Context, owner, repo, sha, path string) (*FileContent, error)
    EvaluatePolicy(ctx context.Context, policyPath string, input interface{}) ([]PolicyViolation, error)
    CreateCheckRun(ctx context.Context, owner, repo, sha string, check CheckRunRequest) error
}

// 3. Basic event bus
type EventProcessor struct {
    pluginManager *PluginManager
    logger        *slog.Logger
}

func (ep *EventProcessor) ProcessWebhook(ctx context.Context, webhook WebhookPayload) error {
    event := ep.enrichEvent(webhook)
    results, err := ep.pluginManager.ProcessEvent(ctx, event)
    if err != nil {
        return err
    }
    
    return ep.handleResults(ctx, results)
}
```

#### **Phase 2: Plugin Extraction (Week 3-4)**
```bash
# Extract existing processors to simple plugins
1. Create vulnerability-plugin from VulnerabilityPolicyProcessor
2. Create license-plugin from LicensePolicyProcessor  
3. Test with existing webhook flows
4. Validate against current test suites
```

#### **Phase 3: Basic Distribution (Week 5-6)**
```bash
# Simple plugin distribution
1. Package plugins as standalone binaries
2. Add basic plugin discovery (local filesystem)
3. Implement plugin health checks
4. Add configuration validation
```

### **MVP Benefits - Get Working Fast**

✅ **Quick Implementation**: No complex coordination, leader election, or HA concerns  
✅ **Familiar Patterns**: Uses existing Go plugin patterns and RPC  
✅ **Easy Testing**: Single process, deterministic behavior  
✅ **Simple Debugging**: All logs in one place, straightforward error handling  
✅ **Proven Foundation**: Based on HashiCorp's go-plugin (used in Terraform, Vault, etc.)  
✅ **Enhancement Ready**: Architecture supports adding HA features later

### **Future Enhancement Path**

After MVP is working:
1. **Week 7+**: Add OCI registry support for plugin distribution
2. **Week 8+**: Implement plugin update polling and hot-reload
3. **Week 9+**: Add leader election for multi-replica deployments
4. **Week 10+**: Add comprehensive monitoring and health checks

### **MVP Success Criteria**

- [ ] Extract vulnerability and license processors to external plugins
- [ ] Event bus processes GitHub webhooks and distributes to plugins  
- [ ] Plugins can evaluate OPA policies and create check runs
- [ ] Zero regression in existing functionality
- [ ] Plugin development time < 2 hours for simple policies
- [ ] Performance within 10% of current monolithic approach

### Core Architectural Principles

1. **Extract, Don't Extend**: Move existing `VulnerabilityPolicyProcessor` and `LicensePolicyProcessor` logic into external plugins rather than maintaining both embedded and plugin approaches
2. **Infrastructure Focus**: Polly core becomes focused on GitHub integration, OPA infrastructure, plugin management, and state coordination
3. **Process Isolation**: Each plugin runs as a separate process using HashiCorp's go-plugin framework for RPC communication
4. **OCI Distribution**: Plugins distributed as OCI container images with hot-reload capabilities via registry polling
5. **Backward Compatibility**: Gradual migration with fallback support during transition period

### Plugin Event Filtering & OPA Bundle Architecture

#### Hybrid Event Filtering Strategy

**Configuration-Level Filtering (Performance)**
```yaml
event_filters: ["pull_request.opened", "workflow_run.completed"]
```
- **Purpose**: Reduce RPC overhead by filtering events before plugin invocation
- **Benefits**: Plugins only receive events they care about, improving system performance
- **Limitation**: Can only filter on basic event type/action combinations

**Plugin-Level Filtering (Business Logic)**  
```go
func (p *Plugin) shouldProcessEvent(event EnrichedEvent) bool {
    // Complex conditions that require event data inspection
    return event.PullRequest != nil && p.hasSensitiveFiles(event.PullRequest.ChangedFiles)
}
```
- **Purpose**: Complex business logic that can't be expressed in simple filters
- **Benefits**: Plugin can inspect event payload, repository context, file changes, etc.
- **Use Cases**: File-based filtering, workflow name matching, conditional processing

#### OPA Bundle Strategy - Complete Separation of Concerns

**Plugin Configuration: Infrastructure Routing Only**
```yaml
- name: vulnerability-plugin
  opa_endpoint: "vulnerability"  # WHERE to evaluate (routing only)
  config:
    logLevel: "info"             # Operational config only
```

**OPA Bundle Management: External to Polly**
```rego
# vulnerability/check_sbom.rego (managed outside Polly)
package vulnerability

# CVE database - updated independently via OPA bundle system
known_cves := {
    "CVE-2024-12345": {"severity": "HIGH", "affected_packages": ["lodash@4.17.20"]},
    "CVE-2024-12346": {"severity": "CRITICAL", "affected_packages": ["axios@0.21.1"]},
    # ... thousands more, updated daily by security team
}

# Severity thresholds - configured in OPA bundle, not Polly
severity_config := {
    "block_severity": ["CRITICAL", "HIGH"],
    "warn_severity": ["MEDIUM"],
    "ignore_dev_deps": true
}

# Policy evaluation logic - all in OPA
violations[violation] {
    sbom := input.sboms[_]
    package := sbom.packages[_]
    cve := known_cves[cve_id]
    
    # All policy logic lives here, not in plugin or Polly config
    package.name in cve.affected_packages
    cve.severity in severity_config.block_severity
    
    violation := {
        "cve_id": cve_id,
        "package": package.name,
        "severity": cve.severity,
        "description": sprintf("Package %s is affected by %s (%s)", [package.name, cve_id, cve.severity])
    }
}
```

#### Configuration Responsibilities

| **Polly Config**                                | **OPA Bundle (External)**                       |
|--------------------------------------------------|--------------------------------------------------|
| ✅ **opa_endpoint**: Routing to OPA instance    | ✅ **Policy Logic**: All business rules         |
| ✅ **event_filters**: Performance optimization  | ✅ **CVE Database**: Updated independently       |
| ✅ **logLevel**: Plugin operational settings    | ✅ **Thresholds**: Severity, allowlists, etc.   |
| ❌ **NOT**: Policy rules, CVE data, thresholds  | ❌ **NOT**: Infrastructure routing              |

#### Policy Update Flow (Zero Polly Configuration Changes)

```
Security Team Updates CVE Database
    ↓
OPA Bundle System (external to Polly)
    ↓
OPA Instance Auto-Updates Bundle
    ↓  
Plugin Calls Polly → OPA (same endpoint)
    ↓
OPA Evaluates with New CVE Data
    ↓
New Vulnerabilities Detected (No Config Changes)
```

#### Polly's Role: Simple OPA Proxy

```go
// PollyHelpers implementation - just proxies to configured OPA endpoint
func (h *PollyHelpers) EvaluatePolicy(ctx context.Context, policyPath string, input interface{}) ([]PolicyViolation, error) {
    // Get OPA endpoint from plugin config
    opaURL := h.getOPAEndpointForPlugin(h.currentPlugin)
    
    // Simple proxy request - no policy management
    response, err := h.opaClient.Query(ctx, opaURL, policyPath, input)
    if err != nil {
        return nil, fmt.Errorf("OPA evaluation failed: %w", err)
    }
    
    // Convert OPA response to standard format
    return h.convertOPAResponse(response), nil
}
```

**Polly does NOT**:
- ❌ Manage OPA bundles
- ❌ Configure policy rules  
- ❌ Update CVE databases
- ❌ Set severity thresholds

**Polly ONLY**:
- ✅ Routes plugin requests to correct OPA endpoint
- ✅ Provides authentication/authorization to OPA
- ✅ Converts OPA responses to standard format
- ✅ Caches OPA responses for performance
- ✅ **Centralized GitHub API Gateway** - all GitHub operations proxied through Polly
- ✅ **CI System Integration** - unified interface for GitHub Actions, GitLab CI, Jenkins, etc.
- ✅ **Rate Limiting & Authentication** - manages API limits and credentials for all plugins
- ✅ **Webhook Processing** - receives, enriches, and distributes all CI/SCM events

#### Polly Core Responsibilities
- **GitHub Integration**: Webhook handling, event enrichment, check run management, PR comments
- **CI System Gateway**: Unified interface for GitHub Actions, GitLab CI, Jenkins, CircleCI, etc.
- **Event Bus**: Broadcasting enriched events to all plugins and processing plugin results
- **Helper Services**: Centralized file fetching, CI artifact access, OPA evaluation, GitHub API operations
- **State Management**: Artifact storage, check run IDs, workflow state persistence  
- **Observability**: Metrics, tracing, logging aggregation across all plugins
- **API Gateway**: Rate limiting, authentication, and caching for all external API calls

#### Plugin Responsibilities  
- **Event Filtering**: Deciding which events to process based on plugin-specific business logic
- **Policy Logic**: Domain-specific policy evaluation using data from Polly helpers
- **Result Formatting**: Converting policy violations into GitHub check runs and comments
- **Cross-Event Intelligence**: Handling complex workflows that span multiple GitHub event types

### CI System Gateway Architecture

#### Centralized CI/SCM Integration Strategy

**Polly as Universal CI Gateway**:
Polly acts as a **centralized gateway** for all CI/SCM system interactions, providing plugins with a **unified interface** regardless of the underlying platform.

```go
// Polly abstracts CI system differences for plugins
func (p *VulnerabilityPlugin) processPullRequest(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error) {
    // Plugin doesn't need to know if this is GitHub, GitLab, or Bitbucket
    files, err := helpers.ListPRFiles(ctx, event.Repository.Owner.Login, event.Repository.Name, event.PullRequest.Number)
    if err != nil {
        return nil, fmt.Errorf("failed to get PR files: %w", err)
    }
    
    // Plugin doesn't handle CI-specific artifact formats
    sboms, err := helpers.GetSBOMFromArtifacts(ctx, event.Repository.Owner.Login, event.Repository.Name, event.WorkflowRun.ID)
    if err != nil {
        return nil, fmt.Errorf("failed to get SBOMs: %w", err)
    }
    
    // Plugin doesn't manage API rate limits or authentication
    err = helpers.CreateCheckRun(ctx, event.Repository.Owner.Login, event.Repository.Name, event.PullRequest.Head.SHA, checkRun)
    if err != nil {
        return nil, fmt.Errorf("failed to create check run: %w", err)
    }
    
    return &PolicyResult{Processed: true, Violations: violations}, nil
}
```

#### Multi-Platform CI Support Strategy

**Current Focus: GitHub Actions**
```yaml
# Phase 1: GitHub-first implementation
ci_systems:
  github:
    enabled: true
    api_url: "https://api.github.com"
    webhook_secret: "github-webhook-secret"
    app_credentials: "github-app-private-key"
```

**Future: Multi-CI Platform Support**
```yaml
# Phase 2+: Multi-platform CI gateway
ci_systems:
  github:
    enabled: true
    api_url: "https://api.github.com"
    webhook_secret: "github-webhook-secret"
    
  gitlab:
    enabled: true
    api_url: "https://gitlab.com/api/v4"
    webhook_secret: "gitlab-webhook-secret"
    access_token: "gitlab-access-token"
    
  jenkins:
    enabled: true
    api_url: "https://jenkins.company.com"
    webhook_secret: "jenkins-webhook-secret"
    credentials: "jenkins-api-token"
    
  circleci:
    enabled: true
    api_url: "https://circleci.com/api/v2"
    webhook_secret: "circleci-webhook-secret"
    api_token: "circleci-api-token"
```

#### Plugin Benefits from Centralized Gateway

**1. Simplified Plugin Development**
- Plugins use **one interface** for all CI systems
- No need to handle GitHub vs GitLab API differences
- No webhook parsing complexity per CI system

**2. Operational Benefits**  
- **Centralized Rate Limiting**: Polly manages API limits across all plugins
- **Unified Authentication**: Single point for managing CI system credentials
- **Consistent Caching**: File content, artifacts, metadata cached once for all plugins
- **Error Handling**: Standardized retry, backoff, and failure patterns

**3. Future-Proof Architecture**
- Adding new CI systems requires **zero plugin changes**
- Plugin ecosystem works with any CI platform Polly supports
- Organizations can migrate CI systems without plugin rewrites

#### CI System Abstraction Layer

```go
// internal/services/ci_gateway.go
type CISystemGateway interface {
    // File operations
    GetFile(ctx context.Context, repo Repository, sha, path string) (*FileContent, error)
    GetFiles(ctx context.Context, repo Repository, sha string, paths []string) ([]FileContent, error)
    
    // PR/MR operations  
    ListPRFiles(ctx context.Context, repo Repository, prNumber int) ([]FileChange, error)
    CreatePRComment(ctx context.Context, repo Repository, prNumber int, comment string) error
    
    // Build/Pipeline operations
    GetWorkflowArtifacts(ctx context.Context, repo Repository, runID int64) ([]Artifact, error)
    GetTestResults(ctx context.Context, repo Repository, runID int64) ([]TestResult, error)
    
    // Status operations
    CreateCheckRun(ctx context.Context, repo Repository, sha string, check CheckRunRequest) error
    SetCommitStatus(ctx context.Context, repo Repository, sha, state, description string) error
}

// Implementations for each CI system
type GitHubGateway struct { /* GitHub API client */ }
type GitLabGateway struct { /* GitLab API client */ }
type JenkinsGateway struct { /* Jenkins API client */ }

// Polly routes based on repository configuration
func (s *CIGatewayService) GetFile(ctx context.Context, owner, repo, sha, path string) (*FileContent, error) {
    gateway := s.getGatewayForRepo(owner, repo) // GitHub, GitLab, etc.
    return gateway.GetFile(ctx, Repository{Owner: owner, Name: repo}, sha, path)
}
```

This architecture positions Polly as a **universal CI orchestration platform** that can work with any CI/SCM system while providing plugins with a simple, consistent interface.

```go
// Enhanced plugin interface - infrastructure focused
// Interface required for RPC boundary, but all data types are concrete structs
type PolicyPlugin interface {
    // Metadata - all return concrete types
    Name() string
    Version() string
    SupportedEvents() []string  // Plugin advertises what it can handle
    
    // Event handling - strongly typed event and result structs
    HandleEvent(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error)
    
    // Lifecycle management
    Initialize(config PluginConfig) error
    Shutdown() error
    Health() error
}

// Helper services - centralized CI/SCM gateway
// Interface required for RPC, but concrete implementation in Polly core
type PollyHelpers interface {
    // Repository file operations - access files from repository at specific commit/PR
    // As a plugin developer, I want to access a file in the repository of a PR or commit
    GetFile(ctx context.Context, owner, repo, sha, path string) (*FileContent, error)
    GetFiles(ctx context.Context, owner, repo, sha string, paths []string) ([]FileContent, error)
    GetPRFiles(ctx context.Context, owner, repo string, prNumber int, paths []string) ([]FileContent, error) // Files at PR head commit
    
    // CI/Artifact operations - access build outputs and CI artifacts  
    // As a plugin developer, I want to access files that are artifacts or build outputs of a CI run
    GetWorkflowArtifacts(ctx context.Context, owner, repo string, runID int64) ([]Artifact, error)
    GetArtifactFile(ctx context.Context, owner, repo string, runID int64, artifactName, filePath string) (*FileContent, error)
    GetSBOMFromArtifacts(ctx context.Context, owner, repo string, runID int64) ([]SBOMDocument, error)
    GetTestResults(ctx context.Context, owner, repo string, runID int64) ([]TestResult, error)
    GetBuildLogs(ctx context.Context, owner, repo string, runID int64) ([]BuildLog, error)
    
    // OPA evaluation - type-safe policy evaluation with generics
    // Following Polly's evaluatePolicy[T, R] pattern for compile-time type safety
    EvaluateVulnerabilityPolicy(ctx context.Context, policyPath string, input VulnerabilityPolicyInput) ([]PolicyViolation, error)
    EvaluateLicensePolicy(ctx context.Context, policyPath string, input LicensePolicyInput) ([]PolicyViolation, error)
    EvaluateCustomPolicy(ctx context.Context, policyPath string, input interface{}) ([]PolicyViolation, error) // Only for custom policies
    
    // GitHub/CI operations - all parameters are concrete types
    CreateCheckRun(ctx context.Context, owner, repo, sha string, check CheckRunRequest) error
    UpdateCheckRun(ctx context.Context, owner, repo string, checkRunID int64, update CheckRunUpdate) error
    CreatePRComment(ctx context.Context, owner, repo string, prNumber int, comment string) error
    SetCommitStatus(ctx context.Context, owner, repo, sha, state, description string) error
    
    // Repository operations - strongly typed returns
    GetRepositoryMetadata(ctx context.Context, owner, repo string) (*RepositoryInfo, error)
    ListPRFiles(ctx context.Context, owner, repo string, prNumber int) ([]FileChange, error)
}

// Plugin configuration - infrastructure only, all concrete types
type PluginConfig struct {
    Name         string                 `json:"name"`
    Registry     string                 `json:"registry"`      // OCI registry path
    EventFilters []string               `json:"event_filters"` // Pre-filter events
    OPAEndpoint  string                 `json:"opa_endpoint"`  // Which OPA instance to use
    Config       map[string]interface{} `json:"config"`        // Plugin operational config
}

// All event data is concrete, type-safe structs - NO interface{} in business logic
type EnrichedEvent struct {
    Type        string            `json:"type"`         // "pull_request", "workflow_run", etc.
    Action      string            `json:"action"`       // "opened", "completed", etc.
    Repository  *RepositoryInfo   `json:"repository"`
    PullRequest *PullRequestInfo  `json:"pull_request,omitempty"`
    WorkflowRun *WorkflowRunInfo  `json:"workflow_run,omitempty"`
    CheckRun    *CheckRunInfo     `json:"check_run,omitempty"`
    Metadata    map[string]string `json:"metadata"`     // Additional context
}

// Policy evaluation input types - type-safe, no interface{}
type VulnerabilityPolicyInput struct {
    SBOMs       []SBOMDocument    `json:"sboms"`
    Repository  RepositoryInfo    `json:"repository"`
    PullRequest *PullRequestInfo  `json:"pull_request,omitempty"`
    WorkflowRun *WorkflowRunInfo  `json:"workflow_run,omitempty"`
}

type LicensePolicyInput struct {
    SBOMs       []SBOMDocument    `json:"sboms"`
    Repository  RepositoryInfo    `json:"repository"`
    PullRequest *PullRequestInfo  `json:"pull_request,omitempty"`
    WorkflowRun *WorkflowRunInfo  `json:"workflow_run,omitempty"`
}

// All result types are concrete structs
type PolicyResult struct {
    Processed  bool              `json:"processed"`    // Did plugin handle this event?
    Violations []PolicyViolation `json:"violations"`   // Policy violations found
    CheckRun   *CheckRunRequest  `json:"check_run,omitempty"`
    Comments   []CommentRequest  `json:"comments,omitempty"`
}

// File and artifact data structures for plugin file access
type FileContent struct {
    Path        string `json:"path"`         // File path in repository
    Content     string `json:"content"`      // Base64 encoded content
    Size        int64  `json:"size"`         // File size in bytes
    SHA         string `json:"sha"`          // Git SHA of file
    Encoding    string `json:"encoding"`     // "base64" or "utf-8"
    Metadata    map[string]string `json:"metadata,omitempty"` // Additional file info
}

type Artifact struct {
    ID          int64             `json:"id"`           // CI system artifact ID  
    Name        string            `json:"name"`         // Artifact name (e.g., "build-outputs")
    Size        int64             `json:"size"`         // Total size in bytes
    Files       []ArtifactFile    `json:"files"`        // Files within artifact
    DownloadURL string            `json:"download_url"` // URL to download artifact
    Metadata    map[string]string `json:"metadata,omitempty"` // CI-specific metadata
}

type ArtifactFile struct {
    Path     string `json:"path"`     // File path within artifact
    Size     int64  `json:"size"`     // File size
    SHA      string `json:"sha"`      // File checksum
    MimeType string `json:"mime_type,omitempty"` // Content type
}

type SBOMDocument struct {
    Format   string            `json:"format"`   // "spdx", "cyclonedx", etc.
    Version  string            `json:"version"`  // Format version
    Content  string            `json:"content"`  // JSON/XML content
    Source   string            `json:"source"`   // Source artifact/file path
    Metadata map[string]string `json:"metadata,omitempty"`
}

type TestResult struct {
    Suite     string            `json:"suite"`     // Test suite name
    Status    string            `json:"status"`    // "passed", "failed", "skipped"
    Duration  int64             `json:"duration"`  // Duration in milliseconds
    Tests     []TestCase        `json:"tests"`     // Individual test cases
    Coverage  *CoverageReport   `json:"coverage,omitempty"` // Code coverage data
    Metadata  map[string]string `json:"metadata,omitempty"`
}

type TestCase struct {
    Name     string `json:"name"`     // Test case name
    Status   string `json:"status"`   // "passed", "failed", "skipped"  
    Duration int64  `json:"duration"` // Duration in milliseconds
    Error    string `json:"error,omitempty"` // Error message if failed
}

type CoverageReport struct {
    Percentage  float64           `json:"percentage"`   // Overall coverage percentage
    Lines       int64             `json:"lines"`        // Total lines
    Covered     int64             `json:"covered"`      // Covered lines
    Files       []FileCoverage    `json:"files"`        // Per-file coverage
    Metadata    map[string]string `json:"metadata,omitempty"`
}

type FileCoverage struct {
    Path        string  `json:"path"`        // File path
    Percentage  float64 `json:"percentage"`  // File coverage percentage
    Lines       int64   `json:"lines"`       // Total lines in file
    Covered     int64   `json:"covered"`     // Covered lines in file
}

type BuildLog struct {
    Job      string            `json:"job"`      // Job name/ID
    Stage    string            `json:"stage"`    // Build stage (e.g., "build", "test", "deploy")
    Content  string            `json:"content"`  // Log content (may be truncated)
    URL      string            `json:"url"`      // URL to full log
    Status   string            `json:"status"`   // "success", "failure", "cancelled"
    Duration int64             `json:"duration"` // Duration in milliseconds
    Metadata map[string]string `json:"metadata,omitempty"`
}

type PolicyViolation struct {
    Severity    string `json:"severity"`     // "CRITICAL", "HIGH", "MEDIUM", "LOW"
    Title       string `json:"title"`
    Description string `json:"description"`
    Component   string `json:"component,omitempty"`  // Package, file, etc.
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Example plugin - type-safe implementation with concrete types
type VulnerabilityPlugin struct {
    config PluginConfig
    logger *slog.Logger
}

func (p *VulnerabilityPlugin) HandleEvent(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error) {
    // Type-safe event filtering - no interface{} casting
    if !p.shouldProcessEvent(event) {
        return &PolicyResult{Processed: false}, nil
    }
    
    // Type-safe event type switching
    switch event.Type {
    case "pull_request":
        return p.processPullRequest(ctx, event, helpers)
    case "workflow_run":
        return p.processWorkflowRun(ctx, event, helpers)
    default:
        return &PolicyResult{Processed: false}, nil
    }
}

func (p *VulnerabilityPlugin) processPullRequest(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error) {
    // Type-safe field access - event.PullRequest is *PullRequestInfo, not interface{}
    if event.PullRequest == nil {
        return nil, fmt.Errorf("pull request event missing pull request data")
    }
    
    // Get SBOM files from PR - all types are concrete
    sboms, err := helpers.GetSBOMFromArtifacts(ctx, event.Repository.Owner.Login, event.Repository.Name, event.PullRequest.Head.SHA)
    if err != nil {
        return nil, fmt.Errorf("failed to get SBOMs: %w", err)
    }
    
    // Type-safe policy input construction - no interface{} needed
    policyInput := VulnerabilityPolicyInput{
        SBOMs:       sboms,
        Repository:  event.Repository,
        PullRequest: event.PullRequest,
    }
    
    // Evaluate using OPA with type-safe helper method
    // Following Polly's evaluatePolicy[T, R] pattern for compile-time type safety
    violations, err := helpers.EvaluateVulnerabilityPolicy(ctx, "vulnerability/check_sbom", policyInput)
    if err != nil {
        return nil, fmt.Errorf("vulnerability policy evaluation failed: %w", err)
    }
    
    // Type-safe result construction
    return &PolicyResult{
        Processed:  true,
        Violations: violations,
        CheckRun: &CheckRunRequest{
            Name:       "Security / Vulnerability Scan",
            Status:     p.getCheckStatus(violations),
            Summary:    p.formatSummary(violations),
        },
    }, nil
}

// Example: Plugin accessing repository files and CI artifacts
func (p *VulnerabilityPlugin) processWorkflowRun(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error) {
    if event.WorkflowRun == nil {
        return nil, fmt.Errorf("workflow run event missing workflow data")
    }

    // Example 1: Access repository files at specific commit
    // "As a plugin developer, I want to access a file in the repository of a PR or commit"
    configFiles, err := helpers.GetFiles(ctx, 
        event.Repository.Owner.Login, 
        event.Repository.Name, 
        event.WorkflowRun.HeadSHA,
        []string{"package.json", "requirements.txt", "go.mod"})
    if err != nil {
        p.logger.Warn("Failed to get dependency files", "error", err)
    }

    // Access single file with error handling
    dockerfile, err := helpers.GetFile(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name, 
        event.WorkflowRun.HeadSHA,
        "Dockerfile")
    if err != nil {
        p.logger.Info("No Dockerfile found", "error", err)
    } else {
        // Parse dockerfile content (base64 decoded)
        p.logger.Info("Found Dockerfile", "size", dockerfile.Size, "encoding", dockerfile.Encoding)
    }

    // Example 2: Access CI artifacts and build outputs
    // "As a plugin developer, I want to access files that are artifacts or build outputs of a CI run"
    
    // Get all artifacts from the workflow run
    artifacts, err := helpers.GetWorkflowArtifacts(ctx, 
        event.Repository.Owner.Login,
        event.Repository.Name, 
        event.WorkflowRun.ID)
    if err != nil {
        return nil, fmt.Errorf("failed to get workflow artifacts: %w", err)
    }

    // Look for specific artifacts (SBOM, test results, etc.)
    var sbomArtifact *Artifact
    var testArtifact *Artifact
    
    for _, artifact := range artifacts {
        switch artifact.Name {
        case "sbom-report", "software-bill-of-materials":
            sbomArtifact = &artifact
        case "test-results", "junit-results":
            testArtifact = &artifact
        }
    }

    // Get specific file from artifact
    if sbomArtifact != nil {
        sbomContent, err := helpers.GetArtifactFile(ctx,
            event.Repository.Owner.Login,
            event.Repository.Name,
            event.WorkflowRun.ID,
            sbomArtifact.Name,
            "sbom.json") // File path within the artifact
        if err != nil {
            p.logger.Warn("Failed to get SBOM file from artifact", "error", err)
        } else {
            p.logger.Info("Retrieved SBOM from artifact", 
                "size", sbomContent.Size, 
                "artifact", sbomArtifact.Name)
        }
    }

    // Get structured SBOM documents (parsed and validated)
    sboms, err := helpers.GetSBOMFromArtifacts(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name,
        event.WorkflowRun.ID)
    if err != nil {
        return nil, fmt.Errorf("failed to get SBOMs: %w", err)
    }

    // Get test results (parsed from JUnit XML, etc.)
    testResults, err := helpers.GetTestResults(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name,
        event.WorkflowRun.ID)
    if err != nil {
        p.logger.Warn("Failed to get test results", "error", err)
    } else {
        // Process test results for security analysis
        for _, result := range testResults {
            p.logger.Info("Test suite results", 
                "suite", result.Suite, 
                "status", result.Status,
                "coverage", result.Coverage)
        }
    }

    // Get build logs for analysis
    buildLogs, err := helpers.GetBuildLogs(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name,
        event.WorkflowRun.ID)
    if err != nil {
        p.logger.Warn("Failed to get build logs", "error", err)
    } else {
        // Scan build logs for security issues (exposed secrets, etc.)
        for _, log := range buildLogs {
            if log.Status == "failure" {
                p.logger.Info("Found failed build job", 
                    "job", log.Job, 
                    "stage", log.Stage,
                    "duration", log.Duration)
                // Could scan log.Content for security violations
            }
        }
    }

    // Create policy input combining repository files and CI artifacts
    policyInput := VulnerabilityPolicyInput{
        SBOMs:       sboms,
        Repository:  *event.Repository,
        WorkflowRun: event.WorkflowRun,
    }

    // Evaluate policy with combined data
    violations, err := helpers.EvaluateVulnerabilityPolicy(ctx, "vulnerability/workflow_scan", policyInput)
    if err != nil {
        return nil, fmt.Errorf("vulnerability policy evaluation failed: %w", err)
    }

    return &PolicyResult{
        Processed:  true,
        Violations: violations,
        CheckRun: &CheckRunRequest{
            Name:       "Security / Workflow Vulnerability Scan", 
            Status:     p.getCheckStatus(violations),
            Summary:    p.formatWorkflowSummary(violations, len(artifacts), len(testResults)),
        },
    }, nil
}

// Example: License compliance plugin accessing dependency files
func (p *LicensePlugin) processPullRequest(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error) {
    // Get dependency files from PR head commit
    dependencyFiles, err := helpers.GetPRFiles(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name,
        event.PullRequest.Number,
        []string{"package.json", "package-lock.json", "requirements.txt", "go.mod", "go.sum"})
    if err != nil {
        return nil, fmt.Errorf("failed to get dependency files: %w", err)
    }

    // Get license information from artifacts if available
    artifacts, err := helpers.GetWorkflowArtifacts(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name,
        event.PullRequest.Head.SHA) // Use PR head SHA for artifact lookup
    if err != nil {
        p.logger.Warn("No artifacts found for PR", "pr", event.PullRequest.Number)
    }

    // Look for license scanning results in artifacts
    var licenseReport *FileContent
    for _, artifact := range artifacts {
        if artifact.Name == "license-report" {
            content, err := helpers.GetArtifactFile(ctx,
                event.Repository.Owner.Login,
                event.Repository.Name,
                event.WorkflowRun.ID,
                artifact.Name,
                "license-report.json")
            if err == nil {
                licenseReport = content
                break
            }
        }
    }

    // Create policy input with both repository files and CI artifacts
    policyInput := LicensePolicyInput{
        Repository:      *event.Repository,
        PullRequest:     event.PullRequest,
        DependencyFiles: dependencyFiles,    // Repository files
        LicenseReport:   licenseReport,      // CI artifact
    }

    violations, err := helpers.EvaluateLicensePolicy(ctx, "license/check_compliance", policyInput)
    if err != nil {
        return nil, fmt.Errorf("license policy evaluation failed: %w", err)
    }

    return &PolicyResult{
        Processed:  true,
        Violations: violations,
        CheckRun: &CheckRunRequest{
            Name:    "Legal / License Compliance",
            Status:  p.getCheckStatus(violations),
            Summary: p.formatLicenseSummary(violations),
        },
    }, nil
}
```

### Plugin Distribution via OCI Registry

Following the established OCI pattern, plugins will be distributed as container images:

```yaml
# Plugin Manifest (polly-plugin.yaml)
apiVersion: polly/v1
kind: PolicyPlugin
metadata:
  name: polly-vulnerability-plugin
  version: 1.0.0
  description: "Official vulnerability policy processor"

spec:
  policyType: vulnerability
  runtime:
    platform: linux/amd64
    entrypoint: /usr/local/bin/vulnerability-plugin
  policies:
    bundlePath: /policies/vulnerability.tar.gz
  configuration:
    schema: /config/schema.json
```

### Plugin Lifecycle Management

Based on the established polling pattern:

1. **Registry Polling**: Poll OCI registry for plugin image digest changes
2. **Hot Reloading**: Download new plugin versions and start new processes
3. **Graceful Transition**: Complete in-flight requests on old plugin before shutdown
4. **Health Monitoring**: Continuous health checks with automatic restart on failure
5. **Resource Limits**: Process-level CPU and memory constraints

## Implementation Strategy

### Strategic Implementation Phases for Polly 2.0

The transformation to Polly 2.0 follows a carefully orchestrated approach to minimize risk while enabling the complete architectural evolution:

#### Phase 1: Foundation Infrastructure
**Goal**: Build core event bus architecture and plugin infrastructure

**1.1 Event Bus Interface Contracts** ⚡ *New Architecture Foundation*
- Define `EnrichedEvent`, `PolicyPlugin`, `PollyHelpers`, `PolicyResult` types for event-driven architecture
- Implement event bus communication protocols with RPC-compatible serialization
- Create language-agnostic event schemas (JSON/protobuf)
- **Priority**: Complete architectural shift requires solid interface foundation

**1.2 Event Processing Pipeline** 🔄 *Core Orchestrator*
- Build `EventProcessor` that handles GitHub webhooks and enriches with common data
- Implement event broadcasting to all plugins with parallel execution
- Create event filtering and plugin result aggregation
- **Priority**: Heart of the new architecture - all functionality depends on this

**1.3 Helper Services Layer** 🛠️ *Plugin Ecosystem Enabler*
- Implement `PollyHelpers` with file fetching, CI artifacts, GitHub operations, OPA evaluation
- Add intelligent caching, deduplication, and connection pooling
- Build centralized GitHub API management with rate limiting
- **Priority**: Enables plugin simplicity and performance optimization

#### Phase 2: Plugin Infrastructure

**2.1 Plugin Manager with Hot Reload** 📦 *Production Operations*
- Build `PluginManager` with lifecycle management, health monitoring, zero-downtime updates
- Implement plugin discovery, loading, and graceful shutdown capabilities
- Add plugin result processing and GitHub API integration
- **Priority**: Critical for production plugin ecosystem management

**2.2 Data Infrastructure** 💾 *Performance & Caching*
- Create data fetching layer with GitHub files, CI artifacts, repository metadata
- Implement intelligent caching across plugins with deduplication
- Build artifact processing pipeline for SBOM, vulnerability scans, etc.
- **Priority**: Foundation for helper services performance

**2.3 Process Sandboxing** 🛡️ *Security Foundation*
- Implement `ProcessSandbox` with chroot, namespace isolation, resource limits
- Add behavioral monitoring and automated threat response
- Create ORAS-compatible plugin execution environment
- **Priority**: Essential security for external plugin execution

#### Phase 3: Distribution & Migration

**3.1 ORAS Plugin Distribution** 🚀 *Production Plugin Delivery*
- Build ORAS client for OCI artifact-based plugin distribution
- Implement cryptographic signature verification (Cosign) and SLSA attestation validation
- Add plugin registry management with version control and hot-reload detection
- **Priority**: Production-ready plugin distribution and security

**3.2 Polly 2.0 Go SDK** 📚 *Developer Experience*
- Create comprehensive Go SDK for event-driven plugin development
- Add plugin scaffolding, testing utilities, event handling helpers
- Implement best practices templates and development workflows
- **Priority**: Enables community plugin development

**3.3 Migration of Existing Processors** 🔄 *Real-World Validation*
- Extract `VulnerabilityPolicyProcessor` and `LicensePolicyProcessor` to event-driven plugins
- Validate entire 2.0 architecture with substantial business logic
- Create official plugin examples and reference implementations
- **Priority**: Proves architecture works with real complexity

#### Phase 4: Ecosystem & Compatibility

**4.1 Backward Compatibility Bridge** 🌉 *Migration Path*
- Implement Polly 1.x compatibility layer for gradual migration
- Create configuration migration tools and automated upgrade scripts
- Build webhook handler bridge that translates to event bus
- **Priority**: Enables existing deployments to upgrade safely

**4.2 Migration Tooling** 🛠️ *Enterprise Adoption*
- Develop comprehensive migration guides and automation tools
- Create plugin conversion utilities for custom implementations
- Build configuration validation and testing frameworks
- **Priority**: Reduces migration friction for enterprise adoption

**4.3 Multi-Language SDK Ecosystem** 🌍 *Platform Growth*
- Create Python SDK for data science and security teams
- Build TypeScript/Node.js SDK for web developers
- Add language-agnostic RPC documentation and examples
- **Priority**: Expands plugin ecosystem beyond Go developers

### MVP Success Metrics

#### Core Functionality Metrics
- **Plugin Extraction**: Both vulnerability and license processors working as plugins
- **Performance**: Event processing within 10% of current monolithic performance
- **Compatibility**: Zero regression in existing webhook functionality
- **Developer Experience**: New plugin development time <4 hours

#### Technical Foundation Metrics
- **Event Bus**: All GitHub webhooks properly converted to enriched events
- **Plugin Communication**: RPC communication stable and performant
- **Helper Services**: File fetching, OPA evaluation, and GitHub operations working
- **Error Handling**: Plugin failures don't crash core system

#### Post-MVP Enhancement Metrics (Future)
- **Distribution**: OCI registry plugin distribution
- **Hot Reload**: Zero-downtime plugin updates
- **High Availability**: Multi-instance deployments with leader election
- **Ecosystem**: Multi-language plugin SDKs and community plugins

### Post-MVP Enhancement Roadmap

After MVP is working and validated:

#### Phase 4: Production Features
- **Plugin Distribution**: OCI registry support for plugin distribution
- **Hot Reloading**: Zero-downtime plugin updates  
- **Monitoring**: Comprehensive plugin health monitoring and metrics
- **Security**: Plugin sandboxing, resource limits, signature verification

#### Phase 5: High Availability (Stretch Goal)
- **Leader Election**: Redis-based leader election using `github.com/heyvito/go-leader`
- **Multi-Instance Coordination**: Leader coordinates plugin updates across replicas
- **Automatic Failover**: New leader elected within ~5 seconds on failure
- **Zero Downtime Updates**: Hot plugin swaps coordinated across all instances
- **Production Deployment**: Docker Compose and Kubernetes deployment patterns

```yaml
# High Availability Configuration (Future)
plugins:
  enabled: true
  
  # Leader election for HA deployments
  leader_election:
    enabled: true
    redis_url: "redis://localhost:6379"
    election_key: "polly:plugin-manager:leader"
    lease_duration: "10s"
    election_wait: "5s"
  
  processors:
    - name: vulnerability-plugin
      image: "ghcr.io/company/vulnerability-plugin:v1.2.0"
      config:
        logLevel: "info"
```

#### Phase 6: Ecosystem Growth
- **Multi-Language SDKs**: Python and TypeScript plugin SDKs
- **Plugin Registry**: Public registry for community plugins  
- **Advanced Features**: Complex event workflows, plugin chaining, custom CI integrations

## Benefits

### Immediate Benefits
1. **Real-world Validation**: Testing plugin system with proven, substantial business logic rather than toy examples
2. **Reduced Core Complexity**: Polly core focuses on infrastructure rather than policy specifics
3. **Independent Versioning**: Vulnerability and license policies can evolve at different rates
4. **Process Isolation**: Plugin failures don't crash entire application

### Long-term Benefits
1. **Extensible Architecture**: Third parties can create domain-specific processors (Docker, Terraform, etc.)
2. **Customization Support**: Organizations can fork official plugins for custom policy logic
3. **Resource Optimization**: Only needed plugins consume resources
4. **Deployment Flexibility**: Different environments can run different plugin sets

## Risks and Mitigations

### Risk: Performance Overhead from RPC Communication
**Mitigation**:
- Use go-plugin's high-performance RPC protocol
- Batch payload processing where possible
- Maintain performance SLAs with monitoring

### Risk: Plugin Development Complexity
**Mitigation**:
- Provide comprehensive plugin SDK with helpers
- Create plugin templates and development tools
- Maintain official plugins as reference implementations

### Risk: Migration Disruption
**Mitigation**:
- Gradual migration with embedded processor fallbacks
- Extensive testing with existing test suites
- Clear rollback procedures for each phase

### Risk: Plugin Quality and Security
**Mitigation**:
- Plugin signature verification for production deployments
- Resource limits and process sandboxing
- Official plugin certification process

## Configuration Changes

Extending existing configuration system:

```yaml
# config.yaml additions for Polly 2.0
plugins:
  enabled: true
  pollInterval: "5m"
  timeout: "30s"

  processors:
    - name: vulnerability-plugin
      registry: "ghcr.io/terrpan/polly-plugins/polly-vulnerability-plugin:stable"
      
      # Event filtering for performance (optional - if omitted, gets all events)
      event_filters:
        - "pull_request.opened"
        - "pull_request.synchronize" 
        - "workflow_run.completed"
      
      # OPA endpoint binding - infrastructure only
      opa_endpoint: "vulnerability"  # Which OPA instance to use
      
      config:
        logLevel: "info"
        # Plugin-specific operational config only, no policy rules

    - name: license-plugin
      registry: "ghcr.io/terrpan/polly-plugins/polly-license-plugin:stable"
      
      event_filters:
        - "pull_request.opened"
        - "pull_request.synchronize"
        - "push"
        
      opa_endpoint: "license"  # Different OPA instance
      
      config:
        logLevel: "info"
        # No policy rules here - all in OPA bundle

    - name: compliance-audit-plugin
      registry: "registry.company.com/security/compliance-audit:v1.2.0"
      
      event_filters: ["*"]
      opa_endpoint: "compliance"
      
      config:
        audit_webhook: "https://compliance.company.com/webhook"
        retention_days: 90

# OPA configuration - just endpoint routing, no policy management
opa:
  # Default/primary OPA server
  serverURL: "http://localhost:8181"
  
  # Additional OPA endpoints for plugin routing
  endpoints:
    vulnerability:
      url: "http://vulnerability-opa:8182"
      
    license:
      url: "http://license-opa:8183" 
      
    compliance:
      url: "http://compliance-opa:8184"
      auth:
        type: "bearer_token"
        token_secret: "compliance-opa-token"
```

## Success Metrics

### Technical Metrics
- **Performance**: Plugin processing latency <100ms per payload
- **Reliability**: Plugin availability >99.9% with automatic recovery
- **Resource Usage**: Memory usage per plugin <50MB baseline
- **Migration**: Zero breaking changes to existing API contracts

### Business Metrics
- **Developer Experience**: Plugin development from template to deployment <2 hours
- **Extensibility**: Third-party plugins can be developed without core code access
- **Maintenance**: Policy updates deployable without Polly core changes

## Decision Consequences

### Positive Consequences
1. **Cleaner Architecture**: Clear separation between infrastructure and policy logic
2. **Innovation Enablement**: Plugin ecosystem encourages community contributions
3. **Operational Flexibility**: Different policies can be updated independently
4. **Resource Efficiency**: Fine-grained resource allocation per policy type

### Negative Consequences
1. **Increased Complexity**: More moving parts with plugin lifecycle management
2. **Deployment Overhead**: Additional OCI registry and plugin management infrastructure
3. **Development Learning Curve**: Plugin developers need to understand RPC boundaries
4. **Debugging Complexity**: Issues may span multiple processes requiring distributed tracing

## Related ADRs
- [ADR-008: Policy Processing Strategy Pattern Implementation](./ADR-008-policy-processing-strategy-pattern.md) - Established foundation patterns that enable this plugin extraction
- [ADR-010: Container Service Registry Pattern](./ADR-010-container-service-registry-pattern.md) - Service management patterns extended to plugins

## Decision Consequences for Polly 2.0

### Positive Transformation Outcomes
1. **Platform Evolution**: Transform from security tool to GitHub workflow orchestration platform
2. **Unlimited Extensibility**: Plugin ecosystem enables any organization to implement custom policies  
3. **Community Growth**: Multi-language SDK support drives external plugin development
4. **Operational Excellence**: Hot-reload, monitoring, and helper services provide enterprise-grade reliability
5. **Innovation Acceleration**: New workflow types (compliance, infrastructure, custom business logic) through plugins

### Migration and Adoption Considerations
1. **Major Version Breaking Changes**: Requires deliberate migration planning for existing deployments
2. **Learning Curve**: Plugin developers need to understand event bus patterns and helper services
3. **Ecosystem Bootstrap**: Initial 2.0 adoption requires official plugins and comprehensive documentation
4. **Operational Complexity**: Plugin management, distribution, and monitoring add operational overhead
5. **Performance Profile**: Event bus and plugin coordination introduce new performance characteristics

### Risk Mitigation Strategy
- **Comprehensive Backward Compatibility**: 1.x compatibility layer ensures smooth migration path
- **Migration Automation**: Tools and guides reduce upgrade friction for enterprises
- **Phased Rollout**: Alpha/Beta program validates architecture with real workloads before GA
- **Official Plugin Portfolio**: Vulnerability and license plugins provide immediate 2.0 value
- **Documentation First**: Complete plugin development guides available at 2.0 launch

## Related ADRs and Documentation
- [ADR-008: Policy Processing Strategy Pattern Implementation](./ADR-008-policy-processing-strategy-pattern.md) - Foundation patterns enabling plugin extraction
- [ADR-010: Container Service Registry Pattern](./ADR-010-container-service-registry-pattern.md) - Service management extended to plugin ecosystem
- [Event Bus Architecture Guide](../guides/event-bus-architecture.md) - Complete technical architecture for Polly 2.0
- [Plugin System Implementation Guide](../guides/PLUGIN_SYSTEM_IMPLEMENTATION_GUIDE.md) - Detailed implementation roadmap

**This ADR represents the most significant architectural evolution in Polly's history, transforming it from a GitHub security tool into a comprehensive workflow orchestration platform that can adapt to any organization's unique policy requirements.**

