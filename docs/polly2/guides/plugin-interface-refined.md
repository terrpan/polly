<!-- Moved from docs/plugin-interface-refined.md -->
<!-- Note: This document represents an earlier iteration of plugin interface design -->
<!-- See ../api/PLUGIN_API_REFERENCE.md for the current authoritative plugin interface specification -->

# Refined Plugin Interface - Event Processing Architecture

## Architecture Decision: Polly Processes Events, Plugins Handle Policy Logic

Based on architectural analysis, Polly should handle all GitHub events and third-party integrations, providing plugins with processed, relevant data rather than raw webhook events.

## Benefits of This Approach

### Plugin Simplicity
- Plugins receive exactly what they need (file contents, CI artifacts, SBOM data)
- No webhook parsing complexity in plugins
- No GitHub API client management in plugins
- Plugins focus purely on policy evaluation logic

### Centralized Security & Control
- Single GitHub token management (no token distribution to plugins)
- Rate limit management across all plugins
- Audit trail of all external API calls
- Access control - Polly controls what data plugins can access

### Performance & Efficiency
- Caching: Polly can cache file contents/artifacts across multiple plugins
- Batching: Single fetch for multiple plugins that need the same data
- Connection pooling: Efficient HTTP client management
- Deduplication: Don't fetch the same artifact multiple times

## Refined Plugin Interface

```go
// Plugin receives processed data, not raw GitHub events
type PolicyPlugin interface {
    // Metadata
    Name() string
    Version() string
    PolicyType() string

    // Process specific data types (Polly fetches and provides the data)
    ProcessVulnerabilityData(ctx context.Context, request VulnerabilityRequest) (PolicyProcessingResult, error)
    ProcessLicenseData(ctx context.Context, request LicenseRequest) (PolicyProcessingResult, error)
    ProcessCustomData(ctx context.Context, request CustomPolicyRequest) (PolicyProcessingResult, error)

    // Lifecycle management
    Initialize(config PluginConfig) error
    Shutdown() error
    Health() error
}

// Polly provides processed, relevant data to plugins
type VulnerabilityRequest struct {
    // Repository context
    Owner       string `json:"owner"`
    Repo        string `json:"repo"`
    SHA         string `json:"sha"`
    PullRequest *PullRequestContext `json:"pull_request,omitempty"`

    // Processed vulnerability data (Polly fetched from CI artifacts)
    SBOMData          []SBOMDocument     `json:"sbom_data"`
    VulnerabilityData []VulnScanResult   `json:"vulnerability_data"`

    // File contents (Polly fetched from GitHub)
    RelevantFiles     []FileContent      `json:"relevant_files"`     // Dockerfiles, package.json, etc.
    ChangedFiles      []ChangedFile      `json:"changed_files"`      // What changed in this PR

    // Policy configuration (Polly manages)
    PolicyConfig      map[string]interface{} `json:"policy_config"`
}

type LicenseRequest struct {
    Owner       string `json:"owner"`
    Repo        string `json:"repo"`
    SHA         string `json:"sha"`
    PullRequest *PullRequestContext `json:"pull_request,omitempty"`

    // Processed license data (Polly fetched and analyzed)
    Dependencies      []Dependency       `json:"dependencies"`
    LicenseData       []LicenseInfo      `json:"license_data"`

    // Package files (Polly fetched)
    PackageFiles      []FileContent      `json:"package_files"`     // package.json, go.mod, requirements.txt
    LicenseFiles      []FileContent      `json:"license_files"`     // LICENSE, COPYING, etc.

    PolicyConfig      map[string]interface{} `json:"policy_config"`
}

// Supporting types
type FileContent struct {
    Path     string `json:"path"`
    Content  []byte `json:"content"`
    SHA      string `json:"sha"`
    Size     int64  `json:"size"`
}

type ChangedFile struct {
    Path      string `json:"path"`
    Status    string `json:"status"`    // "added", "modified", "deleted"
    Additions int    `json:"additions"`
    Deletions int    `json:"deletions"`
    Patch     string `json:"patch,omitempty"`
}

type SBOMDocument struct {
    Format      string      `json:"format"`        // "spdx", "cyclonedx"
    Version     string      `json:"version"`
    Components  []Component `json:"components"`
    Source      string      `json:"source"`        // Which CI step produced this
}

type VulnScanResult struct {
    Scanner       string        `json:"scanner"`     // "snyk", "trivy", "grype"
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
    Source        string        `json:"source"`      // Which CI step produced this
}

type PullRequestContext struct {
    Number      int      `json:"number"`
    Title       string   `json:"title"`
    Body        string   `json:"body"`
    BaseBranch  string   `json:"base_branch"`
    HeadBranch  string   `json:"head_branch"`
    Author      string   `json:"author"`
    Labels      []string `json:"labels"`
    IsDraft     bool     `json:"is_draft"`
}
```

## Event Processing Flow

```
1. GitHub Webhook → Polly
2. Polly determines which plugins need to run
3. For each plugin:
   a. Polly fetches required data (files, artifacts, CI results)
   b. Polly processes/parses data into structured format
   c. Polly calls plugin with processed data
   d. Plugin returns policy violations
   e. Polly handles GitHub API calls (check runs, comments)
```

## Polly's Event Processing Responsibilities

### GitHub Event Handling
- Parse webhook events (pull_request, workflow_run, etc.)
- Determine which plugins should run for each event
- Manage plugin execution order and dependencies

### Data Fetching & Processing
- **Repository Files**: Fetch Dockerfiles, package manifests, configuration files
- **CI Artifacts**: Download and parse SBOM files, vulnerability scan results
- **Pull Request Context**: Gather PR metadata, changed files, diff information
- **Historical Data**: Access previous scan results for comparison

### Third-Party Integration
- **GitHub API**: File contents, PR information, commit details
- **CI Systems**: Artifact download, build status
- **Registries**: Container image metadata (if needed)
- **Security Tools**: Integration with Snyk, WhiteSource, etc. (if direct integration needed)

### Caching & Optimization
- Cache frequently accessed files
- Deduplicate artifact downloads across plugins
- Implement efficient diff analysis for incremental scans

## Plugin Simplified Responsibilities

### Policy Evaluation Only
```go
func (p *VulnerabilityPlugin) ProcessVulnerabilityData(ctx context.Context, request VulnerabilityRequest) (PolicyProcessingResult, error) {
    // Plugin focuses only on policy logic - no data fetching!

    var violations []PolicyViolation

    // Analyze SBOM data (already provided by Polly)
    for _, sbom := range request.SBOMData {
        sbomViolations := p.analyzeSBOM(sbom)
        violations = append(violations, sbomViolations...)
    }

    // Analyze vulnerability scan results (already provided by Polly)
    for _, vulnScan := range request.VulnerabilityData {
        vulnViolations := p.analyzeVulnerabilities(vulnScan)
        violations = append(violations, vulnViolations...)
    }

    // Check against policy configuration (already provided by Polly)
    filteredViolations := p.applyPolicyFilters(violations, request.PolicyConfig)

    return PolicyProcessingResult{
        Violations:  filteredViolations,
        Summary:     p.generateSummary(filteredViolations),
        CheckStatus: p.determineStatus(filteredViolations),
    }, nil
}
```

## Benefits Summary

| Aspect | Raw Events to Plugins | Processed Data to Plugins |
|--------|----------------------|---------------------------|
| **Plugin Complexity** | ❌ High (GitHub API, parsing) | ✅ Low (focus on policy logic) |
| **Security** | ❌ Token distribution needed | ✅ Centralized token management |
| **Performance** | ❌ Duplicate API calls | ✅ Cached, batched requests |
| **Rate Limits** | ❌ Hard to manage | ✅ Centralized management |
| **Debugging** | ❌ Complex distributed calls | ✅ Clear separation of concerns |
| **Plugin Development** | ❌ Need GitHub API expertise | ✅ Focus on policy logic only |
| **Testing** | ❌ Mock GitHub APIs | ✅ Test with structured data |
| **Maintenance** | ❌ GitHub API changes break plugins | ✅ Polly shields plugins from API changes |

## Implementation Considerations

### Event Processing Pipeline in Polly
```go
type EventProcessor struct {
    githubClient   *github.Client
    pluginManager  *PluginManager
    artifactFetcher *ArtifactFetcher
    fileCache      *FileCache
}

func (ep *EventProcessor) HandlePullRequestEvent(event *github.PullRequestEvent) error {
    // 1. Determine which plugins should run
    plugins := ep.pluginManager.GetPluginsForEvent("pull_request", event.GetAction())

    // 2. Fetch common data once
    commonData := ep.fetchCommonData(event)

    // 3. Run each plugin with relevant data
    for _, plugin := range plugins {
        pluginData := ep.preparePluginData(plugin.Type(), commonData)
        result, err := plugin.Process(ctx, pluginData)
        if err != nil {
            // Handle plugin error
            continue
        }

        // 4. Update GitHub with results
        ep.updateGitHubChecks(event, plugin.Name(), result)
    }

    return nil
}
```

This architecture provides much cleaner separation of concerns while maintaining plugin simplicity and system security.
