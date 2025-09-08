<!-- Moved from docs/event-bus-architecture.md -->
<!-- Technical architecture guide for Polly 2.0 event bus system. -->
# Event Bus Plugin Architecture

## Architecture: Polly as Event Bus/Router with Helper Services

This approach treats Polly as an intelligent event bus that enriches GitHub webhooks and provides helper services for common tasks, while plugins decide autonomously what events to process.

## Architecture Diagrams

### High-Level Architecture Flowchart

```mermaid
flowchart TD
    A[GitHub Webhook] --> B[Polly Event Processor]
    B --> C{Parse & Validate Event}
    C -->|Valid| D[Enrich Event with Common Data]
    C -->|Invalid| E[Log Error & Return]
    
    D --> F[Pre-fetch Common Data]
    F --> G[Changed Files]
    F --> H[Repository Metadata]
    F --> I[CI/Workflow Context]
    
    G --> J[Enriched Event]
    H --> J
    I --> J
    
    J --> K[Broadcast to All Plugins]
    K --> L[Plugin 1: Vulnerability]
    K --> M[Plugin 2: License]
    K --> N[Plugin 3: Custom Security]
    K --> O[Plugin N: ...]
    
    L --> P{Plugin Interested?}
    M --> Q{Plugin Interested?}
    N --> R{Plugin Interested?}
    O --> S{Plugin Interested?}
    
    P -->|No| T[Return: Not Processed]
    P -->|Yes| U[Use Polly Helpers]
    Q -->|No| V[Return: Not Processed]
    Q -->|Yes| W[Use Polly Helpers]
    R -->|No| X[Return: Not Processed]
    R -->|Yes| Y[Use Polly Helpers]
    S -->|No| Z[Return: Not Processed]
    S -->|Yes| AA[Use Polly Helpers]
    
    U --> AB[Policy Logic & Analysis]
    W --> AC[Policy Logic & Analysis]
    Y --> AD[Policy Logic & Analysis]
    AA --> AE[Policy Logic & Analysis]
    
    AB --> AF[Return Policy Result]
    AC --> AG[Return Policy Result]
    AD --> AH[Return Policy Result]
    AE --> AI[Return Policy Result]
    
    T --> AJ[Collect All Results]
    V --> AJ
    X --> AJ
    Z --> AJ
    AF --> AJ
    AG --> AJ
    AH --> AJ
    AI --> AJ
    
    AJ --> AK[Process Plugin Results]
    AK --> AL[Create/Update Check Runs]
    AK --> AM[Post Comments]
    AK --> AN[Update Check Suites]
    
    AL --> AO[GitHub API Calls]
    AM --> AO
    AN --> AO
    
    AO --> AP[Complete Event Processing]
```

### Event Processing Sequence Diagram

```mermaid
sequenceDiagram
    participant GitHub
    participant Polly as Polly Event Bus
    participant DataFetcher as Data Fetcher
    participant Helpers as Polly Helpers
    participant Plugin1 as Vulnerability Plugin
    participant Plugin2 as License Plugin  
    participant Plugin3 as Custom Plugin
    participant OPA
    participant GitHubAPI as GitHub API

    GitHub->>Polly: Webhook Event (PR opened)
    
    Note over Polly: Event Processing Phase
    Polly->>Polly: Parse webhook payload
    Polly->>DataFetcher: Enrich event with common data
    
    par Fetch Common Data
        DataFetcher->>GitHubAPI: Get changed files
        DataFetcher->>GitHubAPI: Get repository metadata
        DataFetcher->>GitHubAPI: Get latest CI runs
    end
    
    DataFetcher-->>Polly: Enriched event with common data
    
    Note over Polly: Plugin Broadcasting Phase
    
    par Broadcast to All Plugins
        Polly->>Plugin1: HandleEvent(enrichedEvent, helpers)
        Polly->>Plugin2: HandleEvent(enrichedEvent, helpers)
        Polly->>Plugin3: HandleEvent(enrichedEvent, helpers)
    end
    
    Note over Plugin1,Plugin3: Plugin Processing Phase
    
    Plugin1->>Plugin1: shouldProcess(event) → true (PR with code changes)
    Plugin2->>Plugin2: shouldProcess(event) → true (package files changed)
    Plugin3->>Plugin3: shouldProcess(event) → false (not interested)
    
    Plugin3-->>Polly: PolicyResult{Processed: false}
    
    Note over Plugin1,Plugin2: Plugins Use Helpers for Additional Data
    
    Plugin1->>Helpers: GetFiles(dockerfiles, package files)
    Helpers->>GitHubAPI: Fetch specific files
    GitHubAPI-->>Helpers: File contents
    Helpers-->>Plugin1: FileContent[]
    
    Plugin1->>Helpers: EvaluatePolicy("vulnerability", input)
    Helpers->>OPA: Policy evaluation request
    OPA-->>Helpers: Policy violations (normalized)
    Helpers-->>Plugin1: PolicyViolation[]
    
    Plugin2->>Helpers: GetFiles(package.json, requirements.txt)
    Helpers->>GitHubAPI: Fetch package files
    GitHubAPI-->>Helpers: Package file contents
    Helpers-->>Plugin2: FileContent[]
    
    Plugin2->>Helpers: EvaluatePolicy("license", dependencies)
    Helpers->>OPA: License policy evaluation
    OPA-->>Helpers: License violations (normalized)
    Helpers-->>Plugin2: PolicyViolation[]
    
    Note over Plugin1,Plugin2: Plugin Results Phase
    
    Plugin1->>Plugin1: Format results for GitHub
    Plugin1-->>Polly: PolicyResult{Processed: true, CheckRun: {...}}
    
    Plugin2->>Plugin2: Format results for GitHub
    Plugin2-->>Polly: PolicyResult{Processed: true, CheckRun: {...}}
    
    Note over Polly: Results Processing Phase
    
    Polly->>Polly: Collect all plugin results
    Polly->>Polly: Process successful plugin results
    
    par Create GitHub Check Runs
        Polly->>GitHubAPI: Create check run (Vulnerability)
        Polly->>GitHubAPI: Create check run (License)
    end
    
    GitHubAPI-->>Polly: Check run created
    GitHubAPI-->>Polly: Check run created
    
    Polly-->>GitHub: Event processing complete
```

### Plugin Decision Flow

```mermaid
flowchart TD
    A[Plugin Receives EnrichedEvent] --> B{Event Type?}
    
    B -->|pull_request| C{PR Action?}
    B -->|workflow_run| D{Workflow Status?}
    B -->|push| E{Branch?}
    B -->|other| F[Return: Not Processed]
    
    C -->|opened/synchronize| G[Check Changed Files]
    C -->|other| F
    
    D -->|completed + success| H[Check Workflow Artifacts]
    D -->|other| F
    
    E -->|main/default branch| I[Check Commit Changes]
    E -->|other| F
    
    G --> J{Relevant Files?}
    H --> K{Has SBOM/Scan Results?}
    I --> L{Security-Related Changes?}
    
    J -->|Yes| M[Fetch Additional Data via Helpers]
    J -->|No| F
    K -->|Yes| N[Fetch CI Artifacts via Helpers]
    K -->|No| F
    L -->|Yes| O[Analyze Security Impact]
    L -->|No| F
    
    M --> P[Evaluate Policies via OPA Helpers]
    N --> Q[Process SBOM/Vulnerability Data]
    O --> R[Evaluate Security Policies]
    
    P --> S[Format Results for GitHub]
    Q --> T[Format CI-based Results]
    R --> U[Format Security Results]
    
    S --> V[Return PolicyResult with CheckRun]
    T --> W[Return PolicyResult with CheckRun]
    U --> X[Return PolicyResult with CheckRun]
```

### Data Flow Architecture

```mermaid
flowchart LR
    subgraph "External Systems"
        A[GitHub Webhooks]
        B[GitHub API]
        C[CI Systems]
        D[OPA Server]
    end
    
    subgraph "Polly Core"
        E[Event Processor]
        F[Data Fetcher & Enricher]
        G[Helper Services]
        H[Plugin Manager]
        I[Results Processor]
    end
    
    subgraph "Plugins"
        J[Vulnerability Plugin]
        K[License Plugin]
        L[Custom Plugins]
    end
    
    subgraph "Data Storage"
        M[Event Cache]
        N[File Cache]
        O[Policy Cache]
    end
    
    A -->|Webhook Events| E
    E -->|Parse & Route| F
    F <-->|Fetch Data| B
    F <-->|Get Artifacts| C
    F -->|Enriched Events| H
    
    H -->|Broadcast Events| J
    H -->|Broadcast Events| K
    H -->|Broadcast Events| L
    
    J <-->|Helper Calls| G
    K <-->|Helper Calls| G
    L <-->|Helper Calls| G
    
    G <-->|File Operations| B
    G <-->|Policy Evaluation| D
    G <-->|Artifact Access| C
    
    G <-->|Cache Access| M
    G <-->|Cache Access| N
    G <-->|Cache Access| O
    
    J -->|Policy Results| I
    K -->|Policy Results| I
    L -->|Policy Results| I
    
    I -->|GitHub Updates| B
```

### Helper Services Interaction Flow

```mermaid
sequenceDiagram
    participant Plugin
    participant Helpers as Polly Helpers
    participant Cache as Data Cache
    participant GitHub as GitHub API
    participant CI as CI Systems
    participant OPA as OPA Server

    Note over Plugin: Plugin needs additional data

    Plugin->>Helpers: GetFiles(owner, repo, sha, paths[])
    Helpers->>Cache: Check file cache
    
    alt Files in cache
        Cache-->>Helpers: Cached file contents
    else Files not cached
        Helpers->>GitHub: Batch fetch files
        GitHub-->>Helpers: File contents
        Helpers->>Cache: Cache files for future use
    end
    
    Helpers-->>Plugin: FileContent[]
    
    Plugin->>Helpers: GetSBOMFromArtifacts(owner, repo, runID)
    Helpers->>Cache: Check artifact cache
    
    alt SBOM in cache
        Cache-->>Helpers: Cached SBOM data
    else SBOM not cached
        Helpers->>CI: Download workflow artifacts
        CI-->>Helpers: Artifact zip files
        Helpers->>Helpers: Parse SBOM files
        Helpers->>Cache: Cache parsed SBOM
    end
    
    Helpers-->>Plugin: SBOMDocument[]
    
    Plugin->>Helpers: EvaluatePolicy(policyName, input)
    Helpers->>Cache: Check policy evaluation cache
    
    alt Result in cache
        Cache-->>Helpers: Cached policy result
    else Not cached
        Helpers->>OPA: Evaluate policy
        OPA-->>Helpers: Raw OPA response
        Helpers->>Helpers: Normalize to PolicyViolation[]
        Helpers->>Cache: Cache normalized result
    end
    
    Helpers-->>Plugin: PolicyViolation[]
    
    Plugin->>Helpers: CreateCheckRun(owner, repo, sha, checkRun)
    Helpers->>GitHub: Create check run API call
    GitHub-->>Helpers: Check run created
    Helpers-->>Plugin: Success confirmation
```

### Multi-Plugin Event Processing

```mermaid
sequenceDiagram
    participant GitHub
    participant EventBus as Polly Event Bus
    participant VulnPlugin as Vulnerability Plugin
    participant LicensePlugin as License Plugin
    participant CompliancePlugin as Compliance Plugin
    participant Helpers as Polly Helpers
    participant GitHubAPI as GitHub API

    GitHub->>EventBus: PR opened with package.json changes
    
    Note over EventBus: Enrich event with changed files, repo metadata
    
    par Broadcast to all plugins
        EventBus->>VulnPlugin: HandleEvent(enrichedEvent, helpers)
        EventBus->>LicensePlugin: HandleEvent(enrichedEvent, helpers)
        EventBus->>CompliancePlugin: HandleEvent(enrichedEvent, helpers)
    end
    
    Note over VulnPlugin,CompliancePlugin: Each plugin decides independently
    
    VulnPlugin->>VulnPlugin: shouldProcess() → true (package.json = dependencies)
    LicensePlugin->>LicensePlugin: shouldProcess() → true (package.json = licenses)
    CompliancePlugin->>CompliancePlugin: shouldProcess() → false (not monitoring PRs)
    
    CompliancePlugin-->>EventBus: PolicyResult{Processed: false}
    
    par Plugins process in parallel
        VulnPlugin->>Helpers: GetFile("package.json")
        LicensePlugin->>Helpers: GetFile("package.json")
    end
    
    Note over Helpers: Helpers deduplicate - fetch package.json once
    
    Helpers->>GitHubAPI: GET /repos/owner/repo/contents/package.json
    GitHubAPI-->>Helpers: package.json content
    
    par Helpers return to both plugins
        Helpers-->>VulnPlugin: FileContent{package.json}
        Helpers-->>LicensePlugin: FileContent{package.json}
    end
    
    par Plugins do different analysis on same file
        VulnPlugin->>Helpers: EvaluatePolicy("vulnerability", dependencies)
        LicensePlugin->>Helpers: EvaluatePolicy("license", dependencies)
    end
    
    par OPA evaluations
        Helpers->>OPA: Vulnerability policy evaluation
        Helpers->>OPA: License policy evaluation
    end
    
    par OPA responses
        OPA-->>Helpers: Vulnerability violations
        OPA-->>Helpers: License violations
    end
    
    par Normalized results to plugins
        Helpers-->>VulnPlugin: PolicyViolation[] (security issues)
        Helpers-->>LicensePlugin: PolicyViolation[] (license issues)
    end
    
    par Plugins create different check runs
        VulnPlugin-->>EventBus: PolicyResult{CheckRun: "Security Scan"}
        LicensePlugin-->>EventBus: PolicyResult{CheckRun: "License Compliance"}
    end
    
    par EventBus creates multiple check runs
        EventBus->>GitHubAPI: Create "Security Scan" check run
        EventBus->>GitHubAPI: Create "License Compliance" check run
    end
    
    par GitHub responses
        GitHubAPI-->>EventBus: Security check run created
        GitHubAPI-->>EventBus: License check run created
    end
    
    EventBus-->>GitHub: Event processing complete
```

### Plugin Lifecycle and Hot Reload

```mermaid
stateDiagram-v2
    [*] --> Loading: Plugin Manager Start
    
    Loading --> Initializing: Plugin Binary Found
    Loading --> Error: Plugin Not Found
    
    Initializing --> Running: Initialize() Success
    Initializing --> Error: Initialize() Failed
    
    Running --> Processing: Event Received
    Processing --> Running: Event Processed
    Processing --> Error: Plugin Crashed
    
    Running --> Updating: New Version Detected
    Updating --> NewVersionLoading: Download New Plugin
    NewVersionLoading --> NewVersionInitializing: New Binary Ready
    NewVersionInitializing --> Running: Hot Swap Complete
    NewVersionInitializing --> Running: Hot Swap Failed (Keep Old)
    
    Running --> Stopping: Shutdown Requested
    Processing --> Stopping: Graceful Shutdown
    
    Stopping --> Stopped: Shutdown() Complete
    
    Error --> Restarting: Auto-Recovery
    Restarting --> Loading: Restart Attempt
    
    Stopped --> [*]
    Error --> [*]: Max Retries Exceeded
```

## Core Architecture

```
GitHub Webhook → Polly Event Processor → Enriched Event → All Plugins
                                                     ↓
                Plugin Filters Event → Uses Polly Helpers → Returns Result
```

## Benefits

### Plugin Autonomy & Flexibility
- Plugins decide what events they care about (not Polly)
- Same plugin can handle multiple event types
- Easy to add new event types without changing plugin interface
- Plugins can implement complex business logic across events

### Extensibility & Future-Proofing
- New plugins automatically get all events
- Plugins can evolve to handle new event types
- Cross-cutting concerns (security, compliance) can listen to any event
- Event-driven architecture enables complex workflows

### Performance & Efficiency
- Polly fetches common data once, broadcasts to all interested plugins
- Plugins filter events efficiently at the RPC boundary
- No complex routing logic in Polly core
- Lazy loading - plugins only fetch additional data they need

## Plugin Interface Design

```go
// Event bus interface - all plugins receive all events
type PolicyPlugin interface {
    // Metadata
    Name() string
    Version() string
    
    // Event handling - plugin decides what to process
    HandleEvent(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error)
    
    // Lifecycle management
    Initialize(config PluginConfig) error
    Shutdown() error
    Health() error
}

// Enriched event with common data pre-fetched by Polly
type EnrichedEvent struct {
    // Original GitHub webhook data
    Type        string          `json:"type"`         // "pull_request", "workflow_run", "push", etc.
    Action      string          `json:"action"`       // "opened", "synchronize", "completed", etc.
    Repository  Repository      `json:"repository"`
    Sender      User            `json:"sender"`
    
    // Context information
    PullRequest *PullRequest    `json:"pull_request,omitempty"`
    WorkflowRun *WorkflowRun    `json:"workflow_run,omitempty"`
    Commit      *Commit         `json:"commit,omitempty"`
    
    // Pre-fetched common data (Polly fetches proactively)
    CommonData  CommonEventData `json:"common_data"`
    
    // Polly-added metadata
    EventID     string          `json:"event_id"`     // Unique event identifier
    Timestamp   time.Time       `json:"timestamp"`
    ProcessedAt time.Time       `json:"processed_at"`
}

// Common data Polly fetches for most events
type CommonEventData struct {
    // Changed files (for PR/push events)
    ChangedFiles    []ChangedFile   `json:"changed_files,omitempty"`
    
    // Basic repository info
    DefaultBranch   string          `json:"default_branch"`
    Languages       []string        `json:"languages,omitempty"`
    Topics          []string        `json:"topics,omitempty"`
    
    // CI/CD context (if available)
    LatestWorkflow  *WorkflowRun    `json:"latest_workflow,omitempty"`
    CheckSuites     []CheckSuite    `json:"check_suites,omitempty"`
}

// Helper services provided by Polly to plugins
type PollyHelpers interface {
    // File operations
    GetFile(ctx context.Context, owner, repo, sha, path string) (*FileContent, error)
    GetFiles(ctx context.Context, owner, repo, sha string, paths []string) ([]FileContent, error)
    GetDirectoryContents(ctx context.Context, owner, repo, sha, path string) ([]FileInfo, error)
    
    // Diff operations  
    GetPullRequestDiff(ctx context.Context, owner, repo string, prNumber int) (*Diff, error)
    GetCommitDiff(ctx context.Context, owner, repo, sha string) (*Diff, error)
    
    // CI/Artifact operations
    GetWorkflowArtifacts(ctx context.Context, owner, repo string, runID int64) ([]Artifact, error)
    DownloadArtifact(ctx context.Context, owner, repo string, artifactID int64) ([]byte, error)
    GetCheckRuns(ctx context.Context, owner, repo, sha string) ([]CheckRun, error)
    
    // SBOM/Security data
    GetSBOMFromArtifacts(ctx context.Context, owner, repo string, runID int64) ([]SBOMDocument, error)
    GetVulnerabilityScans(ctx context.Context, owner, repo string, runID int64) ([]VulnScanResult, error)
    
    // OPA evaluation
    EvaluatePolicy(ctx context.Context, policyName string, input interface{}) ([]PolicyViolation, error)
    
    // GitHub operations
    CreateCheckRun(ctx context.Context, owner, repo, sha string, check CheckRunRequest) error
    UpdateCheckRun(ctx context.Context, owner, repo string, checkRunID int64, update CheckRunUpdate) error
    CreateComment(ctx context.Context, owner, repo string, prNumber int, comment string) error
}

// Plugin result - what plugins return
type PolicyResult struct {
    // Did this plugin process the event?
    Processed   bool                    `json:"processed"`
    
    // Policy violations found (if any)
    Violations  []PolicyViolation       `json:"violations,omitempty"`
    
    // GitHub check run to create/update
    CheckRun    *CheckRunRequest        `json:"check_run,omitempty"`
    
    // GitHub comment to post
    Comment     *CommentRequest         `json:"comment,omitempty"`
    
    // Additional metadata
    Summary     string                  `json:"summary,omitempty"`
    Details     map[string]interface{}  `json:"details,omitempty"`
}
```

## Plugin Implementation Examples

### Vulnerability Plugin
```go
func (p *VulnerabilityPlugin) HandleEvent(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error) {
    // Plugin decides what events it cares about
    if !p.shouldProcess(event) {
        return &PolicyResult{Processed: false}, nil
    }
    
    var violations []PolicyViolation
    
    switch event.Type {
    case "workflow_run":
        if event.Action == "completed" && event.WorkflowRun.Conclusion == "success" {
            // Get SBOM data from completed workflow
            sboms, err := helpers.GetSBOMFromArtifacts(ctx, event.Repository.Owner, event.Repository.Name, event.WorkflowRun.ID)
            if err != nil {
                return nil, err
            }
            
            // Get vulnerability scan results
            vulnScans, err := helpers.GetVulnerabilityScans(ctx, event.Repository.Owner, event.Repository.Name, event.WorkflowRun.ID)
            if err != nil {
                return nil, err
            }
            
            // Process vulnerability data
            violations = p.processVulnerabilities(sboms, vulnScans)
        }
        
    case "pull_request":
        if event.Action == "opened" || event.Action == "synchronize" {
            // Check for vulnerable dependencies in changed files
            for _, file := range event.CommonData.ChangedFiles {
                if p.isPackageFile(file.Path) {
                    content, err := helpers.GetFile(ctx, event.Repository.Owner, event.Repository.Name, event.PullRequest.Head.SHA, file.Path)
                    if err != nil {
                        continue
                    }
                    
                    fileViolations := p.analyzePackageFile(content)
                    violations = append(violations, fileViolations...)
                }
            }
        }
    }
    
    if len(violations) == 0 {
        return &PolicyResult{Processed: true}, nil
    }
    
    return &PolicyResult{
        Processed: true,
        Violations: violations,
        CheckRun: &CheckRunRequest{
            Name:        "Vulnerability Scan",
            Status:      "completed",
            Conclusion:  p.determineConclusion(violations),
            Summary:     p.formatSummary(violations),
            Details:     p.formatDetails(violations),
        },
    }, nil
}

func (p *VulnerabilityPlugin) shouldProcess(event EnrichedEvent) bool {
    switch event.Type {
    case "workflow_run":
        return event.Action == "completed"
    case "pull_request":
        return event.Action == "opened" || event.Action == "synchronize"
    default:
        return false
    }
}
```

### License Compliance Plugin
```go
func (p *LicensePlugin) HandleEvent(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error) {
    if !p.shouldProcess(event) {
        return &PolicyResult{Processed: false}, nil
    }
    
    // Same plugin can handle different events differently
    switch event.Type {
    case "pull_request":
        return p.handlePullRequest(ctx, event, helpers)
    case "push":
        return p.handlePush(ctx, event, helpers) 
    case "workflow_run":
        return p.handleWorkflowComplete(ctx, event, helpers)
    }
    
    return &PolicyResult{Processed: false}, nil
}

func (p *LicensePlugin) shouldProcess(event EnrichedEvent) bool {
    // License plugin cares about multiple event types
    switch event.Type {
    case "pull_request":
        return event.Action == "opened" || event.Action == "synchronize"
    case "push":
        return event.Repository.DefaultBranch == extractBranchFromRef(event.Commit.Ref)
    case "workflow_run":
        return event.Action == "completed" && event.WorkflowRun.Conclusion == "success"
    default:
        return false
    }
}
```

## Polly Event Processing Pipeline

```go
type EventProcessor struct {
    plugins []PolicyPlugin
    github  *github.Client
    helpers *HelperServices
}

func (ep *EventProcessor) ProcessWebhook(ctx context.Context, eventType string, payload []byte) error {
    // 1. Parse webhook into structured event
    event, err := ep.parseWebhookEvent(eventType, payload)
    if err != nil {
        return err
    }
    
    // 2. Enrich event with common data
    enrichedEvent, err := ep.enrichEvent(ctx, event)
    if err != nil {
        return err
    }
    
    // 3. Broadcast to ALL plugins
    var results []PolicyResult
    for _, plugin := range ep.plugins {
        result, err := plugin.HandleEvent(ctx, enrichedEvent, ep.helpers)
        if err != nil {
            log.Errorf("Plugin %s failed: %v", plugin.Name(), err)
            continue
        }
        
        if result != nil && result.Processed {
            results = append(results, *result)
        }
    }
    
    // 4. Process plugin results (create check runs, comments, etc.)
    return ep.processResults(ctx, enrichedEvent, results)
}

func (ep *EventProcessor) enrichEvent(ctx context.Context, event *GitHubEvent) (*EnrichedEvent, error) {
    enriched := &EnrichedEvent{
        Type:        event.Type,
        Action:      event.Action,
        Repository:  event.Repository,
        EventID:     generateEventID(),
        Timestamp:   time.Now(),
        ProcessedAt: time.Now(),
    }
    
    // Pre-fetch common data based on event type
    switch event.Type {
    case "pull_request", "push":
        // Fetch changed files for code-related events
        changedFiles, err := ep.getChangedFiles(ctx, event)
        if err == nil {
            enriched.CommonData.ChangedFiles = changedFiles
        }
        
    case "workflow_run":
        // Fetch check suites for CI-related events
        checkSuites, err := ep.getCheckSuites(ctx, event)
        if err == nil {
            enriched.CommonData.CheckSuites = checkSuites
        }
    }
    
    return enriched, nil
}
```

## Benefits Summary

| Aspect | Targeted Plugin Calls | Event Bus Approach |
|--------|----------------------|-------------------|
| **Plugin Flexibility** | ❌ Polly decides what runs | ✅ Plugins decide what to process |
| **Event Handling** | ❌ Single event per plugin call | ✅ Plugin can handle multiple event types |
| **Future Events** | ❌ Need to update Polly routing | ✅ New events automatically available |
| **Cross-cutting Concerns** | ❌ Hard to implement | ✅ Easy (listen to all events) |
| **Plugin Autonomy** | ❌ Limited by Polly's routing | ✅ Full autonomy over business logic |
| **Development Speed** | ❌ Need to coordinate with Polly | ✅ Independent plugin development |

This event bus approach is **much more powerful and flexible** while maintaining the benefits of centralized data fetching and helper services!
