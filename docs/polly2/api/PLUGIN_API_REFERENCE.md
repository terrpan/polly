<!-- Moved from docs/PLUGIN_API_REFERENCE.md -->
<!-- Authoritative Plugin API spec lives here under Polly 2.0 hub. -->
# Plugin API Reference (v0.1)

Status: Draft (authoritative for current development phase)

This document is the single source of truth for the Polly 2.0 Plugin API surface during MVP implementation. Other docs must link here instead of redefining structures.

Referencing ADR: `../adr/ADR-012-plugin-system-policy-extraction.md`

## Versioning

```go
const PluginAPIVersion = "0.1"
```
- Increment minor for additive changes (0.1 -> 0.2)
- Increment major (1.0) only when stable & backward compatibility rules enforced
- Plugins MUST expose `Handshake().APIVersion` and Polly rejects mismatches >1 minor behind.

## Handshake Contract

```go
// Core identifies itself with a magic cookie to avoid accidental execution.
const (
    MagicCookieKey   = "POLLY_PLUGIN"
    MagicCookieValue = "polly-plugin"
)

type HandshakeInfo struct {
    APIVersion string
    PluginName string
}
```

## Core Interfaces (RPC Boundary)

Only these interfaces cross process boundaries. All parameters & returns use concrete types.

```go
type PolicyPlugin interface {
    Name() string                // Stable unique name (e.g. "vulnerability")
    Version() string             // Semantic version of plugin
    APIVersion() string          // Declared API version compatibility
    Initialize(ctx context.Context, cfg PluginConfig) error
    HandleEvent(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error)
    Health() error               // Lightweight, no network if possible
    Shutdown() error
}
```

## PollyHelpers (Authoritative Definition)

```go
type PollyHelpers interface {
    // Repository file operations
    GetFile(ctx context.Context, owner, repo, sha, path string) (*FileContent, error)
    GetFiles(ctx context.Context, owner, repo, sha string, paths []string) ([]FileContent, error)
    GetPRFiles(ctx context.Context, owner, repo string, prNumber int, paths []string) ([]FileContent, error)

    // CI / Artifact operations
    GetWorkflowArtifacts(ctx context.Context, owner, repo string, runID int64) ([]Artifact, error)
    GetArtifactFile(ctx context.Context, owner, repo string, runID int64, artifactName, filePath string) (*FileContent, error)
    GetSBOMFromArtifacts(ctx context.Context, owner, repo string, runID int64) ([]SBOMDocument, error)
    GetTestResults(ctx context.Context, owner, repo string, runID int64) ([]TestResult, error)
    GetBuildLogs(ctx context.Context, owner, repo string, runID int64) ([]BuildLog, error)

    // Policy evaluation (typed)
    EvaluateVulnerabilityPolicy(ctx context.Context, policyPath string, input VulnerabilityPolicyInput) ([]PolicyViolation, error)
    EvaluateLicensePolicy(ctx context.Context, policyPath string, input LicensePolicyInput) ([]PolicyViolation, error)
    EvaluateCustomPolicy(ctx context.Context, policyPath string, input interface{}) ([]PolicyViolation, error) // Transitional escape hatch

    // GitHub / CI action helpers
    CreateCheckRun(ctx context.Context, owner, repo, sha string, req CheckRunRequest) error
    UpdateCheckRun(ctx context.Context, owner, repo string, checkRunID int64, upd CheckRunUpdate) error
    CreatePRComment(ctx context.Context, owner, repo string, prNumber int, comment CommentRequest) error
    SetCommitStatus(ctx context.Context, owner, repo, sha, state, description string) error

    // Metadata queries
    GetRepositoryMetadata(ctx context.Context, owner, repo string) (*RepositoryInfo, error)
    ListPRFiles(ctx context.Context, owner, repo string, prNumber int) ([]FileChange, error)
}
```

## Core Data Structures

```go
type PluginConfig struct {
    Name         string                 `json:"name"`
    Registry     string                 `json:"registry"`
    EventFilters []string               `json:"event_filters"`
    OPAEndpoint  string                 `json:"opa_endpoint"`
    Config       map[string]interface{} `json:"config"`
}

type EnrichedEvent struct {
    Type        string           `json:"type"`   // pull_request, workflow_run, check_run, etc.
    Action      string           `json:"action"` // opened, completed, etc.
    Repository  *RepositoryInfo  `json:"repository"`
    PullRequest *PullRequestInfo `json:"pull_request,omitempty"`
    WorkflowRun *WorkflowRunInfo `json:"workflow_run,omitempty"`
    CheckRun    *CheckRunInfo    `json:"check_run,omitempty"`
    Metadata    map[string]string `json:"metadata,omitempty"`
}

// File & Artifact Models

type FileContent struct {
    Path     string            `json:"path"`
    Content  string            `json:"content"`      // Base64 or UTF-8 (Encoding indicates)
    Size     int64             `json:"size"`
    SHA      string            `json:"sha"`
    Encoding string            `json:"encoding"`     // base64|utf-8
    Metadata map[string]string `json:"metadata,omitempty"`
}

type Artifact struct {
    ID          int64             `json:"id"`
    Name        string            `json:"name"`
    Size        int64             `json:"size"`
    Files       []ArtifactFile    `json:"files"`
    DownloadURL string            `json:"download_url"`
    Metadata    map[string]string `json:"metadata,omitempty"`
}

type ArtifactFile struct {
    Path     string `json:"path"`
    Size     int64  `json:"size"`
    SHA      string `json:"sha"`
    MimeType string `json:"mime_type,omitempty"`
}

type SBOMDocument struct {
    Format   string            `json:"format"`
    Version  string            `json:"version"`
    Content  string            `json:"content"`
    Source   string            `json:"source"`
    Metadata map[string]string `json:"metadata,omitempty"`
}

type TestResult struct {
    Suite    string            `json:"suite"`
    Status   string            `json:"status"`
    Duration int64             `json:"duration"` // ms
    Tests    []TestCase        `json:"tests"`
    Coverage *CoverageReport   `json:"coverage,omitempty"`
    Metadata map[string]string `json:"metadata,omitempty"`
}

type TestCase struct {
    Name     string `json:"name"`
    Status   string `json:"status"`
    Duration int64  `json:"duration"`
    Error    string `json:"error,omitempty"`
}

type CoverageReport struct {
    Percentage float64          `json:"percentage"`
    Lines      int64            `json:"lines"`
    Covered    int64            `json:"covered"`
    Files      []FileCoverage   `json:"files"`
}

type FileCoverage struct {
    Path       string  `json:"path"`
    Percentage float64 `json:"percentage"`
    Lines      int64   `json:"lines"`
    Covered    int64   `json:"covered"`
}

type BuildLog struct {
    Job      string            `json:"job"`
    Stage    string            `json:"stage"`
    Content  string            `json:"content"`
    URL      string            `json:"url"`
    Status   string            `json:"status"`
    Duration int64             `json:"duration"`
    Metadata map[string]string `json:"metadata,omitempty"`
}

// Policy Inputs

type VulnerabilityPolicyInput struct {
    SBOMs       []SBOMDocument   `json:"sboms"`
    Repository  RepositoryInfo   `json:"repository"`
    PullRequest *PullRequestInfo `json:"pull_request,omitempty"`
    WorkflowRun *WorkflowRunInfo `json:"workflow_run,omitempty"`
}

type LicensePolicyInput struct {
    SBOMs       []SBOMDocument   `json:"sboms"`
    Repository  RepositoryInfo   `json:"repository"`
    PullRequest *PullRequestInfo `json:"pull_request,omitempty"`
    WorkflowRun *WorkflowRunInfo `json:"workflow_run,omitempty"`
}

// Results & Violations

type PolicyResult struct {
    Processed  bool              `json:"processed"`
    Violations []PolicyViolation `json:"violations"`
    CheckRun   *CheckRunRequest  `json:"check_run,omitempty"`
    Comments   []CommentRequest  `json:"comments,omitempty"`
}

type PolicyViolation struct {
    Severity    string                 `json:"severity"`
    Title       string                 `json:"title"`
    Description string                 `json:"description"`
    Component   string                 `json:"component,omitempty"`
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Comment / Check Models

type CommentRequest struct {
    Body       string          `json:"body"`
    Review     *ReviewComment  `json:"review,omitempty"`
    File       *FileComment    `json:"file,omitempty"`
    UpdateMode CommentUpdateMode `json:"update_mode,omitempty"` // smart|append|replace
    Marker     string          `json:"marker,omitempty"`        // hidden signature for smart updates
}

type CommentUpdateMode string
const (
    CommentUpdateSmart   CommentUpdateMode = "smart"
    CommentUpdateAppend  CommentUpdateMode = "append"
    CommentUpdateReplace CommentUpdateMode = "replace"
)

type FileComment struct {
    Path     string `json:"path"`
    Position int    `json:"position"`
}

type ReviewComment struct {
    Event string `json:"event"` // APPROVE|REQUEST_CHANGES|COMMENT
    Body  string `json:"body"`
}

type CheckRunRequest struct {
    Name    string `json:"name"`
    Status  string `json:"status"`  // success|failure|neutral
    Summary string `json:"summary"`
}

type CheckRunUpdate struct {
    Status  string `json:"status"`
    Summary string `json:"summary"`
}
```

## Error Taxonomy (Minimal v0.1)

```go
type PluginErrorCategory string
const (
    ErrCategoryTransient PluginErrorCategory = "transient"   // Retry advisable
    ErrCategoryPermanent PluginErrorCategory = "permanent"   // Do not retry
    ErrCategoryContract  PluginErrorCategory = "contract"    // Plugin/Core mismatch
)
```
Plugins SHOULD wrap errors with category hints (string metadata) until richer typed errors are added.

## Smart Comment Update Strategy
- Polly searches existing PR comments for hidden marker: `<!-- POLLY:marker=<Marker> -->`
- If found and `UpdateMode=smart`, Polly edits that comment instead of creating a new one.
- If `replace`, Polly deletes then recreates.
- If `append`, Polly adds a new comment always.

## Lifecycle States
1. Discovered → 2. Loaded → 3. Initialized → 4. Healthy → 5. Degraded (health fail threshold) → 6. Restarting → 7. Terminated

## Concurrency Model (MVP)
- Each event processed concurrently across plugins (goroutine per plugin)
- Per-plugin in-flight limit: 1 (queue subsequent events) to simplify ordering initially
- Context deadline inherited from webhook HTTP timeout

## Logging Contract (Key Fields)
`plugin`, `event_type`, `event_action`, `processed`, `violations_count`, `duration_ms`, `error` (if any)

## Reserved Future Additions
- Sandboxing guidelines
- Signature verification details
- Metrics (OpenTelemetry spans + counters)

---
This reference deliberately limits scope to unblock implementation while keeping forward extensibility.
