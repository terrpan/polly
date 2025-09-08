<!-- Moved from docs/PLUGIN_FILE_ACCESS_GUIDE.md -->
# Plugin File and Artifact Access Guide

This guide documents how plugins can access repository files and CI artifacts through the Polly Helper Services.

## Overview

Polly 2.0 provides two primary ways for plugins to access file content:

1. **Repository Files**: Access files from the Git repository at specific commits or PRs
2. **CI Artifacts**: Access build outputs, test results, and other artifacts from CI runs

## User Stories

### Repository File Access
> **As a plugin developer, I want to access a file in the repository of a PR or a commit, so that I can use that file in my plugin.**

### CI Artifact Access  
> **As a plugin developer, I want to access a file that is an artifact or a build output of a CI run, so that I can use that artifact in my plugin.**

## PollyHelpers Interface

```go
type PollyHelpers interface {
    // Repository file operations - access files from repository at specific commit/PR
    GetFile(ctx context.Context, owner, repo, sha, path string) (*FileContent, error)
    GetFiles(ctx context.Context, owner, repo, sha string, paths []string) ([]FileContent, error)
    GetPRFiles(ctx context.Context, owner, repo string, prNumber int, paths []string) ([]FileContent, error)
    
    // CI/Artifact operations - access build outputs and CI artifacts
    GetWorkflowArtifacts(ctx context.Context, owner, repo string, runID int64) ([]Artifact, error)
    GetArtifactFile(ctx context.Context, owner, repo string, runID int64, artifactName, filePath string) (*FileContent, error)
    GetSBOMFromArtifacts(ctx context.Context, owner, repo string, runID int64) ([]SBOMDocument, error)
    GetTestResults(ctx context.Context, owner, repo string, runID int64) ([]TestResult, error)
    GetBuildLogs(ctx context.Context, owner, repo string, runID int64) ([]BuildLog, error)
}
```

## Data Structures

### FileContent
Represents a file from either repository or CI artifacts:

```go
type FileContent struct {
    Path        string `json:"path"`         // File path in repository
    Content     string `json:"content"`      // Base64 encoded content
    Size        int64  `json:"size"`         // File size in bytes
    SHA         string `json:"sha"`          // Git SHA of file
    Encoding    string `json:"encoding"`     // "base64" or "utf-8"
    Metadata    map[string]string `json:"metadata,omitempty"` // Additional file info
}
```

### Artifact
Represents a CI build artifact:

```go
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
```

## Usage Examples

### 1. Repository File Access

#### Single File Access
```go
func (p *MyPlugin) processPullRequest(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error) {
    // Get a specific file from the PR head commit
    dockerfile, err := helpers.GetFile(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name, 
        event.PullRequest.Head.SHA,
        "Dockerfile")
    if err != nil {
        return nil, fmt.Errorf("failed to get Dockerfile: %w", err)
    }
    
    // Access file content (automatically decoded from base64)
    content := dockerfile.Content
    size := dockerfile.Size
    
    // Use file content for policy evaluation...
    return processDockerfile(content), nil
}
```

#### Multiple File Access
```go
func (p *MyPlugin) checkDependencies(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) error {
    // Get multiple dependency files at once
    dependencyFiles, err := helpers.GetFiles(ctx, 
        event.Repository.Owner.Login, 
        event.Repository.Name, 
        event.PullRequest.Head.SHA,
        []string{"package.json", "requirements.txt", "go.mod", "Cargo.toml"})
    if err != nil {
        return fmt.Errorf("failed to get dependency files: %w", err)
    }
    
    // Process each dependency file
    for _, file := range dependencyFiles {
        switch file.Path {
        case "package.json":
            p.processNodeDependencies(file.Content)
        case "requirements.txt":
            p.processPythonDependencies(file.Content)
        case "go.mod":
            p.processGoDependencies(file.Content)
        case "Cargo.toml":
            p.processRustDependencies(file.Content)
        }
    }
    
    return nil
}
```

#### PR-Specific File Access
```go
func (p *MyPlugin) processPRFiles(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) error {
    // Get files from PR head commit (convenience method)
    configFiles, err := helpers.GetPRFiles(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name,
        event.PullRequest.Number,
        []string{"config.yaml", "settings.json"})
    if err != nil {
        return fmt.Errorf("failed to get PR config files: %w", err)
    }
    
    // Validate configuration files...
    return p.validateConfigs(configFiles)
}
```

### 2. CI Artifact Access

#### List Available Artifacts
```go
func (p *MyPlugin) processWorkflowRun(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error) {
    // Get all artifacts from the workflow run
    artifacts, err := helpers.GetWorkflowArtifacts(ctx, 
        event.Repository.Owner.Login,
        event.Repository.Name, 
        event.WorkflowRun.ID)
    if err != nil {
        return nil, fmt.Errorf("failed to get workflow artifacts: %w", err)
    }
    
    // Find specific artifacts
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
    
    // Process found artifacts...
    return p.processArtifacts(sbomArtifact, testArtifact), nil
}
```

#### Access Specific File in Artifact
```go
func (p *MyPlugin) extractSBOMFromArtifact(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (string, error) {
    // Get a specific file from within an artifact
    sbomContent, err := helpers.GetArtifactFile(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name,
        event.WorkflowRun.ID,
        "security-reports",      // Artifact name
        "sbom/results.json")     // File path within artifact
    if err != nil {
        return "", fmt.Errorf("failed to get SBOM file from artifact: %w", err)
    }
    
    return sbomContent.Content, nil
}
```

#### Structured Artifact Access
```go
func (p *MyPlugin) analyzeBuildResults(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) error {
    // Get parsed SBOM documents (Polly handles format detection and parsing)
    sboms, err := helpers.GetSBOMFromArtifacts(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name,
        event.WorkflowRun.ID)
    if err != nil {
        return fmt.Errorf("failed to get SBOMs: %w", err)
    }
    
    // Get parsed test results (Polly handles JUnit XML, etc.)
    testResults, err := helpers.GetTestResults(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name,
        event.WorkflowRun.ID)
    if err != nil {
        p.logger.Warn("No test results found", "error", err)
    }
    
    // Get build logs
    buildLogs, err := helpers.GetBuildLogs(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name,
        event.WorkflowRun.ID)
    if err != nil {
        p.logger.Warn("No build logs found", "error", err)
    }
    
    // Process structured data
    return p.analyzeStructuredData(sboms, testResults, buildLogs)
}
```

### 3. Combining Repository and Artifact Data

#### Security Plugin Example
```go
func (p *SecurityPlugin) comprehensiveSecurityCheck(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error) {
    // 1. Get source code files for static analysis
    sourceFiles, err := helpers.GetFiles(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name,
        event.PullRequest.Head.SHA,
        []string{"**/*.go", "**/*.js", "**/*.py"}) // Glob patterns supported
    if err != nil {
        return nil, fmt.Errorf("failed to get source files: %w", err)
    }
    
    // 2. Get dependency manifests
    depFiles, err := helpers.GetFiles(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name,
        event.PullRequest.Head.SHA,
        []string{"package.json", "requirements.txt", "go.mod"})
    if err != nil {
        p.logger.Warn("Failed to get dependency files", "error", err)
    }
    
    // 3. Get security scan results from CI
    sboms, err := helpers.GetSBOMFromArtifacts(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name,
        event.WorkflowRun.ID)
    if err != nil {
        p.logger.Warn("No SBOM artifacts found", "error", err)
    }
    
    // 4. Get test results to check security test coverage
    testResults, err := helpers.GetTestResults(ctx,
        event.Repository.Owner.Login,
        event.Repository.Name,
        event.WorkflowRun.ID)
    if err != nil {
        p.logger.Warn("No test results found", "error", err)
    }
    
    // 5. Comprehensive security analysis combining all data sources
    violations := []PolicyViolation{}
    
    // Static analysis of source code
    staticViolations := p.analyzeSourceCode(sourceFiles)
    violations = append(violations, staticViolations...)
    
    // Dependency vulnerability analysis
    depViolations := p.analyzeDependencies(depFiles, sboms)
    violations = append(violations, depViolations...)
    
    // Security test coverage analysis
    testViolations := p.analyzeSecurityTestCoverage(testResults)
    violations = append(violations, testViolations...)
    
    return &PolicyResult{
        Processed:  true,
        Violations: violations,
        CheckRun: &CheckRunRequest{
            Name:    "Security / Comprehensive Security Analysis",
            Status:  p.getCheckStatus(violations),
            Summary: p.formatComprehensiveSummary(len(sourceFiles), len(depFiles), len(sboms), len(testResults), violations),
        },
    }, nil
}
```

## Error Handling

All file access operations can fail due to various reasons:

```go
func (p *MyPlugin) handleFileAccess(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) error {
    // Always check for errors
    file, err := helpers.GetFile(ctx, owner, repo, sha, "config.yaml")
    if err != nil {
        // Handle different error types
        if isNotFound(err) {
            p.logger.Info("Config file not found, using defaults")
            return p.useDefaultConfig()
        } else if isAccessDenied(err) {
            return fmt.Errorf("insufficient permissions to access file: %w", err)
        } else if isRateLimit(err) {
            p.logger.Warn("Rate limited, will retry later")
            return fmt.Errorf("GitHub API rate limit exceeded: %w", err)
        }
        
        return fmt.Errorf("unexpected error accessing file: %w", err)
    }
    
    // Process file...
    return p.processConfig(file.Content)
}
```

## Performance Considerations

### Caching
Polly automatically caches file content and artifacts to avoid repeated API calls:

- Repository files are cached by `(owner, repo, sha, path)` 
- Artifacts are cached by `(owner, repo, runID, artifactName)`
- Cache is shared across all plugins processing the same event
- Cache TTL is configurable per deployment

### Batch Operations
Use batch operations when possible to reduce API calls:

```go
// ✅ Good - single API call
files, err := helpers.GetFiles(ctx, owner, repo, sha, []string{"file1.txt", "file2.txt", "file3.txt"})

// ❌ Avoid - multiple API calls  
file1, err1 := helpers.GetFile(ctx, owner, repo, sha, "file1.txt")
file2, err2 := helpers.GetFile(ctx, owner, repo, sha, "file2.txt")  
file3, err3 := helpers.GetFile(ctx, owner, repo, sha, "file3.txt")
```

### Glob Patterns
Repository file access supports glob patterns for efficient file discovery:

```go
// Get all Go files in the repository
goFiles, err := helpers.GetFiles(ctx, owner, repo, sha, []string{"**/*.go"})

// Get all test files
testFiles, err := helpers.GetFiles(ctx, owner, repo, sha, []string{"**/*_test.go", "**/test_*.go"})

// Get configuration files
configFiles, err := helpers.GetFiles(ctx, owner, repo, sha, []string{"*.json", "*.yaml", "*.toml"})
```

## CI Platform Abstraction

Polly abstracts different CI platforms (GitHub Actions, GitLab CI, Jenkins) through a unified interface:

```go
// Same interface works across different CI systems
artifacts, err := helpers.GetWorkflowArtifacts(ctx, owner, repo, runID)

// Polly handles the platform-specific artifact formats:
// - GitHub Actions: workflow run artifacts
// - GitLab CI: job artifacts  
// - Jenkins: build artifacts
// - Azure DevOps: pipeline artifacts
```

## Security Considerations

### Access Control
- Polly respects repository permissions and access controls
- Plugins inherit the same access level as the Polly service account
- Private repository access requires appropriate GitHub App permissions

### Content Sanitization  
- File content is base64 encoded to handle binary files safely
- Large files may be truncated with metadata indicating full size
- Sensitive file paths are filtered based on configuration

### Rate Limiting
- Polly manages GitHub API rate limits automatically
- File access operations are queued and batched when possible
- Plugins receive rate limit errors transparently and should handle gracefully

## Migration from Polly 1.x

In Polly 1.x, file access was handled directly in policy processors. In Polly 2.0, this moves to the PollyHelpers interface:

```go
// Polly 1.x - direct GitHub client usage
client := github.NewClient(token)
content, _, _, err := client.Repositories.GetContents(ctx, owner, repo, path, opts)

// Polly 2.0 - use PollyHelpers interface  
file, err := helpers.GetFile(ctx, owner, repo, sha, path)
```

This provides better caching, error handling, and CI platform abstraction.
