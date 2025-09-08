<!-- Moved from docs/examples/plugin-pr-comments-example.md -->
# Plugin Developer Guide: PR Comments for Policy Violations

## User Story
**As a plugin developer, I want to send a comment to the PR if something in the policy is violated, so that I nudge the user to fix it.**

## Implementation Example

### 1. Plugin Handler with PR Comments (Canonical v0.1 API)

```go
package main

import (
    "context"
    "fmt"
    "strings"
    "time"
)

type VulnerabilityPlugin struct {
    config PluginConfig
    logger *slog.Logger
}

func (p *VulnerabilityPlugin) HandleEvent(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error) {
    // Only process pull request events
    if event.Type != "pull_request" || event.PullRequest == nil {
        return &PolicyResult{Processed: false}, nil
    }

    // Skip if not opened or synchronized
    if event.Action != "opened" && event.Action != "synchronize" {
        return &PolicyResult{Processed: false}, nil
    }

    return p.processPullRequest(ctx, event, helpers)
}

func (p *VulnerabilityPlugin) processPullRequest(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error) {
    // Get SBOMs from workflow artifacts (using workflow run ID if available, else head SHA fallback)
    var sboms []SBOMDocument
    var err error
    if event.WorkflowRun != nil {
        sboms, err = helpers.GetSBOMFromArtifacts(ctx,
            event.Repository.Owner.Login,
            event.Repository.Name,
            event.WorkflowRun.ID)
    } else {
        // Fallback (may be empty if artifacts not yet produced)
        sboms, err = helpers.GetSBOMFromArtifacts(ctx,
            event.Repository.Owner.Login,
            event.Repository.Name,
            event.PullRequest.Head.SHAInt()) // hypothetic helper converting SHA to numeric run ref
    }
    if err != nil {
        return nil, fmt.Errorf("failed to get SBOMs: %w", err)
    }

    // Evaluate vulnerability policy
    violations, err := helpers.EvaluateVulnerabilityPolicy(ctx, "vulnerability/check_sbom", VulnerabilityPolicyInput{
        SBOMs:       sboms,
        Repository:  event.Repository,
        PullRequest: event.PullRequest,
    })
    if err != nil {
        return nil, fmt.Errorf("policy evaluation failed: %w", err)
    }

    // Create result with PR comments for violations
    result := &PolicyResult{
        Processed:  true,
        Violations: violations,
        CheckRun: &CheckRunRequest{
            Name:    "Security / Vulnerability Scan",
            Status:  p.getCheckStatus(violations),
            Summary: p.formatSummary(violations),
        },
    }

    // Always add a comment (smart update will replace previous)
    result.Comments = []CommentRequest{
        p.buildSmartComment(violations, event),
    }

    return result, nil
}
```

### 2. Building Helpful PR Comments

```go
func (p *VulnerabilityPlugin) buildViolationComment(violations []PolicyViolation) string {
    var comment strings.Builder
    
    comment.WriteString("## 🚨 Security Vulnerabilities Detected\n\n")
    comment.WriteString("This pull request introduces packages with known security vulnerabilities:\n\n")

    // Group violations by severity
    criticalViolations := filterViolationsBySeverity(violations, "CRITICAL")
    highViolations := filterViolationsBySeverity(violations, "HIGH")
    mediumViolations := filterViolationsBySeverity(violations, "MEDIUM")

    // Critical vulnerabilities
    if len(criticalViolations) > 0 {
        comment.WriteString("### 🔴 Critical Vulnerabilities\n\n")
        for _, violation := range criticalViolations {
            comment.WriteString(fmt.Sprintf("- **%s**: %s\n", violation.Component, violation.Description))
            if cveID, exists := violation.Metadata["cve_id"]; exists {
                comment.WriteString(fmt.Sprintf("  - CVE: [%s](https://nvd.nist.gov/vuln/detail/%s)\n", cveID, cveID))
            }
            if fixVersion, exists := violation.Metadata["fix_version"]; exists {
                comment.WriteString(fmt.Sprintf("  - **Fix**: Update to version `%s` or later\n", fixVersion))
            }
        }
        comment.WriteString("\n")
    }

    // High vulnerabilities
    if len(highViolations) > 0 {
        comment.WriteString("### 🟡 High Vulnerabilities\n\n")
        for _, violation := range highViolations {
            comment.WriteString(fmt.Sprintf("- **%s**: %s\n", violation.Component, violation.Description))
            if cveID, exists := violation.Metadata["cve_id"]; exists {
                comment.WriteString(fmt.Sprintf("  - CVE: [%s](https://nvd.nist.gov/vuln/detail/%s)\n", cveID, cveID))
            }
            if fixVersion, exists := violation.Metadata["fix_version"]; exists {
                comment.WriteString(fmt.Sprintf("  - **Fix**: Update to version `%s` or later\n", fixVersion))
            }
        }
        comment.WriteString("\n")
    }

    // Medium vulnerabilities (collapsed)
    if len(mediumViolations) > 0 {
        comment.WriteString(fmt.Sprintf("<details>\n<summary>🟠 Medium Vulnerabilities (%d)</summary>\n\n", len(mediumViolations)))
        for _, violation := range mediumViolations {
            comment.WriteString(fmt.Sprintf("- **%s**: %s\n", violation.Component, violation.Description))
        }
        comment.WriteString("</details>\n\n")
    }

    // Add helpful guidance
    comment.WriteString("### 📋 Next Steps\n\n")
    comment.WriteString("1. **Review the vulnerabilities** listed above\n")
    comment.WriteString("2. **Update affected packages** to the recommended versions\n")
    comment.WriteString("3. **Re-run the security scan** by pushing new commits\n\n")
    
    comment.WriteString("💡 **Tip**: You can suppress specific vulnerabilities by adding them to your `.polly-ignore` file if they don't apply to your use case.\n\n")
    comment.WriteString("---\n")
    comment.WriteString("*This comment was generated by the Polly Vulnerability Plugin*")

    return comment.String()
}

func filterViolationsBySeverity(violations []PolicyViolation, severity string) []PolicyViolation {
    var filtered []PolicyViolation
    for _, v := range violations {
        if v.Severity == severity {
            filtered = append(filtered, v)
        }
    }
    return filtered
}
```

### 3. Advanced Comment Features

```go
// Smart comment updates - replace existing comments instead of spamming
func (p *VulnerabilityPlugin) buildSmartComment(violations []PolicyViolation, event EnrichedEvent) CommentRequest {
    body := p.buildViolationComment(violations)
    if len(violations) == 0 {
        body = "## ✅ No Security Vulnerabilities Detected\n\n" +
            "Great job! This pull request doesn't introduce any known security vulnerabilities.\n\n" +
            p.footer()
    }
    return CommentRequest{
        Body:       body + "\n<!-- POLLY:marker=polly-vulnerability-scan -->",
        UpdateMode: CommentUpdateSmart,
        Marker:     "polly-vulnerability-scan",
    }
}

// File-specific comments for targeted feedback
func (p *VulnerabilityPlugin) buildFileSpecificComments(violations []PolicyViolation, event EnrichedEvent) []CommentRequest {
    // Example placeholder logic: in MVP we may not resolve exact line positions
    var comments []CommentRequest
    for _, v := range violations {
        if v.Component == "" { // skip if no file context
            continue
        }
        comments = append(comments, CommentRequest{
            Body: fmt.Sprintf("Potential issue related to `%s`: %s", v.Component, v.Description),
            File: &FileComment{Path: v.Component, Position: 1}, // Position=1 placeholder until diff mapping added
            UpdateMode: CommentUpdateAppend,
        })
    }
    return comments
}
```

### 4. Comment Types Available

The plugin system supports multiple comment types:

```go
// Aligned with PLUGIN_API_REFERENCE.md
type CommentRequest struct {
    Body       string            `json:"body"`
    Review     *ReviewComment    `json:"review,omitempty"`
    File       *FileComment      `json:"file,omitempty"`
    UpdateMode CommentUpdateMode `json:"update_mode,omitempty"`
    Marker     string            `json:"marker,omitempty"`
}

type CommentUpdateMode string
const (
    CommentUpdateSmart   CommentUpdateMode = "smart"
    CommentUpdateAppend  CommentUpdateMode = "append"
    CommentUpdateReplace CommentUpdateMode = "replace"
)

type FileComment struct {
    Path     string `json:"path"`
    Position int    `json:"position"`  // Line number
}

type ReviewComment struct {
    Event string `json:"event"` // "APPROVE", "REQUEST_CHANGES", "COMMENT"
    Body  string `json:"body"`
}
```

### 5. Example Usage in Policy Result

```go
// Alternative example snippet (focused on comment strategies)
func (p *VulnerabilityPlugin) buildResultWithComments(violations []PolicyViolation, event EnrichedEvent) *PolicyResult {
    r := &PolicyResult{Processed: true, Violations: violations}
    switch {
    case len(violations) == 0:
        r.Comments = []CommentRequest{p.buildSmartComment(violations, event)}
    case len(violations) <= 5:
        r.Comments = []CommentRequest{p.buildSmartComment(violations, event)}
    default:
        // Many violations: use file-specific for focus
        r.Comments = p.buildFileSpecificComments(violations, event)
    }
    return r
}

// Helper footer for consistent attribution
func (p *VulnerabilityPlugin) footer() string {
    return "---\n*Generated by Polly Vulnerability Plugin at " + time.Now().UTC().Format(time.RFC3339) + "*"
}
```

## Key Benefits

✅ **Automatic Feedback**: Users get immediate feedback on security issues  
✅ **Actionable Guidance**: Comments include specific fix recommendations  
✅ **Rich Formatting**: Markdown support for clear, readable comments  
✅ **Smart Updates**: Replace existing comments instead of spamming  
✅ **File-Specific**: Target comments to specific files and lines  
✅ **Customizable**: Plugin developers control comment format and content

## Implementation Notes

1. **Helper Service**: `helpers.CreatePRComment()` handles the GitHub API integration
2. **Comment Management**: Polly core manages comment deduplication and updates
3. **Rate Limiting**: All GitHub API calls are rate-limited through Polly's centralized client
4. **Error Handling**: Failed comments don't block the overall policy evaluation
5. **Permissions**: Uses Polly's GitHub App credentials with appropriate comment permissions

This approach gives plugin developers full control over when and how to engage with users through PR comments while leveraging Polly's infrastructure for GitHub integration.
