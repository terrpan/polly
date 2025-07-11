package handlers

import (
	"fmt"
	"strings"

	"github.com/go-playground/webhooks/v6/github"
	"github.com/terrpan/polly/internal/services"
)

// buildCheckRunResult builds the check run result based on policy validation outcome.
func buildCheckRunResult(policyPassed bool, policyError error) (services.CheckRunConclusion, services.CheckRunResult) {
	if policyError != nil {
		return services.ConclusionFailure, services.CheckRunResult{
			Title:   "OPA Policy Check - Error",
			Summary: "Policy validation failed due to error",
			Text:    fmt.Sprintf("Error: %v", policyError),
		}
	}
	if policyPassed {
		return services.ConclusionSuccess, services.CheckRunResult{
			Title:   "OPA Policy Check - Passed",
			Summary: "All policies passed",
			Text:    "The policy validation succeeded.",
		}
	}
	return services.ConclusionFailure, services.CheckRunResult{
		Title:   "OPA Policy Check - Failed",
		Summary: "Policy validation failed",
		Text:    "The policy validation failed.",
	}
}

// buildVulnerabilityViolationComment generates a markdown comment for vulnerability policy violations.
func buildVulnerabilityViolationComment(vulns []services.VulnerabilityPolicyVuln) string {
	vulnComments := make([]string, 0, len(vulns))
	for _, vuln := range vulns {
		comment := fmt.Sprintf("**Package:** `%s@%s`\n**Vulnerability:** %s\n**Severity:** %s",
			vuln.Package, vuln.Version, vuln.ID, vuln.Severity)

		if vuln.Score > 0 {
			comment += fmt.Sprintf("\n**CVSS Score:** %.1f", vuln.Score)
		}

		if vuln.FixedVersion != "" {
			comment += fmt.Sprintf("\n**Fixed Version:** `%s`", vuln.FixedVersion)
		}

		vulnComments = append(vulnComments, comment)
	}
	return fmt.Sprintf("🚨 **Vulnerability Policy Violation - %d vulnerabilities blocked**\n\n<details>\n<summary>Click to view policy violation details</summary>\n\n%s\n\n</details>",
		len(vulnComments), strings.Join(vulnComments, "\n\n---\n\n"))
}

// buildLicenseViolationComment generates a markdown comment for license policy violations.
func buildLicenseViolationComment(licenses []string) string {
	return fmt.Sprintf("🚨 **License Policy Violation - %d licenses blocked**\n\n<details>\n<summary>Click to view policy violation details</summary>\n\n%s\n\n</details>",
		len(licenses), strings.Join(licenses, "\n\n---\n\n"))
}

// getEventInfo extracts common event information for logging using generics
func getEventInfo[T github.PullRequestPayload | github.CheckRunPayload | github.WorkflowRunPayload](event T) (owner, repo, sha string, ID int64) {
	// We use type assertion to 'any' here because Go's type switch does not work directly on generic type parameters.
	switch e := any(event).(type) {
	case github.PullRequestPayload:
		return e.Repository.Owner.Login, e.Repository.Name, e.PullRequest.Head.Sha, e.PullRequest.ID
	case github.CheckRunPayload:
		return e.Repository.Owner.Login, e.Repository.Name, e.CheckRun.HeadSHA, e.CheckRun.ID
	case github.WorkflowRunPayload:
		return e.Repository.Owner.Login, e.Repository.Name, e.WorkflowRun.HeadSha, e.WorkflowRun.ID
	default:
		// This should never happen due to type constraints, but just in case
		return "", "", "", 0
	}
}
