package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/terrpan/polly/internal/services"
)

// processVulnerabilityChecks processes vulnerability payloads, posts comments for violations, and completes the check run.
func processVulnerabilityChecks(
	ctx context.Context,
	logger *slog.Logger,
	policyCacheService *services.PolicyCacheService,
	commentService *services.CommentService,
	checkService *services.CheckService,
	payloads []*services.VulnerabilityPayload,
	owner, repo, sha string,
	prNumber int64,
	checkRunID int64,
) error {
	result := processVulnerabilityPolicies(
		ctx,
		logger,
		policyCacheService,
		payloads,
		owner,
		repo,
		sha,
	)

	if err := postVulnerabilityComments(ctx, logger, commentService, result.NonCompliantVulns, owner, repo, prNumber); err != nil {
		logger.ErrorContext(ctx, "Failed to post vulnerability comment", "error", err)
	}

	conclusion, checkResult := buildVulnerabilityCheckResult(result, len(payloads))

	return checkService.CompleteVulnerabilityCheck(
		ctx,
		owner,
		repo,
		checkRunID,
		conclusion,
		checkResult,
	)
}

// processLicenseChecks processes SBOM payloads, posts comments for violations, and completes the check run.
func processLicenseChecks(
	ctx context.Context,
	logger *slog.Logger,
	policyCacheService *services.PolicyCacheService,
	commentService *services.CommentService,
	checkService *services.CheckService,
	payloads []*services.SBOMPayload,
	owner, repo, sha string,
	prNumber int64,
	checkRunID int64,
) error {
	result := processLicensePolicies(ctx, logger, policyCacheService, payloads, owner, repo, sha)

	if err := postLicenseComments(ctx, logger, commentService, result.NonCompliantComponents, result.ConditionalComponents, owner, repo, prNumber); err != nil {
		logger.ErrorContext(ctx, "Failed to post license comment", "error", err)
	}

	conclusion, checkResult := buildLicenseCheckResult(result, len(payloads))

	return checkService.CompleteLicenseCheck(ctx, owner, repo, checkRunID, conclusion, checkResult)
}

// postVulnerabilityComments posts vulnerability violation comments if needed
func postVulnerabilityComments(
	ctx context.Context,
	logger *slog.Logger,
	commentService *services.CommentService,
	violations []services.VulnerabilityPolicyVuln,
	owner, repo string,
	prNumber int64,
) error {
	if len(violations) > 0 && prNumber > 0 {
		comment := buildVulnerabilityViolationComment(violations)
		return commentService.WriteComment(ctx, owner, repo, int(prNumber), comment)
	}

	return nil
}

// postLicenseComments posts license violation and conditional comments if needed
func postLicenseComments(
	ctx context.Context,
	logger *slog.Logger,
	commentService *services.CommentService,
	violations, conditionals []services.SBOMPolicyComponent,
	owner, repo string,
	prNumber int64,
) error {
	if (len(violations) > 0 || len(conditionals) > 0) && prNumber > 0 {
		comment := buildLicenseComment(violations, conditionals)
		return commentService.WriteComment(ctx, owner, repo, int(prNumber), comment)
	}

	return nil
}

// buildVulnerabilityCheckResult builds the check run result for vulnerability checks
func buildVulnerabilityCheckResult(
	result PolicyProcessingResult,
	payloadCount int,
) (services.CheckRunConclusion, services.CheckRunResult) {
	return buildStandardCheckResult(
		"Vulnerability",
		"vulnerability findings",
		"vulnerability",
		"Vulnerability",
		result,
		payloadCount,
	)
}

// buildLicenseCheckResult builds the check run result for license checks
func buildLicenseCheckResult(
	result PolicyProcessingResult,
	payloadCount int,
) (services.CheckRunConclusion, services.CheckRunResult) {
	return buildStandardCheckResult(
		"License",
		"SBOM findings",
		"license",
		"License",
		result,
		payloadCount,
	)
}

// buildStandardCheckResult centralizes common result-building logic to avoid duplication
func buildStandardCheckResult(
	checkTitlePrefix string,
	processedFindingsLabel string,
	violationLabelLower string,
	violationHeadingCap string,
	result PolicyProcessingResult,
	payloadCount int,
) (services.CheckRunConclusion, services.CheckRunResult) {
	if result.SystemUnavailable {
		return services.ConclusionNeutral, services.CheckRunResult{
			Title:   fmt.Sprintf("%s Check - System Unavailable", checkTitlePrefix),
			Summary: "Policy evaluation system temporarily unavailable",
			Text: fmt.Sprintf(
				"Unable to evaluate %s policies due to system issues. This is not a policy failure.",
				strings.ToLower(checkTitlePrefix),
			),
		}
	}

	if result.AllPassed {
		return services.ConclusionSuccess, services.CheckRunResult{
			Title:   fmt.Sprintf("%s Check - Passed", checkTitlePrefix),
			Summary: fmt.Sprintf("Processed %d %s", payloadCount, processedFindingsLabel),
			Text:    fmt.Sprintf("All %s policies passed.", strings.ToLower(checkTitlePrefix)),
		}
	}

	return services.ConclusionFailure, services.CheckRunResult{
		Title: fmt.Sprintf("%s Check - Failed", checkTitlePrefix),
		Summary: fmt.Sprintf(
			"Found %s violations in %d scan results",
			violationLabelLower,
			len(result.FailureDetails),
		),
		Text: fmt.Sprintf(
			"%s violations found:\n\n%s",
			violationHeadingCap,
			strings.Join(result.FailureDetails, "\n"),
		),
	}
}
