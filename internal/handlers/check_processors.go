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
	result := processVulnerabilityPolicies(ctx, logger, policyCacheService, payloads, owner, repo, sha)

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
	if result.AllPassed {
		return services.ConclusionSuccess, services.CheckRunResult{
			Title:   "Vulnerability Check - Passed",
			Summary: fmt.Sprintf("Processed %d vulnerability findings", payloadCount),
			Text:    "All vulnerability policies passed.",
		}
	}

	return services.ConclusionFailure, services.CheckRunResult{
		Title: "Vulnerability Check - Failed",
		Summary: fmt.Sprintf(
			"Found vulnerability violations in %d scan results",
			len(result.FailureDetails),
		),
		Text: fmt.Sprintf(
			"Vulnerability violations found:\n\n%s",
			strings.Join(result.FailureDetails, "\n"),
		),
	}
}

// buildLicenseCheckResult builds the check run result for license checks
func buildLicenseCheckResult(
	result PolicyProcessingResult,
	payloadCount int,
) (services.CheckRunConclusion, services.CheckRunResult) {
	if result.AllPassed {
		return services.ConclusionSuccess, services.CheckRunResult{
			Title:   "License Check - Passed",
			Summary: fmt.Sprintf("Processed %d SBOM findings", payloadCount),
			Text:    "All license policies passed.",
		}
	}

	return services.ConclusionFailure, services.CheckRunResult{
		Title: "License Check - Failed",
		Summary: fmt.Sprintf(
			"Found license violations in %d scan results",
			len(result.FailureDetails),
		),
		Text: fmt.Sprintf(
			"License violations found:\n\n%s",
			strings.Join(result.FailureDetails, "\n"),
		),
	}
}
