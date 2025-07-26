package handlers

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-playground/webhooks/v6/github"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/terrpan/polly/internal/services"
)

// CheckRunHandler handles check run webhook events (for reruns)
type CheckRunHandler struct {
	*BaseWebhookHandler
}

// NewCheckRunHandler creates a new check run handler
func NewCheckRunHandler(base *BaseWebhookHandler) *CheckRunHandler {
	return &CheckRunHandler{
		BaseWebhookHandler: base,
	}
}

// HandleCheckRunEvent processes check run events.
// Used for handling rerequested check runs.
func (h *CheckRunHandler) HandleCheckRunEvent(
	ctx context.Context,
	event github.CheckRunPayload,
) error {
	ctx, span := h.tracingHelper.StartSpan(ctx, "webhook.handle_check_run")
	defer span.End()

	span.SetAttributes(
		attribute.String("check_run.action", event.Action),
		attribute.Int64("check_run.id", event.CheckRun.ID),
	)

	h.logger.InfoContext(
		ctx,
		"Processing check run event",
		"action",
		event.Action,
		"check_run_id",
		event.CheckRun.ID,
	)

	if event.Action != "rerequested" {
		span.SetAttributes(attribute.String("result", "skipped"))
		h.logger.DebugContext(ctx, "Ignoring non-rerequested check run event")

		return nil
	}

	return h.handleCheckRunRerun(ctx, event, span)
}

// handleCheckRunRerun handles the rerun logic for check run events
func (h *CheckRunHandler) handleCheckRunRerun(
	ctx context.Context,
	event github.CheckRunPayload,
	span trace.Span,
) error {
	owner, repo, sha, checkRunID := getEventInfo(event)
	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.String("github.sha", sha),
		attribute.Int64("github.check_run_id", checkRunID),
	)

	h.logger.DebugContext(ctx, "Handling check run event",
		"owner", owner, "repo", repo, "sha", sha, "check_run_id", checkRunID)

	// Store PR number if available
	if err := h.storePRNumberFromCheckRun(ctx, event, owner, repo, sha); err != nil {
		// Log error but don't fail the entire operation
		h.logger.ErrorContext(ctx, "Failed to store PR number", "error", err)
	}

	// Route to appropriate security check handler
	return h.routeSecurityCheckRerun(ctx, event.CheckRun.Name, owner, repo, sha, checkRunID)
}

// storePRNumberFromCheckRun extracts and stores PR number from check run if available
func (h *CheckRunHandler) storePRNumberFromCheckRun(
	ctx context.Context,
	event github.CheckRunPayload,
	owner, repo, sha string,
) error {
	if len(event.CheckRun.PullRequests) == 0 {
		return nil
	}

	prNumber := int64(event.CheckRun.PullRequests[0].Number)

	err := h.stateService.StorePRNumber(ctx, owner, repo, sha, prNumber)
	if err != nil {
		return fmt.Errorf("failed to store PR number for SHA %s: %w", sha, err)
	}

	h.logger.DebugContext(ctx, "Stored PR context from check run",
		"sha", sha, "pr_number", prNumber)

	return nil
}

// routeSecurityCheckRerun routes the rerun request to the appropriate security check handler
func (h *CheckRunHandler) routeSecurityCheckRerun(
	ctx context.Context,
	checkName, owner, repo, sha string,
	checkRunID int64,
) error {
	h.logger.InfoContext(ctx, "Check run rerun requested",
		"owner", owner, "repo", repo, "sha", sha,
		"check_run_id", checkRunID, "check_name", checkName)

	switch {
	case strings.Contains(checkName, "Vulnerability"):
		return h.handleVulnerabilityCheckRerun(ctx, owner, repo, sha, checkRunID)
	case strings.Contains(checkName, "License"):
		return h.handleLicenseCheckRerun(ctx, owner, repo, sha, checkRunID)
	default:
		h.logger.DebugContext(ctx, "Unknown check type for rerun - skipping",
			"check_name", checkName, "check_run_id", checkRunID)

		return nil
	}
}

// handleVulnerabilityCheckRerun handles rerunning vulnerability security checks
func (h *CheckRunHandler) handleVulnerabilityCheckRerun(
	ctx context.Context,
	owner, repo, sha string,
	checkRunID int64,
) error {
	h.logger.InfoContext(ctx, "Restarting vulnerability check",
		"check_run_id", checkRunID, "sha", sha)

	// Store the check run ID for this SHA
	if err := h.storeCheckRunIDWithError(ctx, owner, repo, sha, checkRunID, "vulnerability", h.stateService.StoreVulnerabilityCheckRunID); err != nil {
		return err
	}

	// Start the vulnerability check and process artifacts if available
	return h.restartVulnerabilityCheck(ctx, owner, repo, sha, checkRunID)
}

// handleLicenseCheckRerun handles rerunning license security checks
func (h *CheckRunHandler) handleLicenseCheckRerun(
	ctx context.Context,
	owner, repo, sha string,
	checkRunID int64,
) error {
	h.logger.InfoContext(ctx, "Restarting license check",
		"check_run_id", checkRunID, "sha", sha)

	// Store the check run ID for this SHA
	if err := h.storeCheckRunIDWithError(ctx, owner, repo, sha, checkRunID, "license", h.stateService.StoreLicenseCheckRunID); err != nil {
		return err
	}

	// Start the license check and process artifacts if available
	return h.restartLicenseCheck(ctx, owner, repo, sha, checkRunID)
}

// SecurityCheckRestartFunc defines the function signature for restarting security checks
type SecurityCheckRestartFunc func(ctx context.Context, owner, repo, sha string, checkRunID int64, vulnPayloads []*services.VulnerabilityPayload, sbomPayloads []*services.SBOMPayload, prNumber int64) error

// restartSecurityCheck is a common handler for restarting security checks
func (h *CheckRunHandler) restartSecurityCheck(
	ctx context.Context,
	checkType, owner, repo, sha string,
	checkRunID int64,
	restartFunc SecurityCheckRestartFunc,
) error {
	ctx, span := h.tracingHelper.StartSpan(
		ctx,
		fmt.Sprintf("check_run.restart_%s_check", checkType),
	)
	defer span.End()

	h.logger.InfoContext(
		ctx,
		fmt.Sprintf("Restarting %s check", checkType),
		"check_run_id",
		checkRunID,
		"sha",
		sha,
	)

	// Store check run ID
	storeFunc := h.stateService.StoreVulnerabilityCheckRunID
	startFunc := h.checkService.StartVulnerabilityCheck
	noArtifactsFunc := h.checkService.CompleteVulnerabilityCheckWithNoArtifacts

	if checkType == "license" {
		storeFunc = h.stateService.StoreLicenseCheckRunID
		startFunc = h.checkService.StartLicenseCheck
		noArtifactsFunc = h.checkService.CompleteLicenseCheckWithNoArtifacts
	}

	if err := h.storeCheckRunIDWithError(ctx, owner, repo, sha, checkRunID, checkType, storeFunc); err != nil {
		return err
	}

	// Start the check run
	if err := startFunc(ctx, owner, repo, checkRunID); err != nil {
		return fmt.Errorf("failed to start %s check: %w", checkType, err)
	}

	// Get stored artifacts
	vulnPayloads, sbomPayloads, prNumber, err := h.getStoredArtifactsAndPR(ctx, owner, repo, sha)
	if err != nil {
		return noArtifactsFunc(ctx, owner, repo, checkRunID)
	}

	return restartFunc(ctx, owner, repo, sha, checkRunID, vulnPayloads, sbomPayloads, prNumber)
}

// getStoredArtifactsAndPR retrieves stored artifacts and PR number for a SHA
func (h *CheckRunHandler) getStoredArtifactsAndPR(
	ctx context.Context,
	owner, repo, sha string,
) ([]*services.VulnerabilityPayload, []*services.SBOMPayload, int64, error) {
	// Get workflow run ID
	workflowRunID, exists, err := h.stateService.GetWorkflowRunID(ctx, owner, repo, sha)
	if err != nil || !exists {
		h.logger.DebugContext(ctx, "No stored artifacts found for SHA", "sha", sha)
		return nil, nil, 0, fmt.Errorf("no artifacts found")
	}

	// Process artifacts
	vulnPayloads, sbomPayloads, err := h.securityService.ProcessWorkflowSecurityArtifacts(
		ctx,
		owner,
		repo,
		sha,
		workflowRunID,
	)
	if err != nil {
		h.logger.ErrorContext(
			ctx,
			"Failed to process stored security artifacts",
			"error",
			err,
			"workflow_run_id",
			workflowRunID,
		)

		return nil, nil, 0, err
	}

	// Get PR number
	prNumber, exists, err := h.stateService.GetPRNumber(ctx, owner, repo, sha)
	if err != nil || !exists {
		h.logger.DebugContext(ctx, "No PR context found for SHA", "sha", sha)

		prNumber = 0
	}

	return vulnPayloads, sbomPayloads, prNumber, nil
}

// restartVulnerabilityCheck restarts a vulnerability check by processing stored artifacts
func (h *CheckRunHandler) restartVulnerabilityCheck(
	ctx context.Context,
	owner, repo, sha string,
	checkRunID int64,
) error {
	return h.restartSecurityCheck(
		ctx,
		"vulnerability",
		owner,
		repo,
		sha,
		checkRunID,
		h.restartVulnerabilityCheckInternal,
	)
}

// restartLicenseCheck restarts a license check by processing stored artifacts
func (h *CheckRunHandler) restartLicenseCheck(
	ctx context.Context,
	owner, repo, sha string,
	checkRunID int64,
) error {
	return h.restartSecurityCheck(
		ctx,
		"license",
		owner,
		repo,
		sha,
		checkRunID,
		h.restartLicenseCheckInternal,
	)
}

// restartVulnerabilityCheckInternal handles the vulnerability-specific restart logic
func (h *CheckRunHandler) restartVulnerabilityCheckInternal(
	ctx context.Context,
	owner, repo, sha string,
	checkRunID int64,
	vulnPayloads []*services.VulnerabilityPayload,
	sbomPayloads []*services.SBOMPayload,
	prNumber int64,
) error {
	if len(vulnPayloads) == 0 {
		return h.checkService.CompleteVulnerabilityCheckWithNoArtifacts(
			ctx,
			owner,
			repo,
			checkRunID,
		)
	}

	return processVulnerabilityChecks(
		ctx,
		h.logger,
		h.policyService,
		h.commentService,
		h.checkService,
		vulnPayloads,
		owner,
		repo,
		sha,
		prNumber,
		checkRunID,
	)
}

// restartLicenseCheckInternal handles the license-specific restart logic
func (h *CheckRunHandler) restartLicenseCheckInternal(
	ctx context.Context,
	owner, repo, sha string,
	checkRunID int64,
	vulnPayloads []*services.VulnerabilityPayload,
	sbomPayloads []*services.SBOMPayload,
	prNumber int64,
) error {
	if len(sbomPayloads) == 0 {
		return h.checkService.CompleteLicenseCheckWithNoArtifacts(ctx, owner, repo, checkRunID)
	}

	return processLicenseChecks(
		ctx,
		h.logger,
		h.policyService,
		h.commentService,
		h.checkService,
		sbomPayloads,
		owner,
		repo,
		sha,
		prNumber,
		checkRunID,
	)
}
