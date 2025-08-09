// Package handlers provides HTTP handlers for processing GitHub webhook events.
// This file specifically handles check suite events
package handlers

import (
	"context"

	"github.com/go-playground/webhooks/v6/github"
	"go.opentelemetry.io/otel/attribute"
)

// CheckSuiteWebhookHandler handles GitHub check suite events
type CheckSuiteWebhookHandler struct {
	*SecurityWebhookHandler
	checkRunHandler *CheckRunHandler
}

// NewCheckSuiteWebhookHandler creates a new CheckSuiteWebhookHandler with the given base handler.
func NewCheckSuiteWebhookHandler(base *BaseWebhookHandler) *CheckSuiteWebhookHandler {
	return &CheckSuiteWebhookHandler{
		SecurityWebhookHandler: NewSecurityWebhookHandler(base),
		checkRunHandler:        NewCheckRunHandler(base),
	}
}

// HandleCheckSuite processes a check suite event from GitHub.
func (h *CheckSuiteWebhookHandler) HandleCheckSuite(
	ctx context.Context,
	event github.CheckSuitePayload,
) error {
	ctx, span := h.telemetry.StartSpan(ctx, "webhook.handle_check_suite")
	defer span.End()

	span.SetAttributes(
		attribute.String("action", event.Action),
		attribute.Int64("check_suite_id", event.CheckSuite.ID),
	)

	h.logger.InfoContext(ctx, "Processing check suite event",
		"action", event.Action,
		"check_suite_id", event.CheckSuite.ID,
	)

	switch event.Action {
	case "requested":
		return h.handleCheckSuiteRequested(ctx, event)
	case "rerequested":
		return h.handleCheckSuiteRerequested(ctx, event)
	case "completed":
		return h.handleCheckSuiteCompleted(ctx, event)
	default:
		h.logger.InfoContext(ctx, "Ignoring check suite event action", "action", event.Action)
		return nil
	}
}

// handleCheckSuiteRequested processes initial check suite creation (from PR/push)
func (h *CheckSuiteWebhookHandler) handleCheckSuiteRequested(
	ctx context.Context,
	event github.CheckSuitePayload,
) error {
	ctx, span := h.telemetry.StartSpan(ctx, "webhook.handle_check_suite_requested")
	defer span.End()

	owner, repo, sha, id := getEventInfo(event)
	h.telemetry.SetRepositoryAttributes(span, owner, repo, sha)
	span.SetAttributes(
		attribute.Int64("check_suite_id", id),
	)

	h.logger.InfoContext(ctx, "Handling check suite requested event",
		"owner", owner,
		"repo", repo,
		"sha", sha,
		"check_suite_id", id,
	)

	// Store check suite ID as the primary coordinator
	if err := h.stateService.StoreCheckSuiteID(ctx, owner, repo, sha, id); err != nil {
		h.logger.WarnContext(ctx, "Failed to store check suite ID",
			"owner", owner, "repo", repo, "sha", sha, "check_suite_id", id, "error", err)
		h.telemetry.SetErrorAttribute(span, err)
	}

	// Delegate to security workflow processing
	return h.processSecurityWorkflow(ctx, owner, repo, sha)
}

// handleCheckSuiteRerequested processes a check suite rerequested event.
func (h *CheckSuiteWebhookHandler) handleCheckSuiteRerequested(
	ctx context.Context,
	event github.CheckSuitePayload,
) error {
	ctx, span := h.telemetry.StartSpan(ctx, "webhook.handle_check_suite_rerequested")
	defer span.End()

	owner, repo, sha, id := getEventInfo(event)
	h.telemetry.SetRepositoryAttributes(span, owner, repo, sha)
	span.SetAttributes(
		attribute.Int64("check_suite_id", id),
	)

	h.logger.InfoContext(ctx, "Handling check suite rerequested event",
		"owner", owner,
		"repo", repo,
		"sha", sha,
		"check_suite_id", id,
	)

	h.logger.InfoContext(ctx, "Rerunning existing checks for check suite",
		"owner", owner,
		"repo", repo,
		"sha", sha,
		"check_suite_id", id,
	)

	// Check for existing runs and delegate to rerun existing checks
	return h.rerunExistingChecks(ctx, owner, repo, sha)
}

// processSecurityWorkflow delegates security workflow processing
func (h *CheckSuiteWebhookHandler) processSecurityWorkflow(
	ctx context.Context,
	owner, repo, sha string,
) error {
	workflowID, found, err := h.stateService.GetWorkflowRunID(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to retrieve workflow run ID",
			"owner", owner, "repo", repo, "sha", sha, "error", err)

		return err
	}

	if !found {
		h.logger.InfoContext(ctx, "No associated workflow found for check suite",
			"owner", owner, "repo", repo, "sha", sha)

		return nil
	}

	// Delegate to security workflow handler
	config := WebhookProcessingConfig{
		Owner:         owner,
		Repo:          repo,
		SHA:           sha,
		WorkflowRunID: workflowID,
		CheckVuln:     true,
		CheckLicense:  true,
	}

	return h.processWorkflowSecurityArtifacts(ctx, config)
}

// rerunExistingChecks delegates check run reruns logic
func (h *CheckSuiteWebhookHandler) rerunExistingChecks(
	ctx context.Context,
	owner, repo, sha string,
) error {
	vulnCheckID, hasVuln, licenseCheckID, hasLicense := h.getExistingCheckRunIDs(
		ctx,
		owner,
		repo,
		sha,
	)

	// If no existing checks, treat as a new request
	if !hasVuln && !hasLicense {
		h.logger.InfoContext(ctx, "No existing checks found, processing as new check suite",
			"owner", owner, "repo", repo, "sha", sha)

		return h.processSecurityWorkflow(ctx, owner, repo, sha)
	}

	if h.tryRerunWithPrefetchedArtifacts(
		ctx,
		owner,
		repo,
		sha,
		vulnCheckID,
		hasVuln,
		licenseCheckID,
		hasLicense,
	) {
		return nil
	}

	return h.fallbackReruns(ctx, owner, repo, sha, vulnCheckID, hasVuln, licenseCheckID, hasLicense)
}

// getExistingCheckRunIDs retrieves existing check run IDs with error handling
func (h *CheckSuiteWebhookHandler) getExistingCheckRunIDs(
	ctx context.Context,
	owner, repo, sha string,
) (int64, bool, int64, bool) {
	vulnCheckID, hasVuln, err := h.stateService.GetVulnerabilityCheckRunID(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to get vulnerability check run ID",
			"owner", owner, "repo", repo, "sha", sha, "error", err,
		)

		hasVuln = false
		vulnCheckID = 0
	}

	licenseCheckID, hasLicense, err := h.stateService.GetLicenseCheckRunID(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to get license check run ID",
			"owner", owner, "repo", repo, "sha", sha, "error", err,
		)

		hasLicense = false
		licenseCheckID = 0
	}

	return vulnCheckID, hasVuln, licenseCheckID, hasLicense
}

// tryRerunWithPrefetchedArtifacts attempts to process artifacts once and restart checks; returns true if handled
func (h *CheckSuiteWebhookHandler) tryRerunWithPrefetchedArtifacts(
	ctx context.Context,
	owner, repo, sha string,
	vulnCheckID int64, hasVuln bool,
	licenseCheckID int64, hasLicense bool,
) bool {
	workflowID, found, err := h.stateService.GetWorkflowRunID(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to retrieve workflow run ID",
			"owner", owner, "repo", repo, "sha", sha, "error", err,
		)

		return false
	}

	if !found || workflowID <= 0 {
		return false
	}

	vulnPayloads, sbomPayloads, err := h.securityService.ProcessWorkflowSecurityArtifacts(
		ctx, owner, repo, sha, workflowID,
	)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to process workflow artifacts for rerun",
			"owner", owner, "repo", repo, "sha", sha, "workflow_id", workflowID, "error", err,
		)

		return false
	}

	prNumber, exists, err := h.stateService.GetPRNumber(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to retrieve PR number",
			"owner", owner, "repo", repo, "sha", sha, "error", err,
		)
	}

	if !exists {
		prNumber = 0
	}

	if hasVuln {
		h.logger.InfoContext(ctx, "Restarting vulnerability check",
			"check_run_id", vulnCheckID, "sha", sha,
		)

		if err := h.checkService.StartVulnerabilityCheck(ctx, owner, repo, vulnCheckID); err != nil {
			h.logger.ErrorContext(ctx, "Failed to start vulnerability check",
				"owner", owner, "repo", repo, "check_run_id", vulnCheckID, "error", err,
			)
		}

		if err := h.checkRunHandler.restartVulnerabilityCheckInternal(ctx, owner, repo, sha, vulnCheckID, vulnPayloads, sbomPayloads, prNumber); err != nil {
			h.logger.ErrorContext(ctx, "Failed to rerun vulnerability check",
				"owner", owner, "repo", repo, "sha", sha, "check_id", vulnCheckID, "error", err,
			)
		}
	}

	if hasLicense {
		h.logger.InfoContext(ctx, "Restarting license check",
			"check_run_id", licenseCheckID, "sha", sha,
		)

		if err := h.checkService.StartLicenseCheck(ctx, owner, repo, licenseCheckID); err != nil {
			h.logger.ErrorContext(ctx, "Failed to start license check",
				"owner", owner, "repo", repo, "check_run_id", licenseCheckID, "error", err,
			)
		}

		if err := h.checkRunHandler.restartLicenseCheckInternal(ctx, owner, repo, sha, licenseCheckID, vulnPayloads, sbomPayloads, prNumber); err != nil {
			h.logger.ErrorContext(ctx, "Failed to rerun license check",
				"owner", owner, "repo", repo, "sha", sha, "check_id", licenseCheckID, "error", err,
			)
		}
	}

	return true
}

// fallbackReruns uses per-check rerun handlers when artifacts aren't available
func (h *CheckSuiteWebhookHandler) fallbackReruns(
	ctx context.Context,
	owner, repo, sha string,
	vulnCheckID int64, hasVuln bool,
	licenseCheckID int64, hasLicense bool,
) error {
	if hasVuln {
		if err := h.checkRunHandler.handleVulnerabilityCheckRerun(ctx, owner, repo, sha, vulnCheckID); err != nil {
			h.logger.ErrorContext(ctx, "Failed to rerun vulnerability check",
				"owner", owner, "repo", repo, "sha", sha, "check_id", vulnCheckID, "error", err,
			)
		}
	}

	if hasLicense {
		if err := h.checkRunHandler.handleLicenseCheckRerun(ctx, owner, repo, sha, licenseCheckID); err != nil {
			h.logger.ErrorContext(ctx, "Failed to rerun license check",
				"owner", owner, "repo", repo, "sha", sha, "check_id", licenseCheckID, "error", err,
			)
		}
	}

	return nil
}

// handleCheckSuiteCompleted processes check suite completion.
func (h *CheckSuiteWebhookHandler) handleCheckSuiteCompleted(
	ctx context.Context,
	event github.CheckSuitePayload,
) error {
	ctx, span := h.telemetry.StartSpan(ctx, "webhook.handle_check_suite_completed")
	defer span.End()

	owner, repo, sha, id := getEventInfo(event)
	h.telemetry.SetRepositoryAttributes(span, owner, repo, sha)
	span.SetAttributes(
		attribute.Int64("check_suite_id", id),
	)

	h.logger.InfoContext(ctx, "Check suite completed",
		"owner", owner,
		"repo", repo,
		"sha", sha,
		"check_suite_id", id,
		"conclusion", event.CheckSuite.Conclusion,
	)

	return nil
}

// getEventInfo extracts owner, repo, sha and check suite ID from a check suite event.
// Mirrors helper pattern used for other webhook handlers.
// NOTE: getEventInfo generic helper (in helpers.go) already supports CheckSuitePayload.
