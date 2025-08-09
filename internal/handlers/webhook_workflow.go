// Package handlers provides HTTP handlers for health checks and webhook processing.
// This file defines the WorkflowHandler which processes GitHub workflow run events.
package handlers

import (
	"context"

	"github.com/go-playground/webhooks/v6/github"
	"go.opentelemetry.io/otel/attribute"
)

// WorkflowHandler handles workflow run webhook events
type WorkflowHandler struct {
	*SecurityWebhookHandler
}

// NewWorkflowHandler creates a new workflow handler
func NewWorkflowHandler(base *BaseWebhookHandler) *WorkflowHandler {
	return &WorkflowHandler{
		SecurityWebhookHandler: NewSecurityWebhookHandler(base),
	}
}

// HandleWorkflowRunEvent processes workflow run events.
func (h *WorkflowHandler) HandleWorkflowRunEvent(
	ctx context.Context,
	event github.WorkflowRunPayload,
) error {
	ctx, span := h.telemetry.StartSpan(ctx, "webhook.handle_workflow_run")
	defer span.End()

	span.SetAttributes(
		attribute.String("workflow.name", event.Workflow.Name),
		attribute.String("workflow.status", event.Workflow.State),
		attribute.String("workflow.action", event.Action),
		attribute.Int64("workflow.id", event.WorkflowRun.ID),
		attribute.String("workflow.conclusion", event.WorkflowRun.Conclusion),
	)

	h.logger.InfoContext(ctx,
		"Processing workflow run event",
		"action", event.Action,
		"workflow_run_id", event.WorkflowRun.ID,
	)

	owner, repo, sha, workflowRunID := getEventInfo(event)
	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.String("github.sha", sha),
		attribute.Int64("github.workflow_run_id", workflowRunID),
	)

	// Handle workflow start - create a pending security check run
	if event.Action == "requested" || event.Action == "in_progress" {
		return h.handleWorkflowStarted(ctx, event, owner, repo, sha, workflowRunID)
	}

	// Handle workflow completion - process security artifacts
	if event.Action == "completed" {
		return h.handleWorkflowCompleted(ctx, event, owner, repo, sha, workflowRunID)
	}

	// Ignore other actions
	span.SetAttributes(attribute.String("result", "skipped"))
	h.logger.DebugContext(ctx, "Ignoring workflow run event with unsupported action",
		"action", event.Action,
	)

	return nil
}

// handleWorkflowStarted creates pending security checks when a workflow starts
func (h *WorkflowHandler) handleWorkflowStarted(
	ctx context.Context,
	event github.WorkflowRunPayload,
	owner, repo, sha string,
	workflowRunID int64,
) error {
	ctx, span := h.telemetry.StartSpan(ctx, "workflow.handle_workflow_started")
	defer span.End()

	h.logger.InfoContext(ctx, "Workflow started - creating pending security checks",
		"owner", owner,
		"repo", repo,
		"workflow_name", event.Workflow.Name,
		"workflow_run_id", workflowRunID,
	)

	// Guard against duplicate creation: if checks already exist, just set them in progress
	if _, hasVuln, err := h.stateService.GetVulnerabilityCheckRunID(ctx, owner, repo, sha); err == nil &&
		hasVuln {
		h.logger.InfoContext(ctx, "Existing vulnerability check found; setting to in_progress",
			"owner", owner, "repo", repo, "sha", sha,
		)

		if err := h.securityCheckMgr.StartExistingSecurityChecksInProgress(ctx, owner, repo, sha); err != nil {
			h.logger.ErrorContext(ctx, "Failed to set existing checks in progress", "error", err)
		}

		return nil
	}

	if _, hasLicense, err := h.stateService.GetLicenseCheckRunID(ctx, owner, repo, sha); err == nil &&
		hasLicense {
		h.logger.InfoContext(ctx, "Existing license check found; setting to in_progress",
			"owner", owner, "repo", repo, "sha", sha,
		)

		if err := h.securityCheckMgr.StartExistingSecurityChecksInProgress(ctx, owner, repo, sha); err != nil {
			h.logger.ErrorContext(ctx, "Failed to set existing checks in progress", "error", err)
		}

		return nil
	}

	// Get PR number from stored context
	prNumber, exists, err := h.stateService.GetPRNumber(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to get PR number for SHA",
			"error", err,
			"sha", sha,
		)

		return err
	}

	if !exists {
		h.logger.InfoContext(ctx, "No PR context found for SHA - skipping security check creation",
			"sha", sha,
		)

		return nil
	}

	h.logger.InfoContext(ctx, "Found PR context for security checks",
		"sha", sha,
		"pr_number", prNumber,
	)

	// Create security check runs
	return h.securityCheckMgr.CreateSecurityCheckRuns(ctx, owner, repo, sha, prNumber)
}

// handleWorkflowCompleted processes security artifacts when a workflow completes
func (h *WorkflowHandler) handleWorkflowCompleted(
	ctx context.Context,
	event github.WorkflowRunPayload,
	owner, repo, sha string,
	workflowRunID int64,
) error {
	ctx, span := h.telemetry.StartSpan(ctx, "workflow.handle_workflow_completed")
	defer span.End()

	h.logger.InfoContext(ctx, "Processing completed workflow",
		"owner", owner, "repo", repo, "sha", sha, "workflow_run_id", workflowRunID,
		"conclusion", event.WorkflowRun.Conclusion, "artifacts_url", event.WorkflowRun.ArtifactsURL)

	// Store workflow run ID for check run reruns and artifact processing
	if err := h.stateService.StoreWorkflowRunID(ctx, owner, repo, sha, workflowRunID); err != nil {
		h.logger.ErrorContext(ctx, "Failed to store workflow run ID", "error", err)
	}

	// Handle non-success conclusions or missing artifacts
	if event.WorkflowRun.Conclusion != "success" {
		h.logger.DebugContext(
			ctx,
			"Handling workflow run event with non-success conclusion as a failed workflow",
			"conclusion",
			event.WorkflowRun.Conclusion,
		)

		return h.securityCheckMgr.CompleteSecurityChecksAsNeutral(ctx, owner, repo, sha)
	}

	// Handle missing artifacts
	if event.WorkflowRun.ArtifactsURL == "" {
		h.logger.DebugContext(
			ctx,
			"Ignoring workflow run event with no artifacts URL",
			"artifacts_url",
			event.WorkflowRun.ArtifactsURL,
		)

		return h.securityCheckMgr.CompleteSecurityChecksAsNeutral(ctx, owner, repo, sha)
	}

	// Get PR number for processing
	prNumber := h.getPRNumberForWorkflow(ctx, owner, repo, sha)
	if prNumber == 0 {
		h.logger.DebugContext(ctx, "No PR context found for SHA", "sha", sha)
		return nil
	}

	// Process security artifacts
	config := WebhookProcessingConfig{
		Owner:         owner,
		Repo:          repo,
		SHA:           sha,
		WorkflowRunID: workflowRunID,
		PRNumber:      prNumber,
		CheckVuln:     true,
		CheckLicense:  true,
	}

	return h.processWorkflowSecurityArtifacts(ctx, config)
}

// getPRNumberForWorkflow retrieves the PR number associated with a workflow
func (h *WorkflowHandler) getPRNumberForWorkflow(
	ctx context.Context,
	owner, repo, sha string,
) int64 {
	prNumber, exists, err := h.stateService.GetPRNumber(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to get PR number for SHA", "error", err, "sha", sha)
		return 0
	}

	if !exists {
		h.logger.DebugContext(ctx, "No PR context found for SHA", "sha", sha)
		return 0
	}

	return prNumber
}
