package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-playground/webhooks/v6/github"
	gogithub "github.com/google/go-github/v72/github"
	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/utils"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// WebhookHandler handles incoming GitHub webhooks.
type WebhookHandler struct {
	logger          *slog.Logger
	hook            *github.Webhook
	commentService  *services.CommentService
	checkService    *services.CheckService
	policyService   *services.PolicyService
	securityService *services.SecurityService
	stateService    *services.StateService
}

// SecurityCheckType represents a type of security check that can be created
type SecurityCheckType struct {
	name   string
	create func() (*gogithub.CheckRun, error)
	start  func(checkRunID int64) error
	store  func(checkRunID int64)
}

// getSecurityCheckTypes returns the configured security check types for the given context
func (h *WebhookHandler) getSecurityCheckTypes(ctx context.Context, owner, repo, sha string) []SecurityCheckType {
	return []SecurityCheckType{
		{
			name: "vulnerability",
			create: func() (*gogithub.CheckRun, error) {
				return h.checkService.CreateVulnerabilityCheck(ctx, owner, repo, sha)
			},
			start: func(checkRunID int64) error {
				return h.checkService.StartVulnerabilityCheck(ctx, owner, repo, checkRunID)
			},
			store: func(checkRunID int64) {
				h.storeCheckRunID(ctx, owner, repo, sha, checkRunID, "vulnerability", h.stateService.StoreVulnerabilityCheckRunID)
			},
		},
		{
			name: "license",
			create: func() (*gogithub.CheckRun, error) {
				return h.checkService.CreateLicenseCheck(ctx, owner, repo, sha)
			},
			start: func(checkRunID int64) error {
				return h.checkService.StartLicenseCheck(ctx, owner, repo, checkRunID)
			},
			store: func(checkRunID int64) {
				h.storeCheckRunID(ctx, owner, repo, sha, checkRunID, "license", h.stateService.StoreLicenseCheckRunID)
			},
		},
	}
}

// createSecurityCheckRuns creates and starts security check runs concurrently
func (h *WebhookHandler) createSecurityCheckRuns(ctx context.Context, checkTypes []SecurityCheckType, owner, repo, sha string, prNumber int64) error {
	tasks := make([]func() error, len(checkTypes))
	for i, ct := range checkTypes {
		ct := ct
		tasks[i] = func() error {
			checkRun, err := ct.create()
			if err != nil {
				h.logger.ErrorContext(ctx, "Failed to create check run",
					"error", err,
					"check_type", ct.name,
					"owner", owner,
					"repo", repo,
					"sha", sha,
				)
				return fmt.Errorf("failed to create %s check: %w", ct.name, err)
			}
			if err := ct.start(checkRun.GetID()); err != nil {
				h.logger.ErrorContext(ctx, "Failed to start check",
					"error", err,
					"check_type", ct.name,
					"check_run_id", checkRun.GetID(),
				)
				return fmt.Errorf("failed to start %s check: %w", ct.name, err)
			}
			ct.store(checkRun.GetID())
			h.logger.InfoContext(ctx, "Created pending check run",
				"check_type", ct.name,
				"check_run_id", checkRun.GetID(),
				"pr_number", prNumber,
			)
			return nil
		}
	}
	errs := utils.ExecuteConcurrently(tasks)
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// storeCheckRunID is a helper method that handles storing check run IDs with consistent error logging
func (h *WebhookHandler) storeCheckRunID(ctx context.Context, owner, repo, sha string, checkRunID int64, checkType string, storeFunc func(context.Context, string, string, string, int64) error) {
	if err := storeFunc(ctx, owner, repo, sha, checkRunID); err != nil {
		h.logger.ErrorContext(ctx, "Failed to store check run ID",
			"error", err,
			"check_type", checkType,
			"owner", owner,
			"repo", repo,
			"sha", sha,
			"check_run_id", checkRunID,
		)
	}
}

// storeCheckRunIDWithError is a helper method that handles storing check run IDs with consistent error logging and returns the error
func (h *WebhookHandler) storeCheckRunIDWithError(ctx context.Context, owner, repo, sha string, checkRunID int64, checkType string, storeFunc func(context.Context, string, string, string, int64) error) error {
	if err := storeFunc(ctx, owner, repo, sha, checkRunID); err != nil {
		h.logger.ErrorContext(ctx, "Failed to store check run ID",
			"error", err,
			"check_type", checkType,
			"owner", owner,
			"repo", repo,
			"sha", sha,
			"check_run_id", checkRunID,
		)
		return err
	}
	return nil
}

// Setups a new WebhookHandler with the provided logger and initializes the GitHub webhook.
// It currently does not support secret verification, but this can be added later.
// It returns an error if the webhook cannot be initialized.
func NewWebhookHandler(logger *slog.Logger,
	commentService *services.CommentService,
	checkService *services.CheckService,
	policyService *services.PolicyService,
	securityService *services.SecurityService,
	stateService *services.StateService) (*WebhookHandler, error) {
	// TODO: Add support for secret verification
	hook, err := github.New()
	if err != nil {
		return nil, err
	}

	return &WebhookHandler{
		logger:          logger,
		hook:            hook,
		commentService:  commentService,
		checkService:    checkService,
		policyService:   policyService,
		securityService: securityService,
		stateService:    stateService, // Initialize state service for storing PR numbers and workflow run IDs
	}, nil
}

// HandleWebhook processes incoming GitHub webhook events.
func (h *WebhookHandler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tracer := otel.Tracer("polly/handlers")
	ctx, span := tracer.Start(ctx, "webhook.handle")
	defer span.End()

	payload, err := h.hook.Parse(r,
		github.PullRequestEvent,
		github.CheckRunEvent,
		github.WorkflowRunEvent,
		github.CheckSuiteEvent,
		github.WorkflowJobEvent,
		github.PushEvent,
	)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		h.logger.Error("Failed to parse webhook", "error", err)
		http.Error(w, "Failed to parse webhook", http.StatusBadRequest)
		return
	}

	eventType := r.Header.Get("X-GitHub-Event")
	h.logger.InfoContext(ctx, "Received webhook event", "event_type", eventType)

	switch event := payload.(type) {
	case github.PullRequestPayload:
		span.SetAttributes(attribute.String("event.type", eventType))
		if err := h.handlePullRequestEvent(ctx, event); err != nil {
			span.SetAttributes(attribute.String("error", err.Error()))
			h.logger.Error("Failed to handle pull request event", "error", err)
			http.Error(w, "Failed to handle pull request event", http.StatusInternalServerError)
			return
		}

	case github.CheckRunPayload:
		span.SetAttributes(attribute.String("event.type", eventType))
		if err := h.handleCheckRunEvent(ctx, event); err != nil {
			span.SetAttributes(attribute.String("error", err.Error()))
			h.logger.Error("Failed to handle check run event", "error", err)
			http.Error(w, "Failed to handle check run event", http.StatusInternalServerError)
			return
		}

	case github.WorkflowRunPayload:
		span.SetAttributes(attribute.String("event.type", eventType))
		if err := h.handleWorkflowRunEvent(ctx, event); err != nil {
			span.SetAttributes(attribute.String("error", err.Error()))
			h.logger.Error("Failed to handle workflow run event", "error", err)
			http.Error(w, "Failed to handle workflow run event", http.StatusInternalServerError)
			return
		}

	case github.CheckSuitePayload, github.WorkflowJobPayload, github.PushPayload:
		span.SetAttributes(attribute.String("event.type", eventType))
		h.logger.DebugContext(ctx, "Ignoring non-essential event type", "event_type", eventType)
		// These events are parsed but not processed - just return success

	default:
		span.SetAttributes(attribute.String("event.type", eventType))
		h.logger.DebugContext(ctx, "Unsupported event type", "event_type", eventType)
		// Don't return an error for unsupported events - just log and continue
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Webhook received successfully"))
}

// handlePullRequestEvent processes pull request events.
func (h *WebhookHandler) handlePullRequestEvent(ctx context.Context, event github.PullRequestPayload) error {
	tracer := otel.Tracer("polly/handlers")
	ctx, span := tracer.Start(ctx, "webhook.handle_pull_request")
	defer span.End()

	span.SetAttributes(
		attribute.String("pr.action", event.Action),
		attribute.Int64("pr.number", event.Number),
	)

	h.logger.InfoContext(ctx,
		"Processing pull request event",
		"action", event.Action,
		"pr_number", event.Number,
	)

	if event.Action != "opened" && event.Action != "reopened" && event.Action != "synchronize" {
		h.logger.DebugContext(ctx, "Ignoring non-opened/reopened/synchronize pull request event",
			"action", event.Action,
		)
		span.SetAttributes(attribute.String("result", "skipped"))
		return nil
	}

	owner, repo, sha, id := getEventInfo(event)
	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.String("github.sha", sha),
		attribute.Int64("github.id", id),
	)

	h.logger.DebugContext(ctx, "Handling pull request event",
		"owner", owner,
		"repo", repo,
		"sha", sha,
		"id", id,
	)

	err := h.stateService.StorePRNumber(ctx, owner, repo, sha, event.Number)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to store PR number for SHA",
			"error", err,
			"sha", sha,
			"pr_number", event.Number,
		)
	}

	// Create security check runs (vulnerability and license checks)
	h.logger.DebugContext(ctx, "Creating security check runs for pull request",
		"owner", owner,
		"repo", repo,
		"sha", sha,
		"pr_number", event.Number,
	)

	checkTypes := h.getSecurityCheckTypes(ctx, owner, repo, sha)
	return h.createSecurityCheckRuns(ctx, checkTypes, owner, repo, sha, event.Number)
}

// handleCheckRunEvent processes check run events.
// Used for handling rerequested check runs.
func (h *WebhookHandler) handleCheckRunEvent(ctx context.Context, event github.CheckRunPayload) error {
	tracer := otel.Tracer("polly/handlers")
	ctx, span := tracer.Start(ctx, "webhook.handle_check_run")
	defer span.End()

	span.SetAttributes(
		attribute.String("check_run.action", event.Action),
		attribute.Int64("check_run.id", event.CheckRun.ID),
	)

	h.logger.InfoContext(ctx,
		"Processing check run event",
		"action", event.Action,
		"check_run_id", event.CheckRun.ID,
	)

	if event.Action != "rerequested" {
		span.SetAttributes(attribute.String("result", "skipped"))
		h.logger.DebugContext(ctx, "Ignoring non-rerequested check run event")
		return nil
	}

	owner, repo, sha, checkRunID := getEventInfo(event)
	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.String("github.sha", sha),
		attribute.Int64("github.check_run_id", checkRunID),
	)

	h.logger.DebugContext(ctx, "Handling check run event",
		"owner", owner,
		"repo", repo,
		"sha", sha,
		"check_run_id", checkRunID,
	)

	// Determine the type of security check based on the check run name
	checkName := event.CheckRun.Name
	h.logger.InfoContext(ctx, "Check run rerun requested",
		"owner", owner,
		"repo", repo,
		"sha", sha,
		"check_run_id", checkRunID,
		"check_name", checkName,
	)

	// Store the PR number for this SHA if we can find it from the check run
	if len(event.CheckRun.PullRequests) > 0 {
		prNumber := int64(event.CheckRun.PullRequests[0].Number)
		err := h.stateService.StorePRNumber(ctx, owner, repo, sha, prNumber)
		if err != nil {
			h.logger.ErrorContext(ctx, "Failed to store PR number for SHA",
				"error", err,
				"sha", sha,
				"pr_number", prNumber,
			)
		}
		h.logger.DebugContext(ctx, "Stored PR context from check run",
			"sha", sha,
			"pr_number", prNumber,
		)
	}

	// Determine check type and restart the appropriate security check
	switch {
	case strings.Contains(checkName, "Vulnerability"):
		h.logger.InfoContext(ctx, "Restarting vulnerability check",
			"check_run_id", checkRunID,
			"sha", sha,
		)
		// Store the check run ID for this SHA
		if err := h.storeCheckRunIDWithError(ctx, owner, repo, sha, checkRunID, "vulnerability", h.stateService.StoreVulnerabilityCheckRunID); err != nil {
			return err
		}

		// Start the vulnerability check and process artifacts if available
		return h.restartVulnerabilityCheck(ctx, owner, repo, sha, checkRunID)

	case strings.Contains(checkName, "License"):
		h.logger.InfoContext(ctx, "Restarting license check",
			"check_run_id", checkRunID,
			"sha", sha,
		)
		// Store the check run ID for this SHA
		if err := h.storeCheckRunIDWithError(ctx, owner, repo, sha, checkRunID, "license", h.stateService.StoreLicenseCheckRunID); err != nil {
			return err
		}

		// Start the license check and process artifacts if available
		return h.restartLicenseCheck(ctx, owner, repo, sha, checkRunID)

	default:
		h.logger.DebugContext(ctx, "Unknown check type for rerun - skipping",
			"check_name", checkName,
			"check_run_id", checkRunID,
		)
		return nil
	}
}

// handleWorkflowRunEvent processes workflow run events.
// This is a placeholder for future functionality, currently it does nothing.
func (h *WebhookHandler) handleWorkflowRunEvent(ctx context.Context, event github.WorkflowRunPayload) error {
	tracer := otel.Tracer("polly/handlers")
	ctx, span := tracer.Start(ctx, "webhook.handle_workflow_run")
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
func (h *WebhookHandler) handleWorkflowStarted(ctx context.Context, event github.WorkflowRunPayload, owner, repo, sha string, workflowRunID int64) error {
	h.logger.InfoContext(ctx, "Workflow started - creating pending security checks",
		"owner", owner,
		"repo", repo,
		"workflow_name", event.Workflow.Name,
		"workflow_run_id", workflowRunID,
	)

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

	// Get security check types and create them concurrently
	checkTypes := h.getSecurityCheckTypes(ctx, owner, repo, sha)
	return h.createSecurityCheckRuns(ctx, checkTypes, owner, repo, sha, prNumber)
}

// handleWorkflowCompleted processes security artifacts when a workflow completes
func (h *WebhookHandler) handleWorkflowCompleted(ctx context.Context, event github.WorkflowRunPayload, owner, repo, sha string, workflowRunID int64) error {
	// Only process successful workflows
	if event.WorkflowRun.Conclusion != "success" {
		h.logger.DebugContext(ctx, "Handling workflow run event with non-success conclusion as a failed workflow",
			"conclusion", event.WorkflowRun.Conclusion,
		)

		// If workflow failed, we should complete any pending security checks as "neutral"
		return h.completeSecurityChecksAsNeutral(ctx, owner, repo, sha)
	}

	if event.WorkflowRun.ArtifactsURL == "" {
		h.logger.DebugContext(ctx, "Ignoring workflow run event with no artifacts URL",
			"artifacts_url", event.WorkflowRun.ArtifactsURL,
		)
		return h.completeSecurityChecksAsNeutral(ctx, owner, repo, sha)
	}

	// Store the workflow run ID for this SHA to enable check reruns
	if err := h.stateService.StoreWorkflowRunID(ctx, owner, repo, sha, workflowRunID); err != nil {
		h.logger.ErrorContext(ctx, "Failed to store workflow run ID for SHA",
			"error", err,
			"sha", sha,
			"workflow_run_id", workflowRunID,
		)
	}

	h.logger.DebugContext(ctx, "Stored workflow run ID for SHA",
		"sha", sha,
		"workflow_run_id", workflowRunID,
	)

	h.logger.InfoContext(ctx, "Processing workflow security artifacts",
		"owner", owner,
		"repo", repo,
		"workflow_name", event.Workflow.Name,
		"workflow_run_id", workflowRunID,
	)

	// Process security artifacts
	vulnPayloads, sbomPayloads, err := h.securityService.ProcessWorkflowSecurityArtifacts(ctx, owner, repo, sha, workflowRunID)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to process workflow security artifacts",
			"error", err,
			"owner", owner,
			"repo", repo,
			"workflow_run_id", workflowRunID,
		)
		return fmt.Errorf("failed to process security artifacts: %w", err)
	}

	if len(vulnPayloads) == 0 && len(sbomPayloads) == 0 {
		h.logger.InfoContext(ctx, "No security artifacts found for workflow run",
			"owner", owner,
			"repo", repo,
			"workflow_run_id", workflowRunID,
		)

		// Complete any pending security checks as "neutral" (no security artifacts to evaluate)
		return h.completeSecurityChecksAsNeutral(ctx, owner, repo, sha)
	}

	// Get PR number from stored context
	// h.prContextMutex.RLock()
	// prNumber, exists := h.prContextStore[sha]
	// h.prContextMutex.RUnlock()

	prNumber, exists, err := h.stateService.GetPRNumber(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to get PR number for SHA",
			"error", err,
			"sha", sha,
		)
		return err
	}

	if !exists {
		h.logger.DebugContext(ctx, "No PR context found for SHA",
			"sha", sha,
		)
		return nil
	}

	// Find the existing security check runs for this SHA
	vulnCheckRunID, err := h.findVulnerabilityCheckRun(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to find vulnerability check run",
			"error", err,
			"sha", sha,
		)
		return err
	}

	licenseCheckRunID, err := h.findLicenseCheckRun(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to find license check run",
			"error", err,
			"sha", sha,
		)
		return err
	}

	if vulnCheckRunID == 0 && licenseCheckRunID == 0 {
		h.logger.WarnContext(ctx, "No security check runs found for SHA",
			"sha", sha,
		)
		return nil
	}

	// Process and evaluate security payloads
	return h.processSecurityPayloads(ctx, vulnPayloads, sbomPayloads, owner, repo, sha, prNumber, vulnCheckRunID, licenseCheckRunID)
}

// completeVulnerabilityCheckAsNeutral completes vulnerability checks as neutral when no artifacts are found
func (h *WebhookHandler) completeVulnerabilityCheckAsNeutral(ctx context.Context, owner, repo, sha string) error {
	checkRunID, err := h.findVulnerabilityCheckRun(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to find security check run",
			"error", err,
			"sha", sha,
		)
		return nil // Don't fail if we can't find the check run
	}

	if checkRunID == 0 {
		return nil // No security check run to complete
	}

	return h.checkService.CompleteVulnerabilityCheckWithNoArtifacts(ctx, owner, repo, checkRunID)
}

// completeSecurityChecksAsNeutral completes both vulnerability and license checks as neutral when no artifacts are found
func (h *WebhookHandler) completeSecurityChecksAsNeutral(ctx context.Context, owner, repo, sha string) error {
	// Define completion functions
	completionFuncs := []func() error{
		func() error { return h.completeVulnerabilityCheckAsNeutral(ctx, owner, repo, sha) },
		func() error { return h.completeLicenseCheckAsNeutral(ctx, owner, repo, sha) },
	}

	// Complete security checks as neutral concurrently using runConcurrent
	tasks := make([]func() error, len(completionFuncs))
	for i, fn := range completionFuncs {
		fn := fn
		tasks[i] = func() error {
			if err := fn(); err != nil {
				h.logger.ErrorContext(ctx, "Failed to complete security check as neutral", "error", err)
			}
			return nil
		}
	}
	_ = utils.ExecuteConcurrently(tasks)
	return nil
}

// completeLicenseCheckAsNeutral completes license checks as neutral when no artifacts are found
func (h *WebhookHandler) completeLicenseCheckAsNeutral(ctx context.Context, owner, repo, sha string) error {
	checkRunID, err := h.findLicenseCheckRun(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to find license check run",
			"error", err,
			"sha", sha,
		)
		return nil // Don't fail if we can't find the check run
	}

	if checkRunID == 0 {
		return nil // No license check run to complete
	}

	return h.checkService.CompleteLicenseCheckWithNoArtifacts(ctx, owner, repo, checkRunID)
}

// findVulnerabilityCheckRun finds an existing vulnerability check run for the given SHA
func (h *WebhookHandler) findVulnerabilityCheckRun(ctx context.Context, owner, repo, sha string) (int64, error) {
	checkRunID, exists, err := h.stateService.GetVulnerabilityCheckRunID(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to get vulnerability check run ID",
			"error", err,
			"sha", sha,
		)
		return 0, err
	}

	if !exists {
		h.logger.DebugContext(ctx, "No security check run found for SHA",
			"sha", sha,
		)
		return 0, nil
	}

	h.logger.DebugContext(ctx, "Found security check run for SHA",
		"sha", sha,
		"check_run_id", checkRunID,
	)

	return checkRunID, nil
}

// findLicenseCheckRun finds an existing license check run for the given SHA
func (h *WebhookHandler) findLicenseCheckRun(ctx context.Context, owner, repo, sha string) (int64, error) {
	checkRunID, exists, err := h.stateService.GetLicenseCheckRunID(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to get license check run ID",
			"error", err,
			"sha", sha,
		)
		return 0, err
	}

	if !exists {
		h.logger.DebugContext(ctx, "No license check run found for SHA",
			"sha", sha,
		)
		return 0, nil
	}

	h.logger.DebugContext(ctx, "Found license check run for SHA",
		"sha", sha,
		"check_run_id", checkRunID,
	)

	return checkRunID, nil
}

// restartVulnerabilityCheck restarts a vulnerability check by processing stored artifacts
func (h *WebhookHandler) restartVulnerabilityCheck(ctx context.Context, owner, repo, sha string, checkRunID int64) error {
	// Start the check run in progress state
	if err := h.checkService.StartVulnerabilityCheck(ctx, owner, repo, checkRunID); err != nil {
		return fmt.Errorf("failed to start vulnerability check: %w", err)
	}

	// Look for stored artifacts for this SHA
	workflowRunID, exists, err := h.stateService.GetWorkflowRunID(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to get workflow run ID for SHA",
			"error", err,
			"sha", sha,
		)
		return err
	}

	if !exists {
		h.logger.DebugContext(ctx, "No stored artifacts found for SHA - completing as neutral",
			"sha", sha,
		)
		return h.checkService.CompleteVulnerabilityCheckWithNoArtifacts(ctx, owner, repo, checkRunID)
	}

	h.logger.InfoContext(ctx, "Processing stored artifacts for vulnerability check rerun",
		"sha", sha,
		"workflow_run_id", workflowRunID,
		"check_run_id", checkRunID,
	)

	// Process the security artifacts from the stored workflow run
	vulnPayloads, _, err := h.securityService.ProcessWorkflowSecurityArtifacts(ctx, owner, repo, sha, workflowRunID)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to process stored security artifacts",
			"error", err,
			"workflow_run_id", workflowRunID,
		)
		return h.checkService.CompleteVulnerabilityCheckWithNoArtifacts(ctx, owner, repo, checkRunID)
	}

	if len(vulnPayloads) == 0 {
		h.logger.InfoContext(ctx, "No vulnerability artifacts found in stored workflow run",
			"workflow_run_id", workflowRunID,
		)
		return h.checkService.CompleteVulnerabilityCheckWithNoArtifacts(ctx, owner, repo, checkRunID)
	}

	// Get PR number for comments
	prNumber, exists, err := h.stateService.GetPRNumber(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to get PR number for SHA",
			"error", err,
			"sha", sha,
		)
		return err
	}

	if !exists {
		h.logger.DebugContext(ctx, "No PR context found for SHA",
			"sha", sha,
		)
		prNumber = 0 // Process without PR comments
	}

	// Process vulnerability payloads
	return h.processVulnerabilityChecks(ctx, vulnPayloads, owner, repo, sha, prNumber, checkRunID)
}

// restartLicenseCheck restarts a license check by processing stored artifacts
func (h *WebhookHandler) restartLicenseCheck(ctx context.Context, owner, repo, sha string, checkRunID int64) error {
	// Start the check run in progress state
	if err := h.checkService.StartLicenseCheck(ctx, owner, repo, checkRunID); err != nil {
		return fmt.Errorf("failed to start license check: %w", err)
	}

	// Look for stored artifacts for this SHA
	// workflowRunID, exists := h.getWorkflowRunIDForSHA(sha)
	workflowRunID, exists, err := h.stateService.GetWorkflowRunID(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to get workflow run ID for SHA",
			"error", err,
			"sha", sha,
		)
		return err
	}

	if !exists {
		h.logger.DebugContext(ctx, "No stored artifacts found for SHA - completing as neutral",
			"sha", sha,
		)
		return h.checkService.CompleteLicenseCheckWithNoArtifacts(ctx, owner, repo, checkRunID)
	}

	h.logger.InfoContext(ctx, "Processing stored artifacts for license check rerun",
		"sha", sha,
		"workflow_run_id", workflowRunID,
		"check_run_id", checkRunID,
	)

	// Process the security artifacts from the stored workflow run
	_, sbomPayloads, err := h.securityService.ProcessWorkflowSecurityArtifacts(ctx, owner, repo, sha, workflowRunID)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to process stored security artifacts",
			"error", err,
			"workflow_run_id", workflowRunID,
		)
		return h.checkService.CompleteLicenseCheckWithNoArtifacts(ctx, owner, repo, checkRunID)
	}

	if len(sbomPayloads) == 0 {
		h.logger.InfoContext(ctx, "No SBOM artifacts found in stored workflow run",
			"workflow_run_id", workflowRunID,
		)
		return h.checkService.CompleteLicenseCheckWithNoArtifacts(ctx, owner, repo, checkRunID)
	}

	// Get PR number for comments
	// prNumber, exists := h.getPRNumberForSHA(sha)
	prNumber, exists, err := h.stateService.GetPRNumber(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to get PR number for SHA",
			"error", err,
			"sha", sha,
		)
		return err
	}

	if !exists {
		h.logger.DebugContext(ctx, "No PR context found for SHA",
			"sha", sha,
		)
		prNumber = 0 // Process without PR comments
	}

	// Process SBOM payloads
	return h.processLicenseChecks(ctx, sbomPayloads, owner, repo, sha, prNumber, checkRunID)
}

// processVulnerabilityChecks processes vulnerability payloads, posts comments for violations, and completes the check run.
func (h *WebhookHandler) processVulnerabilityChecks(ctx context.Context, payloads []*services.VulnerabilityPayload, owner, repo, sha string, prNumber int64, checkRunID int64) error {
	allPassed := true
	var failureDetails []string
	var allNonCompliantVulns []services.VulnerabilityPolicyVuln

	for _, payload := range payloads {
		h.logger.DebugContext(ctx, "Processing vulnerability payload",
			"owner", owner,
			"repo", repo,
			"sha", sha,
			"payload_vulnerability_summary", payload.Summary,
		)

		policyResult, err := h.policyService.CheckVulnerabilityPolicy(ctx, payload)
		if err != nil {
			h.logger.ErrorContext(ctx, "Failed to evaluate vulnerability policy", "error", err)
			if payload.Summary.Critical > 0 || payload.Summary.High > 0 {
				allPassed = false
				failureDetails = append(failureDetails,
					fmt.Sprintf("Found %d critical and %d high severity vulnerabilities (policy evaluation failed)",
						payload.Summary.Critical, payload.Summary.High))
			}
			continue
		}

		if !policyResult.Compliant {
			allPassed = false
			failureDetails = append(failureDetails,
				fmt.Sprintf("Vulnerability policy violation: %d non-compliant vulnerabilities out of %d total",
					policyResult.NonCompliantCount, policyResult.TotalVulnerabilities))
			allNonCompliantVulns = append(allNonCompliantVulns, policyResult.NonCompliantVulnerabilities...)
		}
	}

	if len(allNonCompliantVulns) > 0 {
		vulnComment := buildVulnerabilityViolationComment(allNonCompliantVulns)
		if err := h.commentService.WriteComment(ctx, owner, repo, int(prNumber), vulnComment); err != nil {
			h.logger.ErrorContext(ctx, "Failed to post vulnerability comment", "error", err)
		}
	}

	conclusion := services.ConclusionSuccess
	result := services.CheckRunResult{
		Title:   "Vulnerability Check - Passed",
		Summary: fmt.Sprintf("Processed %d vulnerability findings", len(payloads)),
		Text:    "All vulnerability policies passed.",
	}

	if !allPassed {
		conclusion = services.ConclusionFailure
		result = services.CheckRunResult{
			Title:   "Vulnerability Check - Failed",
			Summary: fmt.Sprintf("Found vulnerability violations in %d scan results", len(failureDetails)),
			Text:    fmt.Sprintf("Vulnerability violations found:\n\n%s", strings.Join(failureDetails, "\n")),
		}
	}

	return h.checkService.CompleteVulnerabilityCheck(ctx, owner, repo, checkRunID, conclusion, result)
}

// processLicenseChecks processes SBOM payloads, posts comments for violations, and completes the check run.
func (h *WebhookHandler) processLicenseChecks(ctx context.Context, payloads []*services.SBOMPayload, owner, repo, sha string, prNumber int64, checkRunID int64) error {
	allPassed := true
	var failureDetails []string
	var allNonCompliantComponents []services.SBOMPolicyComponent
	var allConditionalComponents []services.SBOMPolicyComponent

	// Iterate through SBOM payloads and evaluate license policies
	for _, payload := range payloads {
		h.logger.DebugContext(ctx, "Processing SBOM payload",
			"owner", owner,
			"repo", repo,
			"sha", sha,
			"package_count", payload.Summary.TotalPackages,
		)

		policyResult, err := h.policyService.CheckSBOMPolicy(ctx, payload)
		if err != nil {
			h.logger.ErrorContext(ctx, "Failed to evaluate SBOM policy", "error", err)
			if payload.Summary.PackagesWithoutLicense > 0 {
				allPassed = false
				failureDetails = append(failureDetails,
					fmt.Sprintf("Found %d packages without license (policy evaluation failed)",
						payload.Summary.PackagesWithoutLicense))
			}
			continue
		}

		if !policyResult.Compliant {
			allPassed = false
			failureDetails = append(failureDetails,
				fmt.Sprintf("SBOM policy violation: %d non-compliant components out of %d total",
					policyResult.TotalComponents-policyResult.CompliantComponents, policyResult.TotalComponents))
			allNonCompliantComponents = append(allNonCompliantComponents, policyResult.NonCompliantComponents...)
		}

		allConditionalComponents = append(allConditionalComponents, policyResult.ConditionalComponents...)
	}

	// Post a combined comment if there are any violations or conditional licenses
	if len(allNonCompliantComponents) > 0 || len(allConditionalComponents) > 0 {
		licenseComment := buildLicenseComment(allNonCompliantComponents, allConditionalComponents)
		if err := h.commentService.WriteComment(ctx, owner, repo, int(prNumber), licenseComment); err != nil {
			h.logger.ErrorContext(ctx, "Failed to post license comment", "error", err)
		}
	}

	conclusion := services.ConclusionSuccess
	result := services.CheckRunResult{
		Title:   "License Check - Passed",
		Summary: fmt.Sprintf("Processed %d SBOM findings", len(payloads)),
		Text:    "All license policies passed.",
	}

	if !allPassed {
		conclusion = services.ConclusionFailure
		result = services.CheckRunResult{
			Title:   "License Check - Failed",
			Summary: fmt.Sprintf("Found license violations in %d scan results", len(failureDetails)),
			Text:    fmt.Sprintf("License violations found:\n\n%s", strings.Join(failureDetails, "\n")),
		}
	}

	return h.checkService.CompleteLicenseCheck(ctx, owner, repo, checkRunID, conclusion, result)
}

// processSecurityPayloads evaluates vulnerability and SBOM payloads separately and completes their respective check runs
func (h *WebhookHandler) processSecurityPayloads(ctx context.Context, vulnPayloads []*services.VulnerabilityPayload, sbomPayloads []*services.SBOMPayload, owner, repo, sha string, prNumber int64, vulnCheckRunID, licenseCheckRunID int64) error {
	// Define processing functions
	type processingFunc struct {
		name string
		fn   func() error
	}

	var processingFuncs []processingFunc

	// Add vulnerability processing if we have a check run ID
	if vulnCheckRunID != 0 {
		processingFuncs = append(processingFuncs, processingFunc{
			name: "vulnerability",
			fn: func() error {
				return h.processVulnerabilityChecks(ctx, vulnPayloads, owner, repo, sha, prNumber, vulnCheckRunID)
			},
		})
	}

	// Add SBOM processing if we have a check run ID
	if licenseCheckRunID != 0 {
		processingFuncs = append(processingFuncs, processingFunc{
			name: "license",
			fn: func() error {
				return h.processLicenseChecks(ctx, sbomPayloads, owner, repo, sha, prNumber, licenseCheckRunID)
			},
		})
	}

	if len(processingFuncs) == 0 {
		h.logger.DebugContext(ctx, "No security checks to process")
		return nil
	}

	// Process security payloads concurrently using runConcurrent
	tasks := make([]func() error, len(processingFuncs))
	for i, pf := range processingFuncs {
		pf := pf
		tasks[i] = func() error {
			h.logger.DebugContext(ctx, "Processing security payloads", "type", pf.name)
			if err := pf.fn(); err != nil {
				h.logger.ErrorContext(ctx, "Error processing security payload", "type", pf.name, "error", err)
				return err
			}
			return nil
		}
	}
	_ = utils.ExecuteConcurrently(tasks)
	return nil
}
