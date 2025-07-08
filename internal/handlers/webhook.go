package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/go-playground/webhooks/v6/github"
	gogithub "github.com/google/go-github/v72/github"
	"github.com/terrpan/polly/internal/services"
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

	// In-memory cache for PR context store
	prContextStore          map[string]int64 // sha -> pr_number
	vulnerabilityCheckStore map[string]int64 // sha -> vulnerability_check_id
	prContextMutex          sync.RWMutex     // RWMutex to protect the context store
	vulnerabilityCheckMutex sync.RWMutex     // RWMutex to protect the vulnerability check store

}

// Setups a new WebhookHandler with the provided logger and initializes the GitHub webhook.
// It currently does not support secret verification, but this can be added later.
// It returns an error if the webhook cannot be initialized.
func NewWebhookHandler(logger *slog.Logger, commentService *services.CommentService, checkService *services.CheckService, policyService *services.PolicyService, securityService *services.SecurityService) (*WebhookHandler, error) {
	// TODO: Add support for secret verification
	hook, err := github.New()

	if err != nil {
		return nil, err
	}
	return &WebhookHandler{
		logger:                  logger,
		hook:                    hook,
		commentService:          commentService,
		checkService:            checkService,
		policyService:           policyService,
		securityService:         securityService,
		prContextStore:          make(map[string]int64), // Initialize the PR context store
		vulnerabilityCheckStore: make(map[string]int64), // Initialize the vulnerability check store

	}, nil
}

// HandleWebhook processes incoming GitHub webhook events.
func (h *WebhookHandler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tracer := otel.Tracer("polly/handlers")
	ctx, span := tracer.Start(ctx, "webhook.handle")
	defer span.End()

	payload, err := h.hook.Parse(r, github.PullRequestEvent, github.CheckRunEvent, github.WorkflowRunEvent)
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

	default:
		span.SetAttributes(attribute.String("event.type", eventType))
		h.logger.Warn("Unsupported event type", "event_type", eventType)
		http.Error(w, "Unsupported event type", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Webhook received successfully"))
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

	if event.Action != "opened" && event.Action != "reopened" {
		h.logger.DebugContext(ctx, "Ignoring non-opened/reopened pull request event",
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

	h.prContextMutex.Lock()
	h.prContextStore[sha] = event.Number // Store the PR number in the context store
	h.prContextMutex.Unlock()

	// 1. Create a check run for the pull request
	checkRun, err := h.createCheckRun(ctx, event)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to create check run",
			"error", err,
			"owner", owner,
			"repo", repo,
			"sha", sha,
		)
		return err
	}

	// 2. Update status of the check run to "in_progress" and trigger OPA policy validation
	h.logger.DebugContext(ctx, "Updating check run status to in_progress",
		"owner", owner,
		"repo", repo,
		"sha", sha,
	)
	if err := h.checkService.StartPolicyCheck(
		ctx,
		owner,
		repo,
		checkRun.GetID(),
	); err != nil {
		h.logger.ErrorContext(ctx, "Failed to start policy check",
			"error", err,
			"owner", owner,
			"repo", repo,
			"sha", sha,
		)
		return err
	}

	// 3. Perform OPA policy validation
	h.logger.DebugContext(ctx, "Performing OPA policy validation",
		"owner", owner,
		"repo", repo,
		"sha", sha,
	)

	return h.validateAndCompletePolicyCheck(ctx, owner, repo, sha, checkRun.GetID())
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

	// 1. Update status of the check run to "in_progress"
	if err := h.checkService.StartPolicyCheck(
		ctx,
		owner,
		repo,
		checkRunID,
	); err != nil {
		h.logger.ErrorContext(ctx, "Failed to start policy check",
			"error", err,
			"owner", owner,
			"repo", repo,
			"sha", sha,
			"check_run_id", checkRunID,
		)
		return err
	}

	// 2. Validate policies and complete check run
	return h.validateAndCompletePolicyCheck(ctx, owner, repo, sha, checkRunID)
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

// handleWorkflowStarted creates a pending security check when a workflow starts
func (h *WebhookHandler) handleWorkflowStarted(ctx context.Context, event github.WorkflowRunPayload, owner, repo, sha string, workflowRunID int64) error {
	h.logger.InfoContext(ctx, "Workflow started - creating pending security check",
		"owner", owner,
		"repo", repo,
		"workflow_name", event.Workflow.Name,
		"workflow_run_id", workflowRunID,
	)

	// Get PR number from stored context
	h.prContextMutex.RLock()
	prNumber, exists := h.prContextStore[sha]
	h.prContextMutex.RUnlock()

	if !exists {
		h.logger.DebugContext(ctx, "No PR context found for SHA - skipping security check creation",
			"sha", sha,
		)
		return nil
	}

	h.logger.InfoContext(ctx, "Found PR context for security check",
		"sha", sha,
		"pr_number", prNumber,
	)

	// Create security check run in pending state
	checkRun, err := h.checkService.CreateVulnerabilityCheck(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to create security check run",
			"error", err,
			"owner", owner,
			"repo", repo,
			"sha", sha,
		)
		return err
	}

	// Mark it as pending (waiting for workflow to complete)
	if err := h.checkService.StartVulnerabilityCheck(ctx, owner, repo, checkRun.GetID()); err != nil {
		h.logger.ErrorContext(ctx, "Failed to start vulnerability check",
			"error", err,
			"check_run_id", checkRun.GetID(),
		)
		return err
	}

	// Store the security check run ID for later retrieval
	h.vulnerabilityCheckMutex.Lock()
	h.vulnerabilityCheckStore[sha] = checkRun.GetID()
	h.vulnerabilityCheckMutex.Unlock()

	h.logger.InfoContext(ctx, "Created pending vulnerability check run",
		"check_run_id", checkRun.GetID(),
		"pr_number", prNumber,
	)

	return nil
}

// handleWorkflowCompleted processes security artifacts when a workflow completes
func (h *WebhookHandler) handleWorkflowCompleted(ctx context.Context, event github.WorkflowRunPayload, owner, repo, sha string, workflowRunID int64) error {
	// Only process successful workflows
	if event.WorkflowRun.Conclusion != "success" {
		h.logger.DebugContext(ctx, "Handling workflow run event with non-success conclusion as a failed workflow",
			"conclusion", event.WorkflowRun.Conclusion,
		)

		// If workflow failed, we should complete any pending vulnerability checks as "neutral"
		return h.completeVulnerabilityCheckAsNeutral(ctx, owner, repo, sha)
	}

	if event.WorkflowRun.ArtifactsURL == "" {
		h.logger.DebugContext(ctx, "Ignoring workflow run event with no artifacts URL",
			"artifacts_url", event.WorkflowRun.ArtifactsURL,
		)
		return nil
	}

	h.logger.InfoContext(ctx, "Processing workflow security artifacts",
		"owner", owner,
		"repo", repo,
		"workflow_name", event.Workflow.Name,
		"workflow_run_id", workflowRunID,
	)

	// Process security artifacts
	payloads, err := h.securityService.ProcessWorkflowSecurityArtifacts(ctx, owner, repo, sha, workflowRunID)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to process workflow security artifacts",
			"error", err,
			"owner", owner,
			"repo", repo,
			"workflow_run_id", workflowRunID,
		)
		return fmt.Errorf("failed to process security artifacts: %w", err)
	}

	if len(payloads) == 0 {
		h.logger.InfoContext(ctx, "No security artifacts found for workflow run",
			"owner", owner,
			"repo", repo,
			"workflow_run_id", workflowRunID,
		)

		// Complete any pending security checks as "neutral" (no security artifacts to evaluate)
		return h.completeVulnerabilityCheckAsNeutral(ctx, owner, repo, sha)
	}

	// Get PR number from stored context
	h.prContextMutex.RLock()
	prNumber, exists := h.prContextStore[sha]
	h.prContextMutex.RUnlock()

	if !exists {
		h.logger.DebugContext(ctx, "No PR context found for SHA",
			"sha", sha,
		)
		return nil
	}

	// Find the existing security check run for this SHA
	checkRunID, err := h.findVulnerabilityCheckRun(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to find security check run",
			"error", err,
			"sha", sha,
		)
		return err
	}

	if checkRunID == 0 {
		h.logger.WarnContext(ctx, "No security check run found for SHA",
			"sha", sha,
		)
		return nil
	}

	// Process and evaluate vulnerability payloads
	return h.processVulnerabilityPayloads(ctx, payloads, owner, repo, sha, prNumber, checkRunID)
}

// handleFailedWorkflow completes security checks as neutral when workflows fail
// func (h *WebhookHandler) handleFailedWorkflow(ctx context.Context, owner, repo, sha string, workflowRunID int64) error {
// 	checkRunID, err := h.findVulnerabilityCheckRun(ctx, owner, repo, sha)
// 	if err != nil {
// 		h.logger.ErrorContext(ctx, "Failed to find security check run for failed workflow",
// 			"error", err,
// 			"sha", sha,
// 		)
// 		return nil // Don't fail if we can't find the check run
// 	}

// 	if checkRunID == 0 {
// 		return nil // No security check run to complete
// 	}

// 	result := services.CheckRunResult{
// 		Title:   "Vulnerability Check - Skipped",
// 		Summary: "Workflow failed - vulnerability scan not completed",
// 		Text:    "The workflow failed before vulnerability artifacts could be processed.",
// 	}

// 	return h.checkService.CompleteVulnerabilityCheck(ctx, owner, repo, checkRunID, services.ConclusionNeutral, result)
// }

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

// findVulnerabilityCheckRun finds an existing vulnerability check run for the given SHA
func (h *WebhookHandler) findVulnerabilityCheckRun(ctx context.Context, owner, repo, sha string) (int64, error) {
	h.vulnerabilityCheckMutex.RLock()
	checkRunID, exists := h.vulnerabilityCheckStore[sha]
	h.vulnerabilityCheckMutex.RUnlock()

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

// createCheckRun is a helper function to create a check run for the pull request.
func (h *WebhookHandler) createCheckRun(ctx context.Context, event github.PullRequestPayload) (*gogithub.CheckRun, error) {
	h.logger.DebugContext(ctx, "Creating check run for pull request",
		"owner", event.Repository.Owner.Login,
		"repo", event.Repository.Name,
		"sha", event.PullRequest.Head.Sha,
	)

	checkRun, err := h.checkService.CreatePolicyCheck(
		ctx,
		event.Repository.Owner.Login,
		event.Repository.Name,
		event.PullRequest.Head.Sha,
	)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to create policy check",
			"error", err,
			"owner", event.Repository.Owner.Login,
			"repo", event.Repository.Name,
			"sha", event.PullRequest.Head.Sha,
		)
		return nil, err
	}

	return checkRun, nil
}

// buildCheckrunResult builds the check run result based on policy validation outome.
func (h *WebhookHandler) buildCheckRunResult(policyPassed bool, policyError error) (services.CheckRunConclusion, services.CheckRunResult) {
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
			Text:    "The hello policy validation succeeded.",
		}
	}
	return services.ConclusionFailure, services.CheckRunResult{
		Title:   "OPA Policy Check - Failed",
		Summary: "Policy validation failed",
		Text:    "The hello policy validation failed.",
	}
}

// validateAndCompletePolicyCheck performs policy validation and completes the check run
func (h *WebhookHandler) validateAndCompletePolicyCheck(ctx context.Context, owner, repo, sha string, checkRunID int64) error {
	h.logger.DebugContext(ctx, "Validating policies and completing check run",
		"owner", owner,
		"repo", repo,
		"sha", sha,
		"check_run_id", checkRunID,
	)

	helloInput := services.HelloInput{Message: "hello"}
	policyPassed, err := h.policyService.CheckHelloPolicy(ctx, helloInput)
	if err != nil {
		h.logger.ErrorContext(ctx, "Policy validation failed", "error", err)
		return h.completePolicyCheckWithResult(ctx, owner, repo, checkRunID, false, err)
	}

	return h.completePolicyCheckWithResult(ctx, owner, repo, checkRunID, policyPassed, nil)
}

// completePolicyCheckWithResult completes the check run with the given policy result.
func (h *WebhookHandler) completePolicyCheckWithResult(ctx context.Context, owner, repo string, checkRunID int64, policyPassed bool, policyError error) error {
	conclusion, result := h.buildCheckRunResult(policyPassed, policyError)
	if err := h.checkService.CompletePolicyCheck(
		ctx,
		owner,
		repo,
		checkRunID,
		conclusion,
		result,
	); err != nil {
		h.logger.ErrorContext(ctx, "Failed to complete policy check",
			"error", err,
			"owner", owner,
			"repo", repo,
			"check_run_id", checkRunID,
		)
		return err
	}
	h.logger.InfoContext(ctx, "Policy check completed",
		"owner", owner,
		"repo", repo,
		"check_run_id", checkRunID,
		"conclusion", conclusion,
		"result", result,
	)
	return nil
}

// processVulnerabilityPayloads evaluates vulnerability payloads and completes the check run
func (h *WebhookHandler) processVulnerabilityPayloads(ctx context.Context, payloads []*services.VulnerabilityPayload, owner, repo, sha string, prNumber int64, checkRunID int64) error {
	allPassed := true
	var failureDetails []string
	for _, payload := range payloads {
		h.logger.DebugContext(ctx, "Processing vulnerability payload",
			"owner", owner,
			"repo", repo,
			"sha", sha,
			"payload_summary", payload.Summary,
		)

		// TODO: Replace with actual OPA evaluation
		// For now, fail if we have CRITICAL or HIGH severity vulnerabilities
		if payload.Summary.Critical > 0 || payload.Summary.High > 0 {
			allPassed = false
			failureDetails = append(failureDetails,
				fmt.Sprintf("Found %d critical and %d high severity vulnerabilities",
					payload.Summary.Critical, payload.Summary.High))
		}

		// Collect high/critical vulnerabilities for a single comment
		var vulnComments []string
		for _, vuln := range payload.Vulnerabilities {
			if vuln.Severity == "CRITICAL" || vuln.Severity == "HIGH" {
				comment := fmt.Sprintf("**Package:** `%s@%s`\n**Vulnerability:** %s\n**Severity:** %s\n**Description:** %s\n**File:** `%s`",
					vuln.Package.Name, vuln.Package.Version, vuln.ID, vuln.Severity, vuln.Description, vuln.Location.File)

				if vuln.FixedVersion != "" {
					comment += fmt.Sprintf("\n**Fixed Version:** %s", vuln.FixedVersion)
				}
				vulnComments = append(vulnComments, comment)
			}
		}

		// Post single comment with all vulnerabilities
		if len(vulnComments) > 0 {
			fullComment := fmt.Sprintf("🚨 **Vulnerability Alert - %d high/critical vulnerabilities found**\n\n<details>\n<summary>Click to view vulnerability details</summary>\n\n%s\n\n</details>",
				len(vulnComments), strings.Join(vulnComments, "\n\n---\n\n"))

			if err := h.commentService.WriteComment(ctx, owner, repo, int(prNumber), fullComment); err != nil {
				h.logger.ErrorContext(ctx, "Failed to post vulnerability comment", "error", err)
			}
		}
	}

	// Complete the vulnerability check run
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
