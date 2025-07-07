package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
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
	prContextStore map[string]int64 // sha -> pr_number
	prContextMutex sync.RWMutex     // RWMutex to protect the context store
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
		logger:          logger,
		hook:            hook,
		commentService:  commentService,
		checkService:    checkService,
		policyService:   policyService,
		securityService: securityService,
		prContextStore:  make(map[string]int64), // Initialize the PR context store
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

	// only handle "completed" workflows
	if event.Action != "completed" {
		span.SetAttributes(attribute.String("result", "skipped"))
		return nil
	}

	// Only process successful workflows
	if event.WorkflowRun.Conclusion != "success" {
		span.SetAttributes(attribute.String("result", "skipped"))
		h.logger.DebugContext(ctx, "Ignoring workflow run event with non-success conclusion",
			"conclusion", event.WorkflowRun.Conclusion,
		)
		return nil
	}

	if event.WorkflowRun.ArtifactsURL == "" {
		h.logger.DebugContext(ctx, "Ignoring workflow run event with no artifacts URL",
			"artifacts_url", event.WorkflowRun.ArtifactsURL,
		)
		span.SetAttributes(attribute.String("result", "skipped_no_artifacts"))
		return nil
	}

	owner, repo, sha, workflowRunID := getEventInfo(event)
	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.String("github.sha", sha),
		attribute.Int64("github.workflow_run_id", workflowRunID),
	)

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
		span.SetAttributes(attribute.String("result", "error"))
		return fmt.Errorf("failed to process security artifacts: %w", err)
	}

	if len(payloads) == 0 {
		h.logger.InfoContext(ctx, "No security artifacts found for workflow run",
			"owner", owner,
			"repo", repo,
			"workflow_run_id", workflowRunID,
		)
		span.SetAttributes(attribute.String("result", "success"))
		return nil
	}

	// Get PR number from stored context
	h.prContextMutex.RLock()
	prNumber, exists := h.prContextStore[sha]
	h.prContextMutex.RUnlock()

	if !exists {
		h.logger.DebugContext(ctx, "No PR context found for SHA",
			"sha", sha,
		)
		span.SetAttributes(attribute.String("result", "skipped_no_pr_context"))
		return nil
	}

	h.logger.InfoContext(ctx, "Found PR context for security check",
		"sha", sha,
		"pr_number", prNumber,
	)

	// Create security check run
	checkRun, err := h.checkService.CreateSecurityCheck(ctx, owner, repo, sha)
	if err != nil {
		h.logger.ErrorContext(ctx, "Failed to create security check run",
			"error", err,
			"owner", owner,
			"repo", repo,
			"sha", sha,
		)
		return err
	}

	// Start the security check
	if err := h.checkService.StartSecurityCheck(ctx, owner, repo, checkRun.GetID()); err != nil {
		h.logger.ErrorContext(ctx, "Failed to start security check",
			"error", err,
			"check_run_id", checkRun.GetID(),
		)
		return err
	}

	// Process and evaluate security payloads
	return h.processSecurityPayloads(ctx, payloads, owner, repo, sha, prNumber, checkRun.GetID())

	// // Process each payload
	// for _, payload := range payloads {
	// 	h.logger.DebugContext(ctx, "Processing security payload",
	// 		"owner", owner,
	// 		"repo", repo,
	// 		"workflow_run_id", workflowRunID,
	// 		"payload", payload,
	// 	)
	// TODO: Here you would typically send the payload to OPA or kick off a check run via policyService
	// }

	// span.SetAttributes(attribute.String("result", "success"))
	// h.logger.InfoContext(ctx, "Successfully processed workflow security artifacts",
	// 	"owner", owner,
	// 	"repo", repo,
	// 	"workflow_run_id", workflowRunID,
	// )

	// return nil
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
