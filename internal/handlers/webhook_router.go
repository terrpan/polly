// Package handlers provides HTTP handlers for health checks and webhook processing.
// This file defines the WebhookRouter which routes GitHub webhook events to appropriate handlers.
package handlers

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-playground/webhooks/v6/github"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/terrpan/polly/internal/services"
)

// WebhookRouter handles incoming GitHub webhooks and routes them to appropriate handlers.
type WebhookRouter struct {
	logger             *slog.Logger
	hook               *github.Webhook
	tracingHelper      *TracingHelper
	pullRequestHandler *PullRequestHandler
	checkRunHandler    *CheckRunHandler
	workflowHandler    *WorkflowHandler
}

// NewWebhookRouter creates a new webhook router with the provided logger and initializes the GitHub webhook.
// It currently does not support secret verification, but this can be added later.
// It returns an error if the webhook cannot be initialized.
func NewWebhookRouter(logger *slog.Logger,
	commentService *services.CommentService,
	checkService *services.CheckService,
	policyService *services.PolicyService,
	policyCacheService *services.PolicyCacheService,
	securityService *services.SecurityService,
	stateService *services.StateService) (*WebhookRouter, error) {
	// TODO: Add support for secret verification
	hook, err := github.New()
	if err != nil {
		return nil, err
	}

	// Create the base handler with shared dependencies
	baseHandler := NewBaseWebhookHandler(
		logger,
		commentService,
		checkService,
		policyService,
		policyCacheService,
		securityService,
		stateService,
	)

	// Create specialized handlers
	pullRequestHandler := NewPullRequestHandler(baseHandler)
	checkRunHandler := NewCheckRunHandler(baseHandler)
	workflowHandler := NewWorkflowHandler(baseHandler)

	return &WebhookRouter{
		logger:             logger,
		hook:               hook,
		tracingHelper:      NewTracingHelper(),
		pullRequestHandler: pullRequestHandler,
		checkRunHandler:    checkRunHandler,
		workflowHandler:    workflowHandler,
	}, nil
}

// HandleWebhook processes incoming GitHub webhook events and routes them to the appropriate handler.
func (r *WebhookRouter) HandleWebhook(w http.ResponseWriter, req *http.Request) {
	ctx, span := r.tracingHelper.StartSpan(req.Context(), "webhook.handle")
	defer span.End()

	// Parse webhook
	payload, err := r.parseWebhook(req)
	if err != nil {
		r.handleWebhookError(w, span, "Failed to parse webhook", err, http.StatusBadRequest)
		return
	}

	// Route to appropriate handler
	if err := r.routeWebhookEvent(ctx, req, payload); err != nil {
		r.handleWebhookError(
			w,
			span,
			"Failed to process webhook event",
			err,
			http.StatusInternalServerError,
		)

		return
	}

	r.handleWebhookSuccess(w, span)
}

// parseWebhook parses the incoming webhook request
func (r *WebhookRouter) parseWebhook(req *http.Request) (interface{}, error) {
	return r.hook.Parse(req,
		github.PullRequestEvent,
		github.CheckRunEvent,
		github.WorkflowRunEvent,
		github.CheckSuiteEvent,
		github.WorkflowJobEvent,
		github.PushEvent,
	)
}

// routeWebhookEvent routes the webhook payload to the appropriate handler
func (r *WebhookRouter) routeWebhookEvent(
	ctx context.Context,
	req *http.Request,
	payload interface{},
) error {
	eventType := req.Header.Get("X-GitHub-Event")
	r.logger.InfoContext(ctx, "Received webhook event", "event_type", eventType)

	switch event := payload.(type) {
	case github.PullRequestPayload:
		return r.pullRequestHandler.HandlePullRequestEvent(ctx, event)
	case github.CheckRunPayload:
		return r.checkRunHandler.HandleCheckRunEvent(ctx, event)
	case github.WorkflowRunPayload:
		return r.workflowHandler.HandleWorkflowRunEvent(ctx, event)
	case github.CheckSuitePayload, github.WorkflowJobPayload, github.PushPayload:
		r.logger.DebugContext(ctx, "Ignoring non-essential event type", "event_type", eventType)
		return nil
	default:
		r.logger.DebugContext(ctx, "Unsupported event type", "event_type", eventType)
		return nil
	}
}

// handleWebhookError handles webhook processing errors
func (r *WebhookRouter) handleWebhookError(
	w http.ResponseWriter,
	span trace.Span,
	message string,
	err error,
	statusCode int,
) {
	span.SetAttributes(
		attribute.String("result", "error"),
		attribute.String("error", err.Error()),
	)
	r.logger.Error(message, "error", err)
	http.Error(w, message, statusCode)
}

// handleWebhookSuccess handles successful webhook processing
func (r *WebhookRouter) handleWebhookSuccess(w http.ResponseWriter, span trace.Span) {
	span.SetAttributes(attribute.String("result", "success"))
	w.WriteHeader(http.StatusOK)

	_, err := w.Write([]byte("Webhook received successfully"))
	if err != nil {
		r.logger.Error("Failed to write response", "error", err)
	}
}
