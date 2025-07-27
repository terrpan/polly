// Package handlers provides HTTP handlers for health checks and webhook processing.
// This file defines the PullRequestHandler which processes GitHub pull request events.
package handlers

import (
	"context"

	"github.com/go-playground/webhooks/v6/github"
	"go.opentelemetry.io/otel/attribute"
)

// PullRequestHandler handles pull request webhook events
type PullRequestHandler struct {
	*SecurityWebhookHandler
}

// NewPullRequestHandler creates a new pull request handler
func NewPullRequestHandler(base *BaseWebhookHandler) *PullRequestHandler {
	return &PullRequestHandler{
		SecurityWebhookHandler: NewSecurityWebhookHandler(base),
	}
}

// HandlePullRequestEvent processes pull request events.
func (h *PullRequestHandler) HandlePullRequestEvent(
	ctx context.Context,
	event github.PullRequestPayload,
) error {
	ctx, span := h.tracingHelper.StartSpan(ctx, "webhook.handle_pull_request")
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

	return h.securityCheckMgr.CreateSecurityCheckRuns(ctx, owner, repo, sha, event.Number)
}
