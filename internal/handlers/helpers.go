package handlers

import (
	"context"
	"log/slog"

	"github.com/go-playground/webhooks/v6/github"

	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/telemetry"
)

// SecurityCheckManager handles the creation and management of security check runs
type SecurityCheckManager struct {
	logger       *slog.Logger
	checkService *services.CheckService
	stateService *services.StateService
	telemetry    *telemetry.Helper
}

// BaseWebhookHandler contains the common dependencies for all webhook handlers
type BaseWebhookHandler struct {
	logger             *slog.Logger
	commentService     *services.CommentService
	checkService       *services.CheckService
	policyService      *services.PolicyService
	policyCacheService *services.PolicyCacheService
	securityService    *services.SecurityService
	stateService       *services.StateService
	telemetry          *telemetry.Helper
}

// SecurityWebhookHandler extends BaseWebhookHandler with security check management capabilities
type SecurityWebhookHandler struct {
	*BaseWebhookHandler
	securityCheckMgr *SecurityCheckManager
}

// WebhookProcessingConfig holds configuration for processing workflow artifacts
type WebhookProcessingConfig struct {
	Owner         string
	Repo          string
	SHA           string
	WorkflowRunID int64
	PRNumber      int64
	CheckVuln     bool
	CheckLicense  bool
}

// NewSecurityCheckManager creates a new security check manager
func NewSecurityCheckManager(
	logger *slog.Logger,
	checkService *services.CheckService,
	stateService *services.StateService,
) *SecurityCheckManager {
	return &SecurityCheckManager{
		logger:       logger,
		checkService: checkService,
		stateService: stateService,
		telemetry:    telemetry.NewTelemetryHelper("polly/handlers"),
	}
}

// NewBaseWebhookHandler creates a new base webhook handler with common dependencies
func NewBaseWebhookHandler(
	logger *slog.Logger,
	commentService *services.CommentService,
	checkService *services.CheckService,
	policyService *services.PolicyService,
	policyCacheService *services.PolicyCacheService,
	securityService *services.SecurityService,
	stateService *services.StateService,
) *BaseWebhookHandler {
	return &BaseWebhookHandler{
		logger:             logger,
		commentService:     commentService,
		checkService:       checkService,
		policyService:      policyService,
		policyCacheService: policyCacheService,
		securityService:    securityService,
		stateService:       stateService,
		telemetry:          telemetry.NewTelemetryHelper("polly/handlers"),
	}
}

// NewSecurityWebhookHandler creates a new security webhook handler with security check management
func NewSecurityWebhookHandler(base *BaseWebhookHandler) *SecurityWebhookHandler {
	securityHandler := &SecurityWebhookHandler{
		BaseWebhookHandler: base,
	}

	// Only create SecurityCheckManager if we have a valid base handler
	if base != nil {
		securityHandler.securityCheckMgr = NewSecurityCheckManager(
			base.logger,
			base.checkService,
			base.stateService,
		)
	}

	return securityHandler
}

// storeCheckRunIDWithError is a helper method that handles storing check run IDs with consistent error logging and returns the error
func (h *BaseWebhookHandler) storeCheckRunIDWithError(
	ctx context.Context,
	owner, repo, sha string,
	checkRunID int64,
	checkType string,
	storeFunc func(context.Context, string, string, string, int64) error,
) error {
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

// getEventInfo extracts common event information for logging using generics
func getEventInfo[T github.PullRequestPayload | github.CheckRunPayload | github.WorkflowRunPayload | github.CheckSuitePayload](
	event T,
) (owner, repo, sha string, eventID int64) {
	// We use type assertion to 'any' here because Go's type switch does not work directly on generic type parameters.
	switch e := any(event).(type) {
	case github.PullRequestPayload:
		return e.Repository.Owner.Login, e.Repository.Name, e.PullRequest.Head.Sha, e.PullRequest.ID
	case github.CheckRunPayload:
		return e.Repository.Owner.Login, e.Repository.Name, e.CheckRun.HeadSHA, e.CheckRun.ID
	case github.WorkflowRunPayload:
		return e.Repository.Owner.Login, e.Repository.Name, e.WorkflowRun.HeadSha, e.WorkflowRun.ID
	case github.CheckSuitePayload:
		return e.Repository.Owner.Login, e.Repository.Name, e.CheckSuite.HeadSHA, e.CheckSuite.ID
	default:
		// This should never happen due to type constraints, but just in case
		return "", "", "", 0
	}
}
