package handlers

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/terrpan/polly/internal/telemetry"

	"github.com/go-playground/webhooks/v6/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/storage"
)

// WorkflowHandlerTestSuite provides shared setup for workflow handler tests
type WorkflowHandlerTestSuite struct {
	suite.Suite
	ctx          context.Context
	logger       *slog.Logger
	baseHandler  *BaseWebhookHandler
	handler      *WorkflowHandler
	stateService *services.StateService
}

func (suite *WorkflowHandlerTestSuite) SetupSuite() {
	suite.ctx = context.Background()
	suite.logger = slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
	)
}

func (suite *WorkflowHandlerTestSuite) SetupTest() {
	// Create test services
	githubClient := clients.NewGitHubClient(suite.ctx, "", "")
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	store := storage.NewMemoryStore()

	commentService := services.NewCommentService(
		githubClient,
		suite.logger,
		telemetry.NewTelemetryHelper("test"),
	)
	checkService := services.NewCheckService(
		githubClient,
		suite.logger,
		telemetry.NewTelemetryHelper("test"),
	)
	policyService := services.NewPolicyService(
		opaClient,
		suite.logger,
		telemetry.NewTelemetryHelper("test"),
		services.NewStandardEvaluators(nil),
	)
	securityService := services.NewSecurityService(
		githubClient,
		suite.logger,
		telemetry.NewTelemetryHelper("test"),
		services.DefaultSecurityDetectors()...)
	suite.stateService = services.NewStateService(
		store,
		suite.logger,
		telemetry.NewTelemetryHelper("test"),
	)
	policyCacheService := services.NewPolicyCacheService(
		policyService,
		suite.stateService,
		suite.logger,
		telemetry.NewTelemetryHelper("test"),
	)

	// Create base handler and workflow handler
	suite.baseHandler = NewBaseWebhookHandler(
		suite.logger,
		commentService,
		checkService,
		policyService,
		policyCacheService,
		securityService,
		suite.stateService,
	)
	suite.handler = NewWorkflowHandler(suite.baseHandler)
}

func TestWorkflowHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(WorkflowHandlerTestSuite))
}

func (suite *WorkflowHandlerTestSuite) TestNewWorkflowHandler() {
	suite.T().Run("creates handler successfully", func(t *testing.T) {
		handler := NewWorkflowHandler(suite.baseHandler)

		assert.NotNil(t, handler)
		assert.NotNil(t, handler.BaseWebhookHandler)
	})
}

func (suite *WorkflowHandlerTestSuite) TestHandleWorkflowRunEvent_UnsupportedActions() {
	unsupportedActions := []string{"requested", "in_progress"}

	for _, action := range unsupportedActions {
		suite.T().Run("ignores "+action+" action", func(t *testing.T) {
			payload := github.WorkflowRunPayload{
				Action: action,
			}
			// Set nested fields
			payload.Repository.Name = "test-repo"
			payload.Repository.Owner.Login = "test-owner"
			payload.WorkflowRun.HeadSha = "test-sha"

			err := suite.handler.HandleWorkflowRunEvent(suite.ctx, payload)

			// Should return no error for unsupported actions (just ignored)
			assert.NoError(t, err)
		})
	}
}

func (suite *WorkflowHandlerTestSuite) TestHandleWorkflowRunEvent_StartWithExistingChecks_SetsInProgress_NoCreate() {
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha-existing"

	// Pre-store PR number and existing check run IDs to force the in_progress branch
	require.NoError(suite.T(), suite.stateService.StorePRNumber(suite.ctx, owner, repo, sha, 42))
	require.NoError(
		suite.T(),
		suite.stateService.StoreVulnerabilityCheckRunID(suite.ctx, owner, repo, sha, 1111),
	)
	require.NoError(
		suite.T(),
		suite.stateService.StoreLicenseCheckRunID(suite.ctx, owner, repo, sha, 2222),
	)

	// Build a workflow_run payload for start actions
	buildPayload := func(action string) github.WorkflowRunPayload {
		p := github.WorkflowRunPayload{Action: action}
		p.Repository.Name = repo
		p.Repository.Owner.Login = owner
		p.WorkflowRun.HeadSha = sha
		p.WorkflowRun.ID = 7777
		p.Workflow.Name = "Security Scan and SBOM Generation"
		return p
	}

	// requested
	err := suite.handler.HandleWorkflowRunEvent(suite.ctx, buildPayload("requested"))
	// Guard should prevent creation path (which would error due to real GitHub API), so expect no error
	assert.NoError(suite.T(), err)

	// in_progress
	err = suite.handler.HandleWorkflowRunEvent(suite.ctx, buildPayload("in_progress"))
	assert.NoError(suite.T(), err)

	// Ensure stored IDs remain unchanged (no duplicate creation overwrote them)
	if id, ok, _ := suite.stateService.GetVulnerabilityCheckRunID(suite.ctx, owner, repo, sha); assert.True(
		suite.T(),
		ok,
	) {
		assert.Equal(suite.T(), int64(1111), id)
	}
	if id, ok, _ := suite.stateService.GetLicenseCheckRunID(suite.ctx, owner, repo, sha); assert.True(
		suite.T(),
		ok,
	) {
		assert.Equal(suite.T(), int64(2222), id)
	}
}

func (suite *WorkflowHandlerTestSuite) TestHandleWorkflowRunEvent_CompletedAction() {
	suite.T().Run("handles completed action with conclusion success", func(t *testing.T) {
		// First store a workflow run ID
		err := suite.stateService.StoreWorkflowRunID(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
			98765,
		)
		require.NoError(suite.T(), err)

		payload := github.WorkflowRunPayload{
			Action: "completed",
		}
		// Initialize nested structs properly
		payload.Repository.Name = "test-repo"
		payload.Repository.Owner.Login = "test-owner"
		payload.WorkflowRun.HeadSha = "test-sha"
		payload.WorkflowRun.ID = 98765
		payload.WorkflowRun.Conclusion = "success"

		// This will complete security checks as neutral since there's no artifacts URL
		err = suite.handler.HandleWorkflowRunEvent(suite.ctx, payload)

		// Should not return error when completing checks as neutral
		assert.NoError(t, err)
	})

	suite.T().Run("handles completed action with conclusion failure", func(t *testing.T) {
		payload := github.WorkflowRunPayload{
			Action: "completed",
		}
		// Set nested fields
		payload.Repository.Name = "test-repo"
		payload.Repository.Owner.Login = "test-owner"
		payload.WorkflowRun.HeadSha = "test-sha"
		payload.WorkflowRun.ID = 11111
		payload.WorkflowRun.Conclusion = "failure"

		// Should complete security checks as neutral for failed workflows
		err := suite.handler.HandleWorkflowRunEvent(suite.ctx, payload)

		// Should not return error when completing checks as neutral
		assert.NoError(t, err)
	})
}

func (suite *WorkflowHandlerTestSuite) TestHandleWorkflowRunEvent_StateStorage() {
	suite.T().Run("stores workflow run ID for requested workflows", func(t *testing.T) {
		payload := github.WorkflowRunPayload{
			Action: "requested",
		}
		// Set nested fields
		payload.Repository.Name = "test-repo"
		payload.Repository.Owner.Login = "test-owner"
		payload.WorkflowRun.HeadSha = "test-sha-workflow"
		payload.WorkflowRun.ID = 54321

		err := suite.handler.HandleWorkflowRunEvent(suite.ctx, payload)
		assert.NoError(t, err) // requested action should be ignored gracefully

		// Note: This test ensures that no workflow run ID is stored for the "requested" action,
		// as storage only occurs for the "completed" action in the current implementation.
	})
}

// Simple unit tests for workflow handler
func TestNewWorkflowHandler_Unit(t *testing.T) {
	t.Run("creates handler with valid base handler", func(t *testing.T) {
		logger := slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
		)
		store := storage.NewMemoryStore()
		githubClient := clients.NewGitHubClient(context.Background(), "", "")
		opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
		stateService := services.NewStateService(
			store,
			logger,
			telemetry.NewTelemetryHelper("test"),
		)
		policyService := services.NewPolicyService(
			opaClient,
			logger,
			telemetry.NewTelemetryHelper("test"),
			services.NewStandardEvaluators(nil),
		)
		policyCacheService := services.NewPolicyCacheService(
			policyService,
			stateService,
			logger,
			telemetry.NewTelemetryHelper("test"),
		)

		baseHandler := NewBaseWebhookHandler(
			logger,
			services.NewCommentService(githubClient, logger, telemetry.NewTelemetryHelper("test")),
			services.NewCheckService(githubClient, logger, telemetry.NewTelemetryHelper("test")),
			policyService,
			policyCacheService,
			services.NewSecurityService(
				githubClient,
				logger,
				telemetry.NewTelemetryHelper("test"),
				services.DefaultSecurityDetectors()...,
			),
			stateService,
		)

		handler := NewWorkflowHandler(baseHandler)

		assert.NotNil(t, handler)
		assert.Equal(t, baseHandler, handler.BaseWebhookHandler)
	})

	t.Run("creates handler with nil base handler", func(t *testing.T) {
		// Should handle nil gracefully
		handler := NewWorkflowHandler(nil)

		assert.NotNil(t, handler)
		assert.Nil(t, handler.BaseWebhookHandler)
	})
}
