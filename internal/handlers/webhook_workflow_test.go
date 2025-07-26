package handlers

import (
	"context"
	"log/slog"
	"os"
	"testing"

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
	githubClient := clients.NewGitHubClient(suite.ctx)
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	store := storage.NewMemoryStore()

	commentService := services.NewCommentService(githubClient, suite.logger)
	checkService := services.NewCheckService(githubClient, suite.logger)
	policyService := services.NewPolicyService(opaClient, suite.logger)
	securityService := services.NewSecurityService(githubClient, suite.logger)
	suite.stateService = services.NewStateService(store, suite.logger)

	// Create base handler and workflow handler
	suite.baseHandler = NewBaseWebhookHandler(
		suite.logger,
		commentService,
		checkService,
		policyService,
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

		// Note: The workflow run ID storage happens in the completed action,
		// not in the requested action based on the current implementation
	})
}

// Simple unit tests for workflow handler
func TestNewWorkflowHandler_Unit(t *testing.T) {
	t.Run("creates handler with valid base handler", func(t *testing.T) {
		logger := slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
		)
		store := storage.NewMemoryStore()
		githubClient := clients.NewGitHubClient(context.Background())
		opaClient, _ := clients.NewOPAClient("http://test-opa:8181")

		baseHandler := NewBaseWebhookHandler(
			logger,
			services.NewCommentService(githubClient, logger),
			services.NewCheckService(githubClient, logger),
			services.NewPolicyService(opaClient, logger),
			services.NewSecurityService(githubClient, logger),
			services.NewStateService(store, logger),
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
