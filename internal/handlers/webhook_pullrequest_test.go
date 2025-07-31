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

// PullRequestHandlerTestSuite provides shared setup for pull request handler tests
type PullRequestHandlerTestSuite struct {
	suite.Suite
	ctx             context.Context
	logger          *slog.Logger
	baseHandler     *BaseWebhookHandler
	handler         *PullRequestHandler
	commentService  *services.CommentService
	checkService    *services.CheckService
	policyService   *services.PolicyService
	securityService *services.SecurityService
	stateService    *services.StateService
}

func (suite *PullRequestHandlerTestSuite) SetupSuite() {
	suite.ctx = context.Background()
	suite.logger = slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
	)
}

func (suite *PullRequestHandlerTestSuite) SetupTest() {
	// Create test services
	githubClient := clients.NewGitHubClient(suite.ctx)
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	store := storage.NewMemoryStore()

	suite.commentService = services.NewCommentService(githubClient, suite.logger)
	suite.checkService = services.NewCheckService(githubClient, suite.logger)
	suite.policyService = services.NewPolicyService(opaClient, suite.logger)
	suite.securityService = services.NewSecurityService(githubClient, suite.logger)
	suite.stateService = services.NewStateService(store, suite.logger)
	policyCacheService := services.NewPolicyCacheService(suite.policyService, suite.stateService, suite.logger)

	// Create base handler and pull request handler
	suite.baseHandler = NewBaseWebhookHandler(
		suite.logger,
		suite.commentService,
		suite.checkService,
		suite.policyService,
		policyCacheService,
		suite.securityService,
		suite.stateService,
	)
	suite.handler = NewPullRequestHandler(suite.baseHandler)
}

func TestPullRequestHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(PullRequestHandlerTestSuite))
}

func (suite *PullRequestHandlerTestSuite) TestNewPullRequestHandler() {
	suite.T().Run("creates handler successfully", func(t *testing.T) {
		handler := NewPullRequestHandler(suite.baseHandler)

		assert.NotNil(t, handler)
		assert.NotNil(t, handler.BaseWebhookHandler)
	})
}

func (suite *PullRequestHandlerTestSuite) TestHandlePullRequestEvent_SupportedActions() {
	supportedActions := []string{"opened", "reopened", "synchronize"}

	for _, action := range supportedActions {
		suite.T().Run("handles "+action+" action", func(t *testing.T) {
			payload := github.PullRequestPayload{
				Action: action,
				Number: 123,
			}
			// Set nested Repository fields
			payload.Repository.Name = "test-repo"
			payload.Repository.Owner.Login = "test-owner"
			payload.PullRequest.Head.Sha = "test-sha"

			// The handler should try to create security checks, but since we don't have
			// real GitHub API credentials, these will fail. The handler should handle
			// this gracefully and return an error indicating the API call failed
			err := suite.handler.HandlePullRequestEvent(suite.ctx, payload)

			// We expect an error because GitHub API calls will fail in tests
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failed to create")
		})
	}
}

func (suite *PullRequestHandlerTestSuite) TestHandlePullRequestEvent_UnsupportedActions() {
	unsupportedActions := []string{"closed", "edited", "labeled", "unlabeled"}

	for _, action := range unsupportedActions {
		suite.T().Run("ignores "+action+" action", func(t *testing.T) {
			payload := github.PullRequestPayload{
				Action: action,
				Number: 123,
			}
			// Set nested Repository fields
			payload.Repository.Name = "test-repo"
			payload.Repository.Owner.Login = "test-owner"
			payload.PullRequest.Head.Sha = "test-sha"

			err := suite.handler.HandlePullRequestEvent(suite.ctx, payload)

			// Should return no error for unsupported actions (just ignored)
			assert.NoError(t, err)
		})
	}
}

func (suite *PullRequestHandlerTestSuite) TestHandlePullRequestEvent_StateStorage() {
	suite.T().Run("stores PR number even when security checks fail", func(t *testing.T) {
		payload := github.PullRequestPayload{
			Action: "opened",
			Number: 456,
		}
		// Set nested Repository fields
		payload.Repository.Name = "test-repo"
		payload.Repository.Owner.Login = "test-owner"
		payload.PullRequest.Head.Sha = "test-sha-456"

		// The handler will try to create security checks which will fail,
		// but it should still store the PR number
		err := suite.handler.HandlePullRequestEvent(suite.ctx, payload)
		assert.Error(t, err) // Expect error due to failed security check creation

		// However, PR number should still be stored before the security check failure
		storedPR, exists, err := suite.stateService.GetPRNumber(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha-456",
		)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, int64(456), storedPR)
	})
}

// Simple unit tests for pull request handler
func TestNewPullRequestHandler_Unit(t *testing.T) {
	t.Run("creates handler with valid base handler", func(t *testing.T) {
		logger := slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
		)
		store := storage.NewMemoryStore()
		githubClient := clients.NewGitHubClient(context.Background())
		opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
		stateService := services.NewStateService(store, logger)
		policyService := services.NewPolicyService(opaClient, logger)
		policyCacheService := services.NewPolicyCacheService(policyService, stateService, logger)

		baseHandler := NewBaseWebhookHandler(
			logger,
			services.NewCommentService(githubClient, logger),
			services.NewCheckService(githubClient, logger),
			policyService,
			policyCacheService,
			services.NewSecurityService(githubClient, logger),
			stateService,
		)

		handler := NewPullRequestHandler(baseHandler)

		assert.NotNil(t, handler)
		assert.Equal(t, baseHandler, handler.BaseWebhookHandler)
	})

	t.Run("creates handler with nil base handler", func(t *testing.T) {
		// Should handle nil gracefully
		handler := NewPullRequestHandler(nil)

		assert.NotNil(t, handler)
		assert.Nil(t, handler.BaseWebhookHandler)
	})
}
