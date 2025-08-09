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

// CheckRunHandlerTestSuite provides shared setup for check run handler tests
type CheckRunHandlerTestSuite struct {
	suite.Suite
	ctx          context.Context
	logger       *slog.Logger
	baseHandler  *BaseWebhookHandler
	handler      *CheckRunHandler
	stateService *services.StateService
}

func (suite *CheckRunHandlerTestSuite) SetupSuite() {
	suite.ctx = context.Background()
	suite.logger = slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
	)
}

func (suite *CheckRunHandlerTestSuite) SetupTest() {
	// Create test services
	githubClient := clients.NewGitHubClient(suite.ctx)
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
	policyCacheService := services.NewPolicyCacheService(
		policyService,
		suite.stateService,
		suite.logger,
		telemetry.NewTelemetryHelper("test"),
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

	// Create base handler and check run handler
	suite.baseHandler = NewBaseWebhookHandler(
		suite.logger,
		commentService,
		checkService,
		policyService,
		policyCacheService,
		securityService,
		suite.stateService,
	)
	suite.handler = NewCheckRunHandler(suite.baseHandler)
}

func TestCheckRunHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(CheckRunHandlerTestSuite))
}

func (suite *CheckRunHandlerTestSuite) TestNewCheckRunHandler() {
	suite.T().Run("creates handler successfully", func(t *testing.T) {
		handler := NewCheckRunHandler(suite.baseHandler)

		assert.NotNil(t, handler)
		assert.NotNil(t, handler.BaseWebhookHandler)
	})
}

func (suite *CheckRunHandlerTestSuite) TestHandleCheckRunEvent_UnsupportedActions() {
	unsupportedActions := []string{"created", "completed"}

	for _, action := range unsupportedActions {
		suite.T().Run("ignores "+action+" action", func(t *testing.T) {
			payload := github.CheckRunPayload{
				Action: action,
			}
			// Set nested fields
			payload.Repository.Name = "test-repo"
			payload.Repository.Owner.Login = "test-owner"
			payload.CheckRun.HeadSHA = "test-sha"

			err := suite.handler.HandleCheckRunEvent(suite.ctx, payload)

			// Should return no error for unsupported actions (just ignored)
			assert.NoError(t, err)
		})
	}
}

func (suite *CheckRunHandlerTestSuite) TestHandleCheckRunEvent_RerequestAction() {
	suite.T().Run("handles rerequested action with vulnerability check", func(t *testing.T) {
		// First store a vulnerability check run ID
		err := suite.stateService.StoreVulnerabilityCheckRunID(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
			12345,
		)
		require.NoError(suite.T(), err)

		payload := github.CheckRunPayload{
			Action: "rerequested",
		}
		// Set nested fields
		payload.Repository.Name = "test-repo"
		payload.Repository.Owner.Login = "test-owner"
		payload.CheckRun.HeadSHA = "test-sha"
		payload.CheckRun.Name = "Vulnerability Scan Check"

		// This will try to make GitHub API calls which will fail in tests
		err = suite.handler.HandleCheckRunEvent(suite.ctx, payload)

		// Expect error due to failed GitHub API calls
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to start vulnerability check")
	})

	suite.T().Run("handles rerequested action with license check", func(t *testing.T) {
		// First store a license check run ID
		err := suite.stateService.StoreLicenseCheckRunID(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
			67890,
		)
		require.NoError(suite.T(), err)

		payload := github.CheckRunPayload{
			Action: "rerequested",
		}
		// Set nested fields
		payload.Repository.Name = "test-repo"
		payload.Repository.Owner.Login = "test-owner"
		payload.CheckRun.HeadSHA = "test-sha"
		payload.CheckRun.Name = "License Compliance Check"

		// This will try to make GitHub API calls which will fail in tests
		err = suite.handler.HandleCheckRunEvent(suite.ctx, payload)

		// Expect error due to failed GitHub API calls
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to start license check")
	})
}

// Simple unit tests for check run handler
func TestNewCheckRunHandler_Unit(t *testing.T) {
	t.Run("creates handler with valid base handler", func(t *testing.T) {
		logger := slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
		)
		store := storage.NewMemoryStore()
		githubClient := clients.NewGitHubClient(context.Background())
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
				services.DefaultSecurityDetectors()...),
			stateService,
		)

		handler := NewCheckRunHandler(baseHandler)

		assert.NotNil(t, handler)
		assert.Equal(t, baseHandler, handler.BaseWebhookHandler)
	})

	t.Run("creates handler with nil base handler", func(t *testing.T) {
		// Should handle nil gracefully
		handler := NewCheckRunHandler(nil)

		assert.NotNil(t, handler)
		assert.Nil(t, handler.BaseWebhookHandler)
	})
}
