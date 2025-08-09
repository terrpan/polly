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
	"github.com/terrpan/polly/internal/telemetry"
)

// CheckSuiteWebhookTestSuite provides shared setup for check suite handler tests
type CheckSuiteWebhookTestSuite struct {
	suite.Suite
	ctx          context.Context
	logger       *slog.Logger
	baseHandler  *BaseWebhookHandler
	handler      *CheckSuiteWebhookHandler
	stateService *services.StateService
}

func (suite *CheckSuiteWebhookTestSuite) SetupSuite() {
	suite.ctx = context.Background()
	suite.logger = slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
	)
}

func (suite *CheckSuiteWebhookTestSuite) SetupTest() {
	// Create test services
	githubClient := clients.NewGitHubClient(suite.ctx)
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	store := storage.NewMemoryStore()

	// Order: create state service before policy cache for safety
	suite.stateService = services.NewStateService(
		store,
		suite.logger,
		telemetry.NewTelemetryHelper("test"),
	)

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

	// Create base handler and check suite handler
	suite.baseHandler = NewBaseWebhookHandler(
		suite.logger,
		commentService,
		checkService,
		policyService,
		policyCacheService,
		securityService,
		suite.stateService,
	)
	suite.handler = NewCheckSuiteWebhookHandler(suite.baseHandler)
}

func TestCheckSuiteWebhookTestSuite(t *testing.T) {
	suite.Run(t, new(CheckSuiteWebhookTestSuite))
}

func (suite *CheckSuiteWebhookTestSuite) TestNewCheckSuiteWebhookHandler() {
	suite.T().Run("creates handler successfully", func(t *testing.T) {
		handler := NewCheckSuiteWebhookHandler(suite.baseHandler)

		assert.NotNil(t, handler)
		assert.NotNil(t, handler.SecurityWebhookHandler)
		assert.NotNil(t, handler.checkRunHandler)
	})
}

func (suite *CheckSuiteWebhookTestSuite) TestHandleCheckSuite_SupportedActions_NoWorkflow() {
	// With no workflow stored, both requested and rerequested should not error
	supportedActions := []string{"requested", "rerequested", "completed"}

	for _, action := range supportedActions {
		suite.T().Run("handles "+action+" action without workflow", func(t *testing.T) {
			payload := github.CheckSuitePayload{Action: action}
			payload.Repository.Name = "test-repo"
			payload.Repository.Owner.Login = "test-owner"
			payload.CheckSuite.HeadSHA = "test-sha"
			payload.CheckSuite.ID = 123456789

			err := suite.handler.HandleCheckSuite(suite.ctx, payload)
			assert.NoError(t, err)
		})
	}
}

func (suite *CheckSuiteWebhookTestSuite) TestHandleCheckSuiteRequested_WithWorkflow() {
	suite.T().
		Run("handles requested with existing workflow and stores suite ID", func(t *testing.T) {
			// Store a workflow run ID so processSecurityWorkflow executes and likely errors on artifact processing
			err := suite.stateService.StoreWorkflowRunID(
				suite.ctx,
				"test-owner",
				"test-repo",
				"test-sha",
				42,
			)
			require.NoError(suite.T(), err)

			payload := github.CheckSuitePayload{Action: "requested"}
			payload.Repository.Name = "test-repo"
			payload.Repository.Owner.Login = "test-owner"
			payload.CheckSuite.HeadSHA = "test-sha"
			payload.CheckSuite.ID = 777888999

			err = suite.handler.HandleCheckSuite(suite.ctx, payload)

			// Security artifact processing will call external APIs and may fail; ensure error is surfaced
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failed to process workflow security artifacts")

			// Verify check suite ID was stored
			suiteID, found, err := suite.stateService.GetCheckSuiteID(
				suite.ctx,
				"test-owner",
				"test-repo",
				"test-sha",
			)
			assert.NoError(t, err)
			assert.True(t, found)
			assert.Equal(t, int64(777888999), suiteID)
		})
}

func (suite *CheckSuiteWebhookTestSuite) TestHandleCheckSuiteRequested_NoWorkflow() {
	suite.T().Run("stores suite ID and returns no error when no workflow", func(t *testing.T) {
		payload := github.CheckSuitePayload{Action: "requested"}
		payload.Repository.Name = "test-repo"
		payload.Repository.Owner.Login = "test-owner"
		payload.CheckSuite.HeadSHA = "no-workflow-sha"
		payload.CheckSuite.ID = 123450001

		err := suite.handler.HandleCheckSuite(suite.ctx, payload)
		assert.NoError(t, err)

		suiteID, found, err := suite.stateService.GetCheckSuiteID(
			suite.ctx,
			"test-owner",
			"test-repo",
			"no-workflow-sha",
		)
		assert.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, int64(123450001), suiteID)
	})
}

func (suite *CheckSuiteWebhookTestSuite) TestHandleCheckSuiteRerequested_WithExistingChecks() {
	suite.T().
		Run("reruns existing checks when IDs present and returns no error", func(t *testing.T) {
			// Store existing check run IDs
			err := suite.stateService.StoreVulnerabilityCheckRunID(
				suite.ctx,
				"test-owner",
				"test-repo",
				"test-sha-rerun",
				11111,
			)
			require.NoError(suite.T(), err)

			err = suite.stateService.StoreLicenseCheckRunID(
				suite.ctx,
				"test-owner",
				"test-repo",
				"test-sha-rerun",
				22222,
			)
			require.NoError(suite.T(), err)

			payload := github.CheckSuitePayload{Action: "rerequested"}
			payload.Repository.Name = "test-repo"
			payload.Repository.Owner.Login = "test-owner"
			payload.CheckSuite.HeadSHA = "test-sha-rerun"
			payload.CheckSuite.ID = 999000111

			err = suite.handler.HandleCheckSuite(suite.ctx, payload)

			// Errors from underlying API calls are logged and not propagated; expect no error
			assert.NoError(t, err)
		})
}

func (suite *CheckSuiteWebhookTestSuite) TestHandleCheckSuiteRerequested_NoExistingChecks_NoWorkflow() {
	suite.T().
		Run("treats as new request when no existing checks and no workflow", func(t *testing.T) {
			payload := github.CheckSuitePayload{Action: "rerequested"}
			payload.Repository.Name = "test-repo"
			payload.Repository.Owner.Login = "test-owner"
			payload.CheckSuite.HeadSHA = "sha-no-checks"
			payload.CheckSuite.ID = 333222111

			err := suite.handler.HandleCheckSuite(suite.ctx, payload)

			// With no workflow and no checks, it should return nil (no-op)
			assert.NoError(t, err)
		})
}

func (suite *CheckSuiteWebhookTestSuite) TestHandleCheckSuiteCompleted() {
	suite.T().Run("logs completion without error", func(t *testing.T) {
		payload := github.CheckSuitePayload{Action: "completed"}
		payload.Repository.Name = "test-repo"
		payload.Repository.Owner.Login = "test-owner"
		payload.CheckSuite.HeadSHA = "completed-sha"
		payload.CheckSuite.ID = 1010101
		payload.CheckSuite.Conclusion = "success"

		err := suite.handler.HandleCheckSuite(suite.ctx, payload)
		assert.NoError(t, err)
	})
}

// Simple unit test creating handler from a minimal base handler
func TestNewCheckSuiteWebhookHandler_Unit(t *testing.T) {
	logger := slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
	)
	store := storage.NewMemoryStore()
	githubClient := clients.NewGitHubClient(context.Background())
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	stateService := services.NewStateService(store, logger, telemetry.NewTelemetryHelper("test"))
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

	handler := NewCheckSuiteWebhookHandler(baseHandler)

	assert.NotNil(t, handler)
	assert.NotNil(t, handler.SecurityWebhookHandler)
	assert.NotNil(t, handler.checkRunHandler)
}
