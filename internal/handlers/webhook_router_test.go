package handlers

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/terrpan/polly/internal/telemetry"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/storage"
)

// Simple unit tests for the WebhookRouter
func TestNewWebhookRouter_Unit(t *testing.T) {
	t.Run("creates router successfully", func(t *testing.T) {
		logger := slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
		)
		store := storage.NewMemoryStore()
		githubClient := clients.NewGitHubClient(context.Background())
		opaClient, _ := clients.NewOPAClient("http://test-opa:8181")

		commentService := services.NewCommentService(
			githubClient,
			logger,
			telemetry.NewTelemetryHelper("test"),
		)
		checkService := services.NewCheckService(
			githubClient,
			logger,
			telemetry.NewTelemetryHelper("test"),
		)
		policyService := services.NewPolicyService(
			opaClient,
			logger,
			telemetry.NewTelemetryHelper("test"),
			services.NewStandardEvaluators(nil),
		)
		securityService := services.NewSecurityService(
			githubClient,
			logger,
			telemetry.NewTelemetryHelper("test"),
			services.DefaultSecurityDetectors()...)
		stateService := services.NewStateService(
			store,
			logger,
			telemetry.NewTelemetryHelper("test"),
		)
		policyCacheService := services.NewPolicyCacheService(
			policyService,
			stateService,
			logger,
			telemetry.NewTelemetryHelper("test"),
		)

		router, err := NewWebhookRouter(
			logger,
			commentService,
			checkService,
			policyService,
			policyCacheService,
			securityService,
			stateService,
		)

		require.NoError(t, err)
		assert.NotNil(t, router)
		assert.Equal(t, logger, router.logger)
		assert.NotNil(t, router.hook)
		assert.NotNil(t, router.telemetry)
		assert.NotNil(t, router.pullRequestHandler)
		assert.NotNil(t, router.checkRunHandler)
		assert.NotNil(t, router.workflowHandler)
		assert.NotNil(t, router.checkSuiteHandler)
	})

	t.Run("router has proper structure", func(t *testing.T) {
		logger := slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
		)
		store := storage.NewMemoryStore()
		githubClient := clients.NewGitHubClient(context.Background())
		opaClient, _ := clients.NewOPAClient("http://test-opa:8181")

		commentService := services.NewCommentService(
			githubClient,
			logger,
			telemetry.NewTelemetryHelper("test"),
		)
		checkService := services.NewCheckService(
			githubClient,
			logger,
			telemetry.NewTelemetryHelper("test"),
		)
		policyService := services.NewPolicyService(
			opaClient,
			logger,
			telemetry.NewTelemetryHelper("test"),
			services.NewStandardEvaluators(nil),
		)
		securityService := services.NewSecurityService(
			githubClient,
			logger,
			telemetry.NewTelemetryHelper("test"),
			services.DefaultSecurityDetectors()...)
		stateService := services.NewStateService(
			store,
			logger,
			telemetry.NewTelemetryHelper("test"),
		)
		policyCacheService := services.NewPolicyCacheService(
			policyService,
			stateService,
			logger,
			telemetry.NewTelemetryHelper("test"),
		)

		router, err := NewWebhookRouter(
			logger,
			commentService,
			checkService,
			policyService,
			policyCacheService,
			securityService,
			stateService,
		)

		require.NoError(t, err)

		// Verify all handlers are properly initialized
		assert.NotNil(t, router.pullRequestHandler)
		assert.NotNil(t, router.checkRunHandler)
		assert.NotNil(t, router.workflowHandler)
		assert.NotNil(t, router.checkSuiteHandler)

		// Verify handlers have their base handler
		assert.NotNil(t, router.pullRequestHandler.BaseWebhookHandler)
		assert.NotNil(t, router.checkRunHandler.BaseWebhookHandler)
		assert.NotNil(t, router.workflowHandler.BaseWebhookHandler)
		assert.NotNil(t, router.checkSuiteHandler.BaseWebhookHandler)
	})
}

// Note: HTTP webhook parsing tests would require complex GitHub webhook payload creation
// and are better tested as integration tests with real webhook payloads.
// The main functionality is tested through the individual handler tests.
