package handlers

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/storage"
)

// Test helper to create test services
func createTestServices() (*services.CommentService, *services.CheckService, *services.PolicyService, *services.SecurityService, *services.StateService) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create test GitHub client (will not make real API calls in tests)
	githubClient := clients.NewGitHubClient(context.Background())

	// Create test OPA client
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")

	// Create test storage and state service
	store := storage.NewMemoryStore()
	stateService := services.NewStateService(store, logger)

	commentService := services.NewCommentService(githubClient, logger)
	checkService := services.NewCheckService(githubClient, logger)
	policyService := services.NewPolicyService(opaClient, logger)
	securityService := services.NewSecurityService(githubClient, logger)

	return commentService, checkService, policyService, securityService, stateService
}

func TestNewWebhookHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	commentService, checkService, policyService, securityService, stateService := createTestServices()

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService, stateService)

	require.NoError(t, err)
	assert.NotNil(t, handler)
}

func TestWebhookHandler_Structure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	commentService, checkService, policyService, securityService, stateService := createTestServices()

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService, stateService)
	require.NoError(t, err)

	// Test that handler has the expected structure
	assert.NotNil(t, handler.commentService)
	assert.NotNil(t, handler.checkService)
	assert.NotNil(t, handler.policyService)
	assert.NotNil(t, handler.securityService)
	assert.NotNil(t, handler.stateService)
}

func TestWebhookHandler_ContextStore(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	commentService, checkService, policyService, securityService, stateService := createTestServices()

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService, stateService)
	require.NoError(t, err)

	// Test that StateService is available
	assert.NotNil(t, handler.stateService)

	// Test that StateService can store and retrieve data
	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"

	err = handler.stateService.StorePRNumber(ctx, owner, repo, sha, 123)
	require.NoError(t, err)
	err = handler.stateService.StoreVulnerabilityCheckRunID(ctx, owner, repo, sha, 456)
	require.NoError(t, err)

	prNum, exists, err := handler.stateService.GetPRNumber(ctx, owner, repo, sha)
	require.NoError(t, err)
	require.True(t, exists)
	assert.Equal(t, int64(123), prNum)

	vulnCheckID, exists, err := handler.stateService.GetVulnerabilityCheckRunID(ctx, owner, repo, sha)
	require.NoError(t, err)
	require.True(t, exists)
	assert.Equal(t, int64(456), vulnCheckID)
}

func TestWebhookHandler_Services(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	commentService, checkService, policyService, securityService, stateService := createTestServices()

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService, stateService)
	require.NoError(t, err)

	// Test that all services are properly assigned
	assert.Equal(t, commentService, handler.commentService)
	assert.Equal(t, checkService, handler.checkService)
	assert.Equal(t, policyService, handler.policyService)
	assert.Equal(t, securityService, handler.securityService)
	assert.Equal(t, stateService, handler.stateService)
}

func TestWebhookHandler_ConcurrentAccess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	commentService, checkService, policyService, securityService, stateService := createTestServices()

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService, stateService)
	require.NoError(t, err)

	// Test that StateService can be used for concurrent access without explicit mutexes
	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"

	assert.NotPanics(t, func() {
		err := handler.stateService.StorePRNumber(ctx, owner, repo, sha, 1)
		require.NoError(t, err)
	})

	assert.NotPanics(t, func() {
		err := handler.stateService.StoreVulnerabilityCheckRunID(ctx, owner, repo, sha, 2)
		require.NoError(t, err)
	})
}

func TestWebhookHandler_StoreCheckRunIDHelpers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	commentService, checkService, policyService, securityService, stateService := createTestServices()

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService, stateService)
	require.NoError(t, err)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"
	checkRunID := int64(12345)

	t.Run("storeCheckRunID does not return error (fire and forget)", func(t *testing.T) {
		// Should not panic and should store successfully
		assert.NotPanics(t, func() {
			handler.storeCheckRunID(ctx, owner, repo, sha, checkRunID, "vulnerability", handler.stateService.StoreVulnerabilityCheckRunID)
		})

		// Verify it was stored
		storedID, exists, err := handler.stateService.GetVulnerabilityCheckRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, checkRunID, storedID)
	})

	t.Run("storeCheckRunIDWithError returns error when storage fails", func(t *testing.T) {
		// Test with a function that returns an error
		mockStoreFunc := func(ctx context.Context, owner, repo, sha string, id int64) error {
			return assert.AnError
		}

		err := handler.storeCheckRunIDWithError(ctx, owner, repo, sha, checkRunID+1, "test", mockStoreFunc)
		assert.Error(t, err)
		assert.Equal(t, assert.AnError, err)
	})

	t.Run("storeCheckRunIDWithError succeeds when storage succeeds", func(t *testing.T) {
		licenseCheckRunID := int64(67890)

		err := handler.storeCheckRunIDWithError(ctx, owner, repo, sha, licenseCheckRunID, "license", handler.stateService.StoreLicenseCheckRunID)
		assert.NoError(t, err)

		// Verify it was stored
		storedID, exists, err := handler.stateService.GetLicenseCheckRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, licenseCheckRunID, storedID)
	})
}
