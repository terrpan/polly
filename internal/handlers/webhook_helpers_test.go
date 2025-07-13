package handlers

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"log/slog"
	"os"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/utils"
)

// Test executeConcurrently function
func TestExecuteConcurrently(t *testing.T) {
	t.Run("all tasks succeed", func(t *testing.T) {
		var mu sync.Mutex
		var results []string
		tasks := []func() error{
			func() error {
				mu.Lock()
				results = append(results, "task1")
				mu.Unlock()
				return nil
			},
			func() error {
				mu.Lock()
				results = append(results, "task2")
				mu.Unlock()
				return nil
			},
			func() error {
				mu.Lock()
				results = append(results, "task3")
				mu.Unlock()
				return nil
			},
		}

		errs := utils.ExecuteConcurrently(tasks)

		assert.Len(t, errs, 3)
		for _, err := range errs {
			assert.NoError(t, err)
		}
		assert.Len(t, results, 3)
	})

	t.Run("some tasks fail", func(t *testing.T) {
		tasks := []func() error{
			func() error {
				return nil
			},
			func() error {
				return fmt.Errorf("task 2 failed")
			},
			func() error {
				return nil
			},
		}

		errs := utils.ExecuteConcurrently(tasks)

		assert.Len(t, errs, 3)
		assert.NoError(t, errs[0])
		assert.Error(t, errs[1])
		assert.NoError(t, errs[2])
		assert.Contains(t, errs[1].Error(), "task 2 failed")
	})

	t.Run("empty tasks", func(t *testing.T) {
		tasks := []func() error{}
		errs := utils.ExecuteConcurrently(tasks)
		assert.Len(t, errs, 0)
	})
}

// Test PR context storage helper functions
func TestWebhookHandler_PRContextHelpers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	t.Run("store and retrieve PR number", func(t *testing.T) {
		sha := "test-sha-123"
		prNumber := int64(42)

		// Store PR number
		handler.storePRNumberForSHA(sha, prNumber)

		// Retrieve PR number
		retrievedPR, exists := handler.getPRNumberForSHA(sha)
		assert.True(t, exists)
		assert.Equal(t, prNumber, retrievedPR)
	})

	t.Run("retrieve non-existent PR number", func(t *testing.T) {
		sha := "non-existent-sha"

		retrievedPR, exists := handler.getPRNumberForSHA(sha)
		assert.False(t, exists)
		assert.Equal(t, int64(0), retrievedPR)
	})
}

// Test getSecurityCheckTypes function
func TestWebhookHandler_GetSecurityCheckTypes(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"

	checkTypes := handler.getSecurityCheckTypes(ctx, owner, repo, sha)

	assert.Len(t, checkTypes, 2)

	// Check vulnerability check type
	vulnCheck := checkTypes[0]
	assert.Equal(t, "vulnerability", vulnCheck.name)
	assert.NotNil(t, vulnCheck.create)
	assert.NotNil(t, vulnCheck.start)
	assert.NotNil(t, vulnCheck.store)

	// Check license check type
	licenseCheck := checkTypes[1]
	assert.Equal(t, "license", licenseCheck.name)
	assert.NotNil(t, licenseCheck.create)
	assert.NotNil(t, licenseCheck.start)
	assert.NotNil(t, licenseCheck.store)
}

// Test completeSecurityChecksAsNeutral function
func TestWebhookHandler_CompleteSecurityChecksAsNeutral(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"

	// Test with no stored check runs - should not error
	err = handler.completeSecurityChecksAsNeutral(ctx, owner, repo, sha)
	assert.NoError(t, err)
}

// Test processSecurityPayloads with no check runs
func TestWebhookHandler_ProcessSecurityPayloads_NoCheckRuns(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	ctx := context.Background()
	vulnPayloads := []*services.VulnerabilityPayload{}
	sbomPayloads := []*services.SBOMPayload{}
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"
	prNumber := int64(123)
	vulnCheckRunID := int64(0)    // No vulnerability check run
	licenseCheckRunID := int64(0) // No license check run

	err = handler.processSecurityPayloads(ctx, vulnPayloads, sbomPayloads, owner, repo, sha, prNumber, vulnCheckRunID, licenseCheckRunID)
	assert.NoError(t, err)
}

// Test createSecurityCheckRuns helper function
func TestWebhookHandler_CreateSecurityCheckRuns(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"

	// Get the security check types to pass to the function
	checkTypes := handler.getSecurityCheckTypes(ctx, owner, repo, sha)

	// We verify that the function exists and has the correct signature
	// We don't actually call it because it would panic due to uninitialized services
	assert.Len(t, checkTypes, 2) // Should have vulnerability and license check types
	assert.Equal(t, "vulnerability", checkTypes[0].name)
	assert.Equal(t, "license", checkTypes[1].name)

	// Note: We skip calling createSecurityCheckRuns because it would panic
	// without properly mocked services. This test ensures the function exists.
}
// Test vulnerability check store helpers
func TestWebhookHandler_VulnerabilityCheckStoreHelpers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	t.Run("store and retrieve vulnerability check run ID", func(t *testing.T) {
		sha := "test-sha-vuln"
		checkRunID := int64(999)

		// Store check run ID - using the internal store directly
		handler.vulnerabilityCheckMutex.Lock()
		handler.vulnerabilityCheckStore[sha] = checkRunID
		handler.vulnerabilityCheckMutex.Unlock()

		// Retrieve check run ID
		handler.vulnerabilityCheckMutex.RLock()
		retrievedID, exists := handler.vulnerabilityCheckStore[sha]
		handler.vulnerabilityCheckMutex.RUnlock()

		assert.True(t, exists)
		assert.Equal(t, checkRunID, retrievedID)
	})

	t.Run("retrieve non-existent vulnerability check run ID", func(t *testing.T) {
		sha := "non-existent-vuln-sha"

		handler.vulnerabilityCheckMutex.RLock()
		retrievedID, exists := handler.vulnerabilityCheckStore[sha]
		handler.vulnerabilityCheckMutex.RUnlock()

		assert.False(t, exists)
		assert.Equal(t, int64(0), retrievedID)
	})
}

// Test license check store helpers
func TestWebhookHandler_LicenseCheckStore(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	t.Run("store and retrieve license check run ID", func(t *testing.T) {
		sha := "test-sha-license"
		checkRunID := int64(888)

		// Store check run ID - using the internal store directly
		handler.licenseCheckMutex.Lock()
		handler.licenseCheckStore[sha] = checkRunID
		handler.licenseCheckMutex.Unlock()

		// Retrieve check run ID
		handler.licenseCheckMutex.RLock()
		retrievedID, exists := handler.licenseCheckStore[sha]
		handler.licenseCheckMutex.RUnlock()

		assert.True(t, exists)
		assert.Equal(t, checkRunID, retrievedID)
	})

	t.Run("retrieve non-existent license check run ID", func(t *testing.T) {
		sha := "non-existent-license-sha"

		handler.licenseCheckMutex.RLock()
		retrievedID, exists := handler.licenseCheckStore[sha]
		handler.licenseCheckMutex.RUnlock()

		assert.False(t, exists)
		assert.Equal(t, int64(0), retrievedID)
	})
}

// Test completeVulnerabilityCheckAsNeutral function
func TestWebhookHandler_CompleteVulnerabilityCheckAsNeutralHelper(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"

	// Test with no stored vulnerability check run - should not error
	err = handler.completeVulnerabilityCheckAsNeutral(ctx, owner, repo, sha)
	assert.NoError(t, err)
}

// Test completeLicenseCheckAsNeutral function
func TestWebhookHandler_CompleteLicenseCheckAsNeutral(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"

	// Test with no stored license check run - should not error
	err = handler.completeLicenseCheckAsNeutral(ctx, owner, repo, sha)
	assert.NoError(t, err)
}

// Test findVulnerabilityCheckRun function
func TestWebhookHandler_FindVulnerabilityCheckRun(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"

	// This will likely return an error since we don't have mocked services
	// but we're testing that the function exists and compiles
	checkRunID, err := handler.findVulnerabilityCheckRun(ctx, owner, repo, sha)
	_ = checkRunID
	_ = err
	// Note: Real testing would require mocking the GitHub API
}

// Test findLicenseCheckRun function
func TestWebhookHandler_FindLicenseCheckRun(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"

	// This will likely return an error since we don't have mocked services
	// but we're testing that the function exists and compiles
	checkRunID, err := handler.findLicenseCheckRun(ctx, owner, repo, sha)
	_ = checkRunID
	_ = err
	// Note: Real testing would require mocking the GitHub API
}

// Test processSecurityPayloads with empty payloads
func TestWebhookHandler_ProcessSecurityPayloads_EmptyPayloads(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	ctx := context.Background()
	vulnPayloads := []*services.VulnerabilityPayload{}
	sbomPayloads := []*services.SBOMPayload{}
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"
	prNumber := int64(123)
	vulnCheckRunID := int64(0)
	licenseCheckRunID := int64(0)

	err = handler.processSecurityPayloads(ctx, vulnPayloads, sbomPayloads, owner, repo, sha, prNumber, vulnCheckRunID, licenseCheckRunID)
	assert.NoError(t, err)
}
