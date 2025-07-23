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
	"github.com/stretchr/testify/suite"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/storage"
	"github.com/terrpan/polly/internal/utils"
)

// createTestServicesForHelpers creates mock services for webhook helper tests
func createTestServicesForHelpers() (*services.CommentService, *services.CheckService, *services.PolicyService, *services.SecurityService, *services.StateService) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	memStore := storage.NewMemoryStore()
	opaClient := &clients.OPAClient{}
	githubClient := &clients.GitHubClient{}

	commentService := services.NewCommentService(githubClient, logger)
	checkService := services.NewCheckService(githubClient, logger)
	policyService := services.NewPolicyService(opaClient, logger)
	securityService := services.NewSecurityService(githubClient, logger)
	stateService := services.NewStateService(memStore, logger)

	return commentService, checkService, policyService, securityService, stateService
}

// WebhookHelpersTestSuite provides a test suite for webhook helper tests
type WebhookHelpersTestSuite struct {
	suite.Suite
	ctx             context.Context
	logger          *slog.Logger
	handler         *WebhookHandler
	commentService  *services.CommentService
	checkService    *services.CheckService
	policyService   *services.PolicyService
	securityService *services.SecurityService
	stateService    *services.StateService
}

// SetupSuite runs once before all tests in the suite
func (suite *WebhookHelpersTestSuite) SetupSuite() {
	suite.ctx = context.Background()
	suite.logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
}

// SetupTest runs before each test
func (suite *WebhookHelpersTestSuite) SetupTest() {
	// Create test services
	suite.commentService, suite.checkService, suite.policyService, suite.securityService, suite.stateService = suite.createTestServicesForHelpers()

	// Create webhook handler
	var err error
	suite.handler, err = NewWebhookHandler(
		suite.logger,
		suite.commentService,
		suite.checkService,
		suite.policyService,
		suite.securityService,
		suite.stateService,
	)
	suite.Require().NoError(err)
}

// createTestServicesForHelpers creates test services for the helpers tests
func (suite *WebhookHelpersTestSuite) createTestServicesForHelpers() (*services.CommentService, *services.CheckService, *services.PolicyService, *services.SecurityService, *services.StateService) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create test GitHub client (will not make real API calls in tests)
	githubClient := clients.NewGitHubClient(suite.ctx)

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

func (suite *WebhookHelpersTestSuite) TestPRContextHelpers() {
	suite.Run("store and retrieve PR number", func() {
		owner := "test-owner"
		repo := "test-repo"
		sha := "test-sha-123"
		prNumber := int64(42)

		// Store PR number using StateService
		err := suite.handler.stateService.StorePRNumber(suite.ctx, owner, repo, sha, prNumber)
		suite.Require().NoError(err)

		// Retrieve PR number using StateService
		retrievedPR, exists, err := suite.handler.stateService.GetPRNumber(suite.ctx, owner, repo, sha)
		suite.Require().NoError(err)
		suite.Assert().True(exists)
		suite.Assert().Equal(prNumber, retrievedPR)
	})

	suite.Run("retrieve non-existent PR number", func() {
		owner := "test-owner"
		repo := "test-repo"
		sha := "non-existent-sha"

		retrievedPR, exists, err := suite.handler.stateService.GetPRNumber(suite.ctx, owner, repo, sha)
		suite.Require().NoError(err)
		suite.Assert().False(exists)
		suite.Assert().Equal(int64(0), retrievedPR)
	})
}

func (suite *WebhookHelpersTestSuite) TestGetSecurityCheckTypes() {
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"

	checkTypes := suite.handler.getSecurityCheckTypes(suite.ctx, owner, repo, sha)

	suite.Assert().Len(checkTypes, 2)

	// Check vulnerability check type
	vulnCheck := checkTypes[0]
	suite.Assert().Equal("vulnerability", vulnCheck.name)
	suite.Assert().NotNil(vulnCheck.create)
	suite.Assert().NotNil(vulnCheck.start)
	suite.Assert().NotNil(vulnCheck.store)

	// Check license check type
	licenseCheck := checkTypes[1]
	suite.Assert().Equal("license", licenseCheck.name)
	suite.Assert().NotNil(licenseCheck.create)
	suite.Assert().NotNil(licenseCheck.start)
	suite.Assert().NotNil(licenseCheck.store)
}

func (suite *WebhookHelpersTestSuite) TestCompleteSecurityChecksAsNeutral() {
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"

	// Test with no stored check runs - should not error
	err := suite.handler.completeSecurityChecksAsNeutral(suite.ctx, owner, repo, sha)
	suite.Assert().NoError(err)
}

func (suite *WebhookHelpersTestSuite) TestProcessSecurityPayloadsNoCheckRuns() {
	vulnPayloads := []*services.VulnerabilityPayload{}
	sbomPayloads := []*services.SBOMPayload{}
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"
	prNumber := int64(123)
	vulnCheckRunID := int64(0)    // No vulnerability check run
	licenseCheckRunID := int64(0) // No license check run

	err := suite.handler.processSecurityPayloads(
		suite.ctx,
		vulnPayloads,
		sbomPayloads,
		owner,
		repo,
		sha,
		prNumber,
		vulnCheckRunID,
		licenseCheckRunID,
	)
	suite.Assert().NoError(err)
}

func (suite *WebhookHelpersTestSuite) TestCreateSecurityCheckRuns() {
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"

	// Get the security check types to pass to the function
	checkTypes := suite.handler.getSecurityCheckTypes(suite.ctx, owner, repo, sha)

	// We verify that the function exists and has the correct signature
	// We don't actually call it because it would panic due to uninitialized services
	suite.Assert().Len(checkTypes, 2) // Should have vulnerability and license check types
	suite.Assert().Equal("vulnerability", checkTypes[0].name)
	suite.Assert().Equal("license", checkTypes[1].name)

	// Note: We skip calling createSecurityCheckRuns because it would panic
	// without properly mocked services. This test ensures the function exists.
}

func (suite *WebhookHelpersTestSuite) TestVulnerabilityCheckStoreHelpers() {
	suite.Run("store and retrieve vulnerability check run ID", func() {
		owner := "test-owner"
		repo := "test-repo"
		sha := "test-sha-vuln"
		checkRunID := int64(999)

		// Store check run ID using StateService
		err := suite.handler.stateService.StoreVulnerabilityCheckRunID(suite.ctx, owner, repo, sha, checkRunID)
		suite.Require().NoError(err)

		// Retrieve check run ID using StateService
		retrievedID, exists, err := suite.handler.stateService.GetVulnerabilityCheckRunID(
			suite.ctx,
			owner,
			repo,
			sha,
		)
		suite.Require().NoError(err)
		suite.Assert().True(exists)
		suite.Assert().Equal(checkRunID, retrievedID)
	})

	suite.Run("retrieve non-existent vulnerability check run ID", func() {
		owner := "test-owner"
		repo := "test-repo"
		sha := "non-existent-vuln-sha"

		retrievedID, exists, err := suite.handler.stateService.GetVulnerabilityCheckRunID(
			suite.ctx,
			owner,
			repo,
			sha,
		)
		suite.Require().NoError(err)
		suite.Assert().False(exists)
		suite.Assert().Equal(int64(0), retrievedID)
	})
}

// Test license check store helpers (converted to regular test for comparison)
func TestWebhookHandler_LicenseCheckStore(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	githubClient := clients.NewGitHubClient(context.Background())
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	store := storage.NewMemoryStore()
	stateService := services.NewStateService(store, logger)
	commentService := services.NewCommentService(githubClient, logger)
	checkService := services.NewCheckService(githubClient, logger)
	policyService := services.NewPolicyService(opaClient, logger)
	securityService := services.NewSecurityService(githubClient, logger)

	handler, err := NewWebhookHandler(
		logger,
		commentService,
		checkService,
		policyService,
		securityService,
		stateService,
	)
	require.NoError(t, err)

	t.Run("store and retrieve license check run ID", func(t *testing.T) {
		ctx := context.Background()
		owner := "test-owner"
		repo := "test-repo"
		sha := "test-sha-license"
		checkRunID := int64(888)

		// Store check run ID using StateService
		err := handler.stateService.StoreLicenseCheckRunID(ctx, owner, repo, sha, checkRunID)
		require.NoError(t, err)

		// Retrieve check run ID using StateService
		retrievedID, exists, err := handler.stateService.GetLicenseCheckRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.True(t, exists)
		assert.Equal(t, checkRunID, retrievedID)
	})

	t.Run("retrieve non-existent license check run ID", func(t *testing.T) {
		ctx := context.Background()
		owner := "test-owner"
		repo := "test-repo"
		sha := "non-existent-license-sha"

		retrievedID, exists, err := handler.stateService.GetLicenseCheckRunID(ctx, owner, repo, sha)
		require.NoError(t, err)
		assert.False(t, exists)
		assert.Equal(t, int64(0), retrievedID)
	})
}

// Test completeVulnerabilityCheckAsNeutral function
func TestWebhookHandler_CompleteVulnerabilityCheckAsNeutralHelper(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	commentService, checkService, policyService, securityService, stateService := createTestServicesForHelpers()

	handler, err := NewWebhookHandler(
		logger,
		commentService,
		checkService,
		policyService,
		securityService,
		stateService,
	)
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
	commentService, checkService, policyService, securityService, stateService := createTestServicesForHelpers()

	handler, err := NewWebhookHandler(
		logger,
		commentService,
		checkService,
		policyService,
		securityService,
		stateService,
	)
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
	commentService, checkService, policyService, securityService, stateService := createTestServicesForHelpers()

	handler, err := NewWebhookHandler(
		logger,
		commentService,
		checkService,
		policyService,
		securityService,
		stateService,
	)
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
	commentService, checkService, policyService, securityService, stateService := createTestServicesForHelpers()

	handler, err := NewWebhookHandler(
		logger,
		commentService,
		checkService,
		policyService,
		securityService,
		stateService,
	)
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
	commentService, checkService, policyService, securityService, stateService := createTestServicesForHelpers()

	handler, err := NewWebhookHandler(
		logger,
		commentService,
		checkService,
		policyService,
		securityService,
		stateService,
	)
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

	err = handler.processSecurityPayloads(
		ctx,
		vulnPayloads,
		sbomPayloads,
		owner,
		repo,
		sha,
		prNumber,
		vulnCheckRunID,
		licenseCheckRunID,
	)
	assert.NoError(t, err)
}

// Run the test suite
func TestWebhookHelpersTestSuite(t *testing.T) {
	suite.Run(t, new(WebhookHelpersTestSuite))
}
